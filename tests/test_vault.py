"""The decrypted-database cache.

200 MB of someone's entire chat history should not be sitting in a temp
folder in the clear, so the cache is encrypted with a key that only the
keychain holds.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wacrypt.core import vault
from wacrypt.core.crypto import unpack_to_file


@pytest.fixture()
def stored(backup, plain_db, tmp_path):
    fp = vault.fingerprint(backup)
    vault.store_cache(fp, plain_db, backup)
    return fp, plain_db


class TestFingerprint:
    def test_is_stable_for_the_same_file(self, backup):
        assert vault.fingerprint(backup) == vault.fingerprint(backup)

    def test_changes_when_the_file_is_replaced(self, backup, tmp_path):
        import shutil

        copy = tmp_path / "copy.crypt15"
        shutil.copyfile(backup, copy)
        before = vault.fingerprint(copy)

        copy.write_bytes(backup.read_bytes() + b"\x00")
        after = vault.fingerprint(copy)

        assert after != before
        assert vault.fingerprint(backup) != after

    def test_changes_when_the_file_is_touched(self, backup, tmp_path):
        import os
        import shutil
        import time

        copy = tmp_path / "copy.crypt15"
        shutil.copyfile(backup, copy)
        before = vault.fingerprint(copy)
        os.utime(copy, (time.time() + 100, time.time() + 100))
        assert vault.fingerprint(copy) != before


class TestCache:
    def test_round_trip(self, stored, tmp_path):
        fp, plain_db = stored
        assert vault.has_cache(fp)

        materialised = vault.materialize(fp, tmp_path / "out")
        assert materialised is not None
        assert materialised.read_bytes() == plain_db.read_bytes()
        # The caller owns the directory, and that ownership is what guarantees
        # the copy does not outlive the command.
        assert materialised.parent == tmp_path / "out"

    def test_the_cache_entry_is_not_plaintext(self, stored):
        fp, _ = stored
        enc, _meta = vault._paths(fp)
        raw = enc.read_bytes()
        assert b"SQLite format 3" not in raw
        assert b"note to self" not in raw

    def test_the_plaintext_copy_is_private(self, stored, tmp_path):
        import stat

        fp, _ = stored
        materialised = vault.materialize(fp, tmp_path / "out")
        assert stat.S_IMODE(materialised.stat().st_mode) == 0o600
        assert stat.S_IMODE(materialised.parent.stat().st_mode) == 0o700

    def test_a_tampered_entry_is_rejected(self, stored, tmp_path):
        fp, _ = stored
        enc, _meta = vault._paths(fp)
        payload = bytearray(enc.read_bytes())
        payload[20] ^= 0xFF
        enc.write_bytes(bytes(payload))

        with pytest.raises(vault.VaultError, match="authentication"):
            vault.materialize(fp, tmp_path / "out")

    def test_an_absent_entry_returns_none(self, tmp_path):
        assert vault.materialize("does-not-exist", tmp_path / "out") is None

    def test_nothing_is_cached_in_the_session_directory(self, stored, tmp_path):
        """The regression: a decrypted database must never be parked there."""
        fp, _ = stored
        vault.materialize(fp, tmp_path / "out")
        assert not vault._session_path(fp).exists()

    def test_status_reports_no_plaintext_on_disk(self, stored):
        assert vault.status()["entries"][0]["plaintext_on_disk"] is False

    def test_purge_removes_everything(self, stored, tmp_path):
        fp, _ = stored
        vault.materialize(fp, tmp_path / "out")
        assert vault.purge(fp) >= 1
        assert not vault.has_cache(fp)

    def test_purge_can_clear_all(self, stored):
        vault.purge()
        assert vault.status()["entries"] == []

    def test_status_describes_what_is_there(self, stored):
        fp, _ = stored
        status = vault.status()
        (entry,) = status["entries"]
        assert entry["fingerprint"] == fp
        assert entry["cache_bytes"] > 0
        assert entry["source"].endswith(".crypt15")
        assert status["key_in_keychain"] is True

    def test_staleness_is_a_ttl_not_a_maybe(self, stored):
        fp, _ = stored
        assert not vault.stale(fp, ttl=3600)
        assert vault.stale(fp, ttl=0)

    def test_a_corrupt_meta_file_counts_as_stale(self, stored):
        fp, _ = stored
        _enc, meta = vault._paths(fp)
        meta.write_text("{ not json")
        assert vault.stale(fp) is True
        assert vault.has_cache(fp) is False


def test_the_cache_short_circuits_a_second_decrypt(backup, plain_db, monkeypatch):
    """A cache hit must not touch the backup's ciphertext at all."""
    fp = vault.fingerprint(backup)
    vault.store_cache(fp, plain_db, backup)

    calls = []
    original = unpack_to_file

    def counting(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)

    from wacrypt.core import session

    monkeypatch.setattr(session, "unpack_to_file", counting)
    monkeypatch.setattr(session.vault, "DEFAULT_TTL", 3600)

    with session.open_backup(backup, b"\x00" * 32, use_cache=True) as (header, db, state):
        assert state.cache_hit is True
        assert state.decrypted is False
        assert header.jid_suffix
        assert Path(db).is_file()

    assert calls == [], "a fresh cache hit must not decrypt the backup"


def test_no_decrypted_database_outlives_the_command(backup, plain_db, monkeypatch):
    """The promise: the encrypted cache is the only thing at rest.

    Materialising into a shared session directory is what left 700 MB of
    plaintext chat history on disk in earlier builds, so this asserts the
    opposite directly — inside the block the file exists and is queryable,
    and once the block closes there is nothing to find.
    """
    from wacrypt.core import session

    monkeypatch.setattr(session.vault, "DEFAULT_TTL", 3600)
    fp = vault.fingerprint(backup)
    vault.store_cache(fp, plain_db, backup)

    with session.open_backup(backup, b"\x00" * 32, use_cache=True) as (_h, db, state):
        assert state.cache_hit is True
        held = Path(db)
        assert held.is_file()
        assert held.read_bytes()[:16] == b"SQLite format 3\x00"
        workdir = held.parent

    assert not held.exists(), "the plaintext database survived the command"
    assert not workdir.exists(), "its directory survived too"
    assert not vault._session_path(fp).exists()
    # The cache itself is still there, and still encrypted.
    assert vault.has_cache(fp)
    assert b"SQLite format 3" not in (vault._paths(fp)[0]).read_bytes()


def test_the_cache_entry_still_exists_after_the_command(backup, plain_db, monkeypatch):
    """Cleaning up must not cost the cache — that would defeat the point."""
    from wacrypt.core import session

    monkeypatch.setattr(session.vault, "DEFAULT_TTL", 3600)
    fp = vault.fingerprint(backup)
    vault.store_cache(fp, plain_db, backup)

    for _ in range(2):
        with session.open_backup(backup, b"\x00" * 32, use_cache=True) as (_h, db, state):
            assert state.cache_hit is True
            assert Path(db).read_bytes() == plain_db.read_bytes()

    assert vault.status()["entries"][0]["plaintext_on_disk"] is False
