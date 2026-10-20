"""Turn an encrypted backup into a database you can actually query.

Every read-only command needs a plain SQLite file, and producing one costs a
100 MB GCM decrypt plus a 2.4x inflate.  Doing that per command is what made
the first version feel slow, so this module owns the caching policy:

* a fresh cache hit returns immediately and **needs no key at all**;
* a miss decrypts once, encrypts the result into the cache, and hands back a
  plaintext copy that lives only as long as the call;
* nothing on disk is ever left in plaintext outside :func:`open_backup`.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Iterator, Optional

from .crypto import derive_backup_key, unpack_to_file
from .header import BackupHeader, read_header
from .keys import resolve_key
from . import vault

__all__ = ["open_backup", "decrypt_permanently", "CachedState"]


class CachedState:
    """What happened while locating a database, for reporting to the user."""

    __slots__ = ("cache_hit", "decrypted", "db_size")

    def __init__(self) -> None:
        self.cache_hit = False
        self.decrypted = False
        self.db_size = 0


@contextlib.contextmanager
def open_backup(
    path,
    key: Optional[bytes] = None,
    *,
    use_cache: bool = True,
    ttl: int = vault.DEFAULT_TTL,
    progress=None,
) -> Iterator:
    """Yield ``(header, sqlite_path, state)`` for an encrypted backup.

    The database path is valid for the duration of the ``with`` block only.
    """
    source = Path(path)
    header = read_header(source)
    state = CachedState()

    fp = vault.fingerprint(source) if use_cache else None
    if fp and not vault.stale(fp, ttl):
        # Materialise into a temporary directory, not into a shared session
        # file.  The old behaviour kept the decrypted database in the session
        # directory as a "fast path", which quietly left hundreds of megabytes
        # of chat history on disk in the clear — the exact thing the encrypted
        # cache exists to prevent.  Decrypting the cache costs ~0.17 s, so
        # there is nothing to buy back by doing that.
        temporary = Path(tempfile.mkdtemp(prefix="wacrypt-"))
        try:
            cached = vault.materialize(fp, temporary)
            if cached is not None:
                state.cache_hit = True
                state.db_size = cached.stat().st_size
                yield header, cached, state
                return
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    resolved = key or resolve_key()
    aes_key = derive_backup_key(resolved)
    temporary = Path(tempfile.mkdtemp(prefix="wacrypt-"))
    db = temporary / "msgstore.db"
    try:
        unpack_to_file(source, aes_key, db, header, progress=progress)
        state.decrypted = True
        state.db_size = db.stat().st_size
        if fp:
            with contextlib.suppress(Exception):
                vault.store_cache(fp, db, source)
        yield header, db, state
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def decrypt_permanently(
    path,
    out_path,
    key: Optional[bytes] = None,
    *,
    use_cache: bool = True,
    progress=None,
) -> BackupHeader:
    """Write a plain SQLite database the user keeps.

    Uses the cache when it can, so ``wacrypt decrypt`` right after
    ``wacrypt inspect`` does not decrypt the file a second time.
    """
    target = Path(out_path)
    with open_backup(path, key, use_cache=use_cache, progress=progress) as (
        header,
        db,
        _state,
    ):
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".partial")
        try:
            shutil.copyfile(db, temporary)
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                temporary.unlink()
        os.chmod(target, 0o600)
    return header
