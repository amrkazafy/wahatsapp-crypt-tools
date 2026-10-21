"""The key schedule, the ciphers, and the distinction between a wrong key and
a corrupt file — the two failures that v1 reported identically."""

from __future__ import annotations

import hashlib
import hmac
import os
import stat

import pytest

from wacrypt import (
    BackupHeader,
    CorruptedBackup,
    WrongKey,
    build_prefix,
    derive_backup_key,
    encryption_loop,
    iter_decrypted,
    iter_plaintext,
    pack_from_file,
    read_header,
    sniff_payload,
    unpack_to_file,
)


class TestKeySchedule:
    def test_matches_the_documented_algorithm(self, root_key):
        """Spelled out independently so the test pins the exact construction."""
        private = hmac.new(b"\x00" * 32, root_key, hashlib.sha256).digest()
        expected = hmac.new(
            private, b"backup encryption" + b"\x01", hashlib.sha256
        ).digest()
        assert derive_backup_key(root_key) == expected

    def test_output_is_32_bytes(self, root_key):
        assert len(derive_backup_key(root_key)) == 32

    def test_root_key_length_is_enforced(self):
        with pytest.raises(WrongKey):
            derive_backup_key(b"too short")

    def test_the_label_is_not_optional(self, root_key):
        assert derive_backup_key(root_key) != encryption_loop(root_key, b"", 32)

    def test_loop_stacks_iterations(self, root_key):
        once = encryption_loop(root_key, b"msg", 32)
        twice = encryption_loop(root_key, b"msg", 64)
        assert twice[:32] == once
        assert len(twice) == 64


class TestRoundTrip:
    def test_decrypted_payload_is_the_original_database(self, backup, aes_key, plain_db):
        header = read_header(backup)
        chunks = b"".join(iter_plaintext(backup, aes_key, header))
        assert chunks == plain_db.read_bytes()

    def test_unpack_writes_a_readable_database(self, backup, aes_key, tmp_path):
        out = tmp_path / "msgstore.db"
        header = unpack_to_file(backup, aes_key, out)
        assert out.read_bytes()[:16] == b"SQLite format 3\x00"
        assert header.jid_suffix
        assert stat.S_IMODE(out.stat().st_mode) == 0o600

    def test_streaming_matches_a_single_pass(self, backup, aes_key):
        header = read_header(backup)
        whole = b"".join(iter_decrypted(backup, aes_key, header, chunk=1 << 22))
        piecewise = b"".join(iter_decrypted(backup, aes_key, header, chunk=977))
        assert whole == piecewise

    def test_zlib_is_what_is_inside(self, backup, aes_key):
        header = read_header(backup)
        first = next(iter_decrypted(backup, aes_key, header))
        assert sniff_payload(first) == "zlib"

    def test_nothing_is_left_behind(self, backup, aes_key, tmp_path):
        out = tmp_path / "msgstore.db"
        unpack_to_file(backup, aes_key, out)
        assert list(tmp_path.iterdir()) == [out]


class TestFailureModes:
    """A wrong key and a corrupted file must fail differently."""

    def test_wrong_key_is_reported_as_a_key_problem(self, backup, root_key, tmp_path):
        wrong = derive_backup_key(b"\xff" * 32)
        assert wrong != derive_backup_key(root_key)
        # Not "incorrect header check": the checksum passes (the file is
        # fine), so the message must say the key is what is wrong.
        with pytest.raises(WrongKey, match="wrong key"):
            unpack_to_file(backup, wrong, tmp_path / "x.db")

    def test_a_bit_flip_in_the_ciphertext_is_a_corruption(self, backup, aes_key, tmp_path):
        broken = tmp_path / "broken.crypt15"
        payload = bytearray(backup.read_bytes())
        payload[read_header(backup).cipher_offset + 50] ^= 0x01
        broken.write_bytes(bytes(payload))

        with pytest.raises(CorruptedBackup, match="MD5"):
            unpack_to_file(broken, aes_key, tmp_path / "x.db")

    def test_a_truncated_file_is_named_as_such(self, backup, aes_key, tmp_path):
        broken = tmp_path / "short.crypt15"
        broken.write_bytes(backup.read_bytes()[: len(backup.read_bytes()) // 2])
        with pytest.raises(CorruptedBackup, match="MD5|truncated"):
            unpack_to_file(broken, aes_key, tmp_path / "x.db")

    def test_a_tampered_iv_is_caught_by_the_checksum(self, backup, aes_key, tmp_path):
        """The IV lives inside the prefix, which the MD5 covers.  So tampering
        with it is corruption, not a key problem — and must be reported as
        one rather than as a zlib failure."""
        payload = bytearray(backup.read_bytes())
        header = read_header(backup)
        start = bytes(payload).find(header.iv)
        assert start > 0, "the IV should appear inside the prefix"
        payload[start + 3] ^= 0x01  # a byte in the middle of the IV
        broken = tmp_path / "tampered-iv.crypt15"
        broken.write_bytes(bytes(payload))

        with pytest.raises(CorruptedBackup, match="MD5"):
            unpack_to_file(broken, aes_key, tmp_path / "x.db")

    def test_a_bare_root_key_never_opens_it(self, backup, root_key, tmp_path):
        with pytest.raises(WrongKey):
            unpack_to_file(backup, root_key, tmp_path / "x.db")


class TestReEncryption:
    def test_a_repacked_backup_opens_again(self, plain_db, aes_key, tmp_path, backup):
        header = BackupHeader(
            path=plain_db,
            file_size=0,
            crypt_type=15,
            header_len=0,
            cipher_offset=0,
            prefix=build_prefix(iv=bytes(range(16, 32)), jid_suffix="99"),
            iv=bytes(range(16, 32)),
            jid_suffix="99",
        )
        repacked = tmp_path / "repacked.crypt15"
        pack_from_file(plain_db, aes_key, repacked, header)

        again = tmp_path / "again.db"
        unpack_to_file(repacked, aes_key, again)
        assert again.read_bytes() == plain_db.read_bytes()

        # The trailer is md5(varint + prefix + ciphertext + tag), so the
        # repacked file must be self-consistent too.
        data = repacked.read_bytes()
        assert hashlib.md5(data[:-16]).digest() == data[-16:]

    def test_a_fresh_nonce_is_used_every_time(self, plain_db, aes_key, tmp_path, backup):
        """Re-encrypting a *different* database under the same key and nonce
        is the classic GCM failure: XORing the two ciphertexts together is
        enough to start recovering the GHASH key.  So every packing takes a
        new one, even when it is handed the very same header."""
        header = read_header(backup)
        first, second = tmp_path / "a.crypt15", tmp_path / "b.crypt15"

        pack_from_file(plain_db, aes_key, first, header)
        pack_from_file(plain_db, aes_key, second, header)

        assert read_header(first).iv != read_header(second).iv

    def test_the_header_advertises_the_nonce_that_was_used(
        self, plain_db, aes_key, tmp_path, backup
    ):
        """The reader takes the IV from the prefix, so the two can never
        disagree — and the written one must be the new nonce, not the one the
        caller's header happened to carry."""
        header = read_header(backup)
        repacked = tmp_path / "repacked.crypt15"
        pack_from_file(plain_db, aes_key, repacked, header)

        written = read_header(repacked)
        assert written.iv != header.iv
        assert written.iv in written.prefix

    def test_an_explicit_iv_is_honoured(self, plain_db, aes_key, tmp_path, backup):
        """`--reuse-iv` still has to work: naming a nonce pins it, and the
        prefix is rewritten to match so the file stays decryptable."""
        header = read_header(backup)
        nonce = bytes(range(32, 48))
        pinned = tmp_path / "pinned.crypt15"

        pack_from_file(plain_db, aes_key, pinned, header, iv=nonce)

        written = read_header(pinned)
        assert written.iv == nonce
        assert written.iv in written.prefix

        again = tmp_path / "pinned.db"
        unpack_to_file(pinned, aes_key, again)
        assert again.read_bytes() == plain_db.read_bytes()

    def test_the_payload_is_actually_compressed(self, plain_db, aes_key, tmp_path, backup):
        """WhatsApp zips before encrypting.  A ciphertext larger than the
        database itself would mean we quietly stopped doing that."""
        header = read_header(backup)
        assert header.cipher_size < plain_db.stat().st_size

    def test_refuses_a_bad_key_length(self, plain_db, tmp_path, backup):
        with pytest.raises(WrongKey):
            pack_from_file(plain_db, b"short", tmp_path / "x.crypt15", read_header(backup))


def test_modes_are_not_interchangeable(tmp_path):
    assert sniff_payload(b"SQLite format 3\x00") == "sqlite"
    assert sniff_payload(b"PK\x03\x04rest") == "zip"
    assert sniff_payload(b"\x78\xda\x9c") == "zlib"
    assert sniff_payload(b"\x00\x01\x02") == "unknown"
    assert os.geteuid() >= 0
