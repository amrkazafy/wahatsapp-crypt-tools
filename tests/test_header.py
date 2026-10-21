"""Header parsing: varints, the protobuf prefix, and safe re-writing."""

from __future__ import annotations

import pytest

from wacrypt import (
    CipherField,
    HeaderError,
    MetaField,
    PrefixField,
    build_prefix,
    decode_message,
    encode_varint,
    patch_iv,
    patch_jid_suffix,
    parse_prefix,
    read_header,
    read_varint,
)

OWNER = "99900011122"
SUFFIX = OWNER[-2:]


class TestVarint:
    @pytest.mark.parametrize("value", [0, 1, 127, 128, 300, 2**14 - 1, 2**21, 2**35])
    def test_round_trip(self, value):
        encoded = encode_varint(value)
        decoded, position = read_varint(encoded, 0)
        assert decoded == value
        assert position == len(encoded)

    def test_encoding_is_canonical(self):
        assert encode_varint(300) == b"\xac\x02"

    def test_negative_is_refused(self):
        with pytest.raises(ValueError):
            encode_varint(-1)

    def test_truncated_is_reported(self):
        with pytest.raises(HeaderError):
            read_varint(b"\x80", 0)

    def test_endless_varint_is_reported(self):
        with pytest.raises(HeaderError):
            read_varint(b"\x80" * 40, 0)


class TestProtobuf:
    def test_round_trip(self):
        raw = build_prefix(iv=bytes(16), app_version="1.0", jid_suffix="42", backup_version=1)
        message = decode_message(raw)
        assert PrefixField.E2EE_KEY_DATA in message
        assert PrefixField.BACKUP_METADATA in message
        assert PrefixField.KEY_TYPE_NEW in message

    def test_prefix_is_reusable_bytewise(self):
        raw = build_prefix(iv=bytes(16), app_version="1.0", jid_suffix="42")
        parsed = parse_prefix(raw, path="x", file_size=0, header_len=len(raw), cipher_offset=0)
        assert parsed.prefix == raw
        assert parsed.app_version == "1.0"
        assert parsed.jid_suffix == "42"

    def test_iv_is_enforced(self):
        with pytest.raises(HeaderError):
            build_prefix(iv=b"short")

    def test_unknown_fields_are_reported(self):
        raw = build_prefix(iv=bytes(16), jid_suffix="42")
        raw += bytes([(12 << 3) | 2, 3, 1, 2, 3])  # field 12, length delimited
        parsed = parse_prefix(raw, path="x", file_size=0, header_len=len(raw), cipher_offset=0)
        assert "12" in parsed.unknown_fields


class TestReadHeader:
    def test_reads_the_real_shape(self, backup):
        header = read_header(backup)
        assert header.crypt_type == 15
        assert header.jid_suffix == SUFFIX
        # The fixture packs with a fresh nonce (see test_crypto), so what is
        # pinned here is that the header carries one and that it is the same
        # nonce the prefix advertises — the two disagreeing would make the
        # backup undecryptable.
        assert len(header.iv) == 16
        assert header.iv in header.prefix
        assert header.cipher_offset == len(encode_varint(header.header_len)) + header.header_len
        assert header.cipher_size == header.file_size - header.cipher_offset - 32

    def test_only_reads_the_front(self, backup):
        """A header must be parsable without touching the payload."""
        header = read_header(backup, read_size=256)
        assert header.header_len == len(header.prefix)
        assert header.cipher_offset > header.header_len

    def test_legacy_magic_is_named(self, tmp_path):
        legacy = tmp_path / "old.crypt14"
        legacy.write_bytes(b"WAM" + b"\x00" * 200)
        with pytest.raises(HeaderError, match="legacy"):
            read_header(legacy)

    def test_tiny_file(self, tmp_path):
        tiny = tmp_path / "tiny"
        tiny.write_bytes(b"ab")
        with pytest.raises(HeaderError):
            read_header(tiny)


class TestPatchJidSuffix:
    """The migration rewrites the header; nothing else in it may move."""

    def test_no_op_is_byte_identical(self, backup):
        header = read_header(backup)
        assert patch_jid_suffix(header.prefix, SUFFIX) == header.prefix

    def test_only_the_suffix_changes(self, backup):
        header = read_header(backup)
        patched = patch_jid_suffix(header.prefix, "99")

        before = decode_message(header.prefix)[PrefixField.BACKUP_METADATA][0][1]
        after = decode_message(patched)[PrefixField.BACKUP_METADATA][0][1]
        meta_before, meta_after = decode_message(before), decode_message(after)

        assert set(meta_before) == set(meta_after)
        changed = [n for n in meta_before if meta_before[n] != meta_after[n]]
        assert changed == [MetaField.JID_SUFFIX]

    def test_length_change_recomputes_offsets(self, backup):
        header = read_header(backup)
        patched = patch_jid_suffix(header.prefix, "12345")
        reparsed = parse_prefix(
            patched, path=backup, file_size=0, header_len=len(patched), cipher_offset=0
        )
        assert reparsed.jid_suffix == "12345"
        assert len(patched) == len(header.prefix) + 3

    def test_every_other_field_survives(self, backup):
        header = read_header(backup)
        patched = patch_jid_suffix(header.prefix, "77")
        reparsed = parse_prefix(
            patched, path=backup, file_size=0, header_len=len(patched), cipher_offset=0
        )
        assert reparsed.iv == header.iv
        assert reparsed.app_version == header.app_version
        assert reparsed.features == header.features
        assert reparsed.backup_version == header.backup_version
        assert reparsed.cleaned_db == header.cleaned_db
        assert reparsed.key_type == header.key_type
        assert reparsed.key_type_new == header.key_type_new
        assert reparsed.unknown_fields == header.unknown_fields

    def test_round_trips_both_ways(self, backup):
        header = read_header(backup)
        patched = patch_jid_suffix(header.prefix, "42")
        back = patch_jid_suffix(patched, SUFFIX)
        assert back == header.prefix


class TestPatchIv:
    """Re-encryption takes a new nonce, and the header has to follow it.

    Two backups sealed under the same key with the same nonce but different
    content let anyone holding both XOR the ciphertexts together — the failure
    GCM is famous for.  So the nonce is regenerated per packing and written
    back into the prefix, which is exactly where the reader takes it from.
    """

    def test_only_the_iv_changes(self, backup):
        header = read_header(backup)
        nonce = bytes(range(32, 48))
        patched = patch_iv(header.prefix, nonce)

        cipher = decode_message(patched)[PrefixField.E2EE_KEY_DATA][0][1]
        assert decode_message(cipher)[CipherField.C15_IV][0][1] == nonce

    def test_every_other_field_survives(self, backup):
        header = read_header(backup)
        nonce = bytes(range(32, 48))
        patched = patch_iv(header.prefix, nonce)

        # The nonce is fixed width, so nothing after it may shift.
        assert len(patched) == len(header.prefix)

        reparsed = parse_prefix(
            patched, path=backup, file_size=0, header_len=len(patched), cipher_offset=0
        )
        assert reparsed.iv == nonce
        assert reparsed.jid_suffix == header.jid_suffix
        assert reparsed.app_version == header.app_version
        assert reparsed.features == header.features
        assert reparsed.backup_version == header.backup_version
        assert reparsed.key_type == header.key_type
        assert reparsed.key_type_new == header.key_type_new
        assert reparsed.unknown_fields == header.unknown_fields

    def test_the_same_nonce_twice_round_trips(self, backup):
        header = read_header(backup)
        assert patch_iv(patch_iv(header.prefix, bytes(16)), header.iv) == header.prefix

    def test_a_short_iv_is_refused(self, backup):
        header = read_header(backup)
        with pytest.raises(HeaderError):
            patch_iv(header.prefix, b"short")

    def test_a_prefix_with_no_cipher_block_is_refused(self):
        # There is nowhere to put a nonce, and inventing one would leave the
        # header disagreeing with the ciphertext it describes.
        with pytest.raises(HeaderError):
            patch_iv(b"", bytes(16))
