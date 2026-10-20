"""WhatsApp backup header (``crypt14`` / ``crypt15``).

A local WhatsApp backup is::

    [varint: length of the protobuf prefix]
    [protobuf prefix  (BackupPrefix)]
    [AES-256-GCM ciphertext   (zlib compressed msgstore.db)]
    [16 bytes GCM auth tag]
    [16 bytes MD5 checksum = md5(varint + prefix + ciphertext + tag)]

Everything before the ciphertext is parsed here **without** the protobuf
runtime: the prefix is four nested messages and pulling in ``protobuf`` for
that would be absurd.  The field numbers below are WhatsApp's own and come
from the published schema (``proto/backup_prefix.proto`` and friends in
wa-crypt-tools); every value in this module has been verified byte for byte
against a real WhatsApp 2.26 crypt15 file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "HeaderError",
    "KeyType",
    "BackupHeader",
    "read_header",
    "parse_prefix",
    "read_varint",
    "encode_varint",
    "decode_message",
    "build_prefix",
    "patch_jid_suffix",
]

MAGIC_WAM = b"WAM"
"""Prefix of the legacy fixed binary header used by crypt12 / early crypt14."""

DEFAULT_READ = 64 * 1024
"""How much of the file we slurp to find the prefix.  Headers are ~135 bytes."""

# Protobuf wire types.
_VARINT, _I64, _LEN, _I32 = 0, 1, 2, 5


class HeaderError(Exception):
    """The header is not shaped like a WhatsApp backup."""


# --------------------------------------------------------------------------- #
# Protobuf primitives
# --------------------------------------------------------------------------- #


def read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    """Decode a varint, returning ``(value, new position)``."""
    value = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise HeaderError("truncated varint in header")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 70:
            raise HeaderError("varint is absurdly long; not a WhatsApp header")


def encode_varint(value: int) -> bytes:
    """The protobuf encoding of a non-negative int."""
    if value < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_message(buf: bytes) -> Dict[int, List[Tuple[int, Any]]]:
    """Decode a protobuf message into ``{field number: [(wire type, value), ...]}``.

    Length delimited fields stay ``bytes``; unknown wire types raise rather
    than silently corrupting the parse.
    """
    out: Dict[int, List[Tuple[int, Any]]] = {}
    pos = 0
    while pos < len(buf):
        key, pos = read_varint(buf, pos)
        number, wire = key >> 3, key & 0x07
        if number == 0:
            raise HeaderError("field number 0 is invalid")
        if wire == _VARINT:
            value, pos = read_varint(buf, pos)
        elif wire == _LEN:
            size, pos = read_varint(buf, pos)
            if pos + size > len(buf):
                raise HeaderError(f"field {number} runs past the end of the header")
            value = buf[pos : pos + size]
            pos += size
        elif wire == _I64:
            if pos + 8 > len(buf):
                raise HeaderError(f"truncated fixed64 on field {number}")
            value, pos = buf[pos : pos + 8], pos + 8
        elif wire == _I32:
            if pos + 4 > len(buf):
                raise HeaderError(f"truncated fixed32 on field {number}")
            value, pos = buf[pos : pos + 4], pos + 4
        else:
            raise HeaderError(f"unsupported wire type {wire} on field {number}")
        out.setdefault(number, []).append((wire, value))
    return out


def _first(msg: Dict[int, List[Tuple[int, Any]]], number: int, default: Any = None) -> Any:
    entries = msg.get(number)
    return entries[0][1] if entries else default


def _text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def _number(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return int.from_bytes(raw, "big") if raw else None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Field numbers (WhatsApp's own names)
# --------------------------------------------------------------------------- #


class KeyType:
    """``key_type.proto``.  Which kind of key protects the backup."""

    WA_PROVIDED = 0  # WhatsApp holds it: crypt12 / crypt14
    E2EE_DEPRECATED = 1  # end to end, before the kind was spelled out
    E2EE_PASSWORD = 2  # derived from a user password
    E2EE_ENCRYPTION_KEY = 3  # the 64 hex key: today's crypt15
    E2EE_PASSKEY = 4  # derived from a passkey

    NAMES = {
        WA_PROVIDED: "WA_PROVIDED",
        E2EE_DEPRECATED: "E2EE_DEPRECATED",
        E2EE_PASSWORD: "E2EE_PASSWORD",
        E2EE_ENCRYPTION_KEY: "E2EE_ENCRYPTION_KEY",
        E2EE_PASSKEY: "E2EE_PASSKEY",
    }

    @classmethod
    def name(cls, value: Optional[int]) -> str:
        if value is None:
            return "unknown"
        return cls.NAMES.get(value, f"unknown({value})")


class PrefixField:
    """``backup_prefix.proto`` — ``BackupPrefix``."""

    KEY_TYPE_DEPRECATED = 1
    WA_PROVIDED_KEY_DATA = 2  # C14Cipher, crypt14
    E2EE_KEY_DATA = 3  # C15IV, crypt15
    BACKUP_METADATA = 4  # BackupExpiry
    PASSKEY_METADATA = 5
    KEY_TYPE_NEW = 6


class CipherField:
    """``C14_cipher.proto`` (crypt14) and ``C15_IV.proto`` (crypt15)."""

    C15_IV = 1  # encryption_iv
    C14_CIPHER_HEADER = 1
    C14_KEY_VERSION = 2
    C14_SERVER_SALT = 3
    C14_GOOGLE_ID_SALT = 4
    C14_IV = 5


class MetaField:
    """``backup_expiry.proto`` — ``BackupExpiry``."""

    APP_VERSION = 1
    DEVICE_MODEL = 2
    JID_SUFFIX = 3
    BACKUP_VERSION = 4
    MIGRATION_FIRST = 5  # fields 5..37 are the "feature table"
    MIGRATION_LAST = 37
    BACKUP_EXPORT_FILE_SIZE = 38
    CLEANED_DB = 39
    IDENTIFIER_TYPE = 42
    LID_SUFFIX = 43
    DISPLAY_SUFFIX = 44


# --------------------------------------------------------------------------- #
# Parsed header
# --------------------------------------------------------------------------- #


@dataclass
class BackupHeader:
    """Everything WhatsApp stores before the ciphertext."""

    path: Path
    file_size: int
    crypt_type: int
    header_len: int
    cipher_offset: int
    prefix: bytes

    iv: Optional[bytes] = None
    key_type: int = KeyType.E2EE_DEPRECATED
    key_type_new: Optional[int] = None
    app_version: Optional[str] = None
    device_model: Optional[str] = None
    jid_suffix: Optional[str] = None
    backup_version: Optional[int] = None
    features: List[int] = field(default_factory=list)
    backup_export_file_size: Optional[int] = None
    cleaned_db: bool = False
    identifier_type: Optional[int] = None
    lid_suffix: Optional[str] = None
    display_suffix: Optional[str] = None
    unknown_fields: List[str] = field(default_factory=list)

    @property
    def key_type_name(self) -> str:
        return KeyType.name(self.key_type)

    @property
    def cipher_size(self) -> int:
        """Ciphertext bytes, excluding the auth tag and the checksum."""
        return max(0, self.file_size - self.cipher_offset - 32)

    @property
    def new_number_hint(self) -> Optional[str]:
        """The owner number, if the header's own suffix narrows it to one."""
        return self.jid_suffix

    def summary(self) -> Dict[str, Any]:
        """A JSON friendly view, used by ``--json`` and by the tests."""
        return {
            "path": str(self.path),
            "file_size": self.file_size,
            "crypt_type": self.crypt_type,
            "header_len": self.header_len,
            "cipher_offset": self.cipher_offset,
            "iv": self.iv.hex() if self.iv else None,
            "key_type": self.key_type,
            "key_type_name": self.key_type_name,
            "key_type_new": self.key_type_new,
            "app_version": self.app_version,
            "device_model": self.device_model,
            "jid_suffix": self.jid_suffix,
            "backup_version": self.backup_version,
            "features": list(self.features),
            "backup_export_file_size": self.backup_export_file_size,
            "cleaned_db": self.cleaned_db,
            "identifier_type": self.identifier_type,
            "lid_suffix": self.lid_suffix,
            "display_suffix": self.display_suffix,
            "unknown_fields": list(self.unknown_fields),
        }


def parse_prefix(
    prefix: bytes,
    *,
    path: Path,
    file_size: int,
    header_len: int,
    cipher_offset: int,
) -> BackupHeader:
    """Turn a serialized ``BackupPrefix`` into a :class:`BackupHeader`."""
    msg = decode_message(prefix)

    iv = None
    c14 = msg.get(PrefixField.WA_PROVIDED_KEY_DATA)
    if c14:
        cipher = decode_message(c14[0][1])
        iv = _first(cipher, CipherField.C14_IV)
    c15 = msg.get(PrefixField.E2EE_KEY_DATA)
    if c15:
        inner = decode_message(c15[0][1])
        iv = _first(inner, CipherField.C15_IV)

    if c15:
        crypt_type = 15
    elif c14:
        crypt_type = 14
    else:
        # No cipher block at all: WhatsApp stopped writing one for crypt15 and
        # now relies on key_type alone.
        crypt_type = 15

    features: List[int] = []
    app_version = device_model = jid_suffix = lid_suffix = display_suffix = None
    backup_version = backup_size = identifier_type = None
    cleaned_db = False

    metadata = msg.get(PrefixField.BACKUP_METADATA)
    if metadata:
        meta = decode_message(metadata[0][1])
        app_version = _text(_first(meta, MetaField.APP_VERSION))
        device_model = _text(_first(meta, MetaField.DEVICE_MODEL))
        jid_suffix = _text(_first(meta, MetaField.JID_SUFFIX))
        lid_suffix = _text(_first(meta, MetaField.LID_SUFFIX))
        display_suffix = _text(_first(meta, MetaField.DISPLAY_SUFFIX))
        backup_version = _number(_first(meta, MetaField.BACKUP_VERSION))
        backup_size = _number(_first(meta, MetaField.BACKUP_EXPORT_FILE_SIZE))
        identifier_type = _number(_first(meta, MetaField.IDENTIFIER_TYPE))
        cleaned_db = bool(_first(meta, MetaField.CLEANED_DB, 0))
        # The "feature table" is one boolean per completed schema migration.
        for number, values in meta.items():
            if MetaField.MIGRATION_FIRST <= number <= MetaField.MIGRATION_LAST:
                if any(bool(v) for _w, v in values):
                    features.append(number)

    known = set(PrefixField.__dict__.values()) | {0}
    unknown = [str(number) for number in msg if number not in known]

    return BackupHeader(
        path=Path(path),
        file_size=file_size,
        crypt_type=crypt_type,
        header_len=header_len,
        cipher_offset=cipher_offset,
        prefix=prefix,
        iv=bytes(iv) if iv else None,
        key_type=_number(_first(msg, PrefixField.KEY_TYPE_DEPRECATED)) or 0,
        key_type_new=_number(_first(msg, PrefixField.KEY_TYPE_NEW)),
        app_version=app_version,
        device_model=device_model,
        jid_suffix=jid_suffix,
        backup_version=backup_version,
        features=sorted(features),
        backup_export_file_size=backup_size,
        cleaned_db=cleaned_db,
        identifier_type=identifier_type,
        lid_suffix=lid_suffix,
        display_suffix=display_suffix,
        unknown_fields=unknown,
    )


def read_header(path: "str | os.PathLike[str]", read_size: int = DEFAULT_READ) -> BackupHeader:
    """Read and parse the header of an encrypted backup.

    Only the first :data:`DEFAULT_READ` bytes are touched, so this is cheap
    even on a multi gigabyte backup.
    """
    target = Path(path)
    try:
        file_size = target.stat().st_size
    except OSError as exc:
        raise HeaderError(f"cannot stat {target}: {exc}") from exc

    with target.open("rb") as handle:
        head = handle.read(read_size)

    if len(head) < 4:
        raise HeaderError(f"{target} is too small to be a WhatsApp backup")

    if head.startswith(MAGIC_WAM):
        raise HeaderError(
            f"{target.name} uses the legacy crypt12/early-crypt14 fixed header, "
            "which wacrypt does not read yet"
        )

    header_len, offset = read_varint(head, 0)
    if header_len == 0:
        raise HeaderError(f"{target.name} has an empty header")
    if offset + header_len > len(head):
        raise HeaderError(
            f"header claims {header_len} bytes but only {len(head) - offset} were readable"
        )

    prefix = head[offset : offset + header_len]
    try:
        return parse_prefix(
            prefix,
            path=target,
            file_size=file_size,
            header_len=header_len,
            cipher_offset=offset + header_len,
        )
    except HeaderError as exc:
        # A header that will not parse is almost always a damaged file, and
        # "truncated varint in header" on its own sends people looking for a
        # key problem.
        raise HeaderError(
            f"{target.name} has a malformed header ({exc}); the file is "
            "corrupt, truncated, or not a WhatsApp backup"
        ) from exc


def patch_jid_suffix(prefix: bytes, new_suffix: str) -> bytes:
    """Rewrite ``BackupPrefix.backup_metadata.jid_suffix`` in place.

    Every other field is copied through verbatim, including the ones this
    schema cannot name.  Rebuilding the whole message from what we understand
    would silently drop them, and a header WhatsApp wrote but we did not model
    is exactly the field whose absence makes a restored backup fail.
    """
    message = decode_message(prefix)
    encoded_suffix = str(new_suffix).encode("utf-8")

    out = bytearray()
    for number, entries in message.items():
        for wire, value in entries:
            out += encode_varint((number << 3) | wire)

            if number == PrefixField.BACKUP_METADATA and wire == _LEN:
                out += encode_varint(len(_patch_metadata(value, encoded_suffix)))
                out += _patch_metadata(value, encoded_suffix)
            elif wire == _LEN:
                out += encode_varint(len(value)) + value
            elif wire == _VARINT:
                out += encode_varint(value)
            else:
                out += value
    return bytes(out)


def _patch_metadata(metadata: bytes, encoded_suffix: bytes) -> bytes:
    inner = decode_message(metadata)
    out = bytearray()
    wrote = False
    for number, entries in inner.items():
        for wire, value in entries:
            if number == MetaField.JID_SUFFIX and wire == _LEN:
                value = encoded_suffix
                wrote = True
            out += encode_varint((number << 3) | wire)
            if wire == _LEN:
                out += encode_varint(len(value)) + value
            elif wire == _VARINT:
                out += encode_varint(value)
            else:
                out += value
    if not wrote:
        out += encode_varint((MetaField.JID_SUFFIX << 3) | _LEN)
        out += encode_varint(len(encoded_suffix)) + encoded_suffix
    return bytes(out)


def build_prefix(
    *,
    iv: bytes,
    key_type: int = KeyType.E2EE_DEPRECATED,
    key_type_new: Optional[int] = KeyType.E2EE_ENCRYPTION_KEY,
    app_version: Optional[str] = None,
    device_model: Optional[str] = None,
    jid_suffix: Optional[str] = None,
    backup_version: Optional[int] = None,
    features: Optional[List[int]] = None,
    cleaned_db: bool = False,
    extra: bytes = b"",
) -> bytes:
    """Serialize a ``BackupPrefix``.

    ``extra`` is verbatim protobuf appended at the end of the message: WhatsApp
    keeps adding fields this schema does not model, and dropping them is the
    difference between a re-encryption WhatsApp accepts and one it rejects.
    """
    if len(iv) != 16:
        raise HeaderError(f"IV must be 16 bytes, got {len(iv)}")

    # C15IV: field 1, the 16 byte IV.  The length is computed from the encoded
    # block, never by hand — getting this wrong makes the prefix unparseable.
    iv_block = b"\x0a\x10" + iv

    body = b""
    body += b"\x08" + encode_varint(key_type)
    body += b"\x1a" + encode_varint(len(iv_block)) + iv_block

    meta = b""
    if app_version:
        encoded = app_version.encode("utf-8")
        meta += b"\x0a" + encode_varint(len(encoded)) + encoded
    if jid_suffix is not None:
        encoded = str(jid_suffix).encode("utf-8")
        meta += b"\x1a" + encode_varint(len(encoded)) + encoded
    if backup_version is not None:
        meta += b"\x20" + encode_varint(backup_version)
    for number in sorted(features or []):
        meta += encode_varint((number << 3) | _VARINT) + encode_varint(1)
    if cleaned_db:
        meta += encode_varint((MetaField.CLEANED_DB << 3) | _VARINT) + encode_varint(1)

    body += b"\x22" + encode_varint(len(meta)) + meta

    if key_type_new is not None:
        body += encode_varint((PrefixField.KEY_TYPE_NEW << 3) | _VARINT) + encode_varint(
            key_type_new
        )

    body += extra
    return body
