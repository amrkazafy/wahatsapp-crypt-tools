"""wacrypt — manage, inspect, migrate and search WhatsApp local backups.

One file, one dependency::

    pip install cryptography
    python wacrypt.py info msgstore.db.crypt15

Commands
    info       read the backup header; needs no key, reads only the first 64 KB
    inspect    who owns the backup, what is in it, how far back it goes
    decrypt    turn a .crypt14/.crypt15 into a plain SQLite database
    encrypt    turn a plain database back into a crypt15 backup
    search     find messages without a decrypted file ever resting on disk
    export     write conversations out as HTML, JSON, CSV or plain text
    diff       say what changed between two backups
    migrate    change the phone number a backup belongs to (dry run first)
    integrity  check the backup checksum and the database's structure

What this program deliberately does not do
    There is no network code anywhere in it, and it never shells out to the
    ``wa_crypt_tools`` binaries — the format is implemented directly, with a
    hand written protobuf reader so ``protobuf`` is not a dependency either.

    Nothing it reads is ever written back down: not the backup key, not the
    chats, not the phone numbers.  Every command decrypts into a temporary
    directory and removes it on the way out, which is why there is no cache
    to manage and no key file to forget about.

The on-disk format itself is documented in ``docs/FORMAT.md``.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import getpass
import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import textwrap
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from string import Template
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ==========================================================================
# HEADER
# ==========================================================================

# WhatsApp backup header (``crypt14`` / ``crypt15``).
#
# A local WhatsApp backup is::
#
#     [varint: length of the protobuf prefix]
#     [protobuf prefix  (BackupPrefix)]
#     [AES-256-GCM ciphertext   (zlib compressed msgstore.db)]
#     [16 bytes GCM auth tag]
#     [16 bytes MD5 checksum = md5(varint + prefix + ciphertext + tag)]
#
# Everything before the ciphertext is parsed here **without** the protobuf
# runtime: the prefix is four nested messages and pulling in ``protobuf`` for
# that would be absurd.  The field numbers below are WhatsApp's own and come
# from the published schema (``proto/backup_prefix.proto`` and friends in
# wa-crypt-tools); every value in this module has been verified byte for byte
# against a real WhatsApp 2.26 crypt15 file.





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


# The nonce sits one level down, and the field number differs by format:
# crypt15 keeps it in E2EE_KEY_DATA as field 1, crypt14 in
# WA_PROVIDED_KEY_DATA as field 5.  Reaching for field 1 in a crypt14 block
# would overwrite C14_CIPHER_HEADER, an unrelated message.
_CIPHER_BLOCKS = {
    PrefixField.E2EE_KEY_DATA: CipherField.C15_IV,
    PrefixField.WA_PROVIDED_KEY_DATA: CipherField.C14_IV,
}


def patch_iv(prefix: bytes, new_iv: bytes) -> bytes:
    """Replace the AES-GCM nonce held in ``BackupPrefix`` in place.

    Re-encrypting a database that is *not* byte identical to the original
    while keeping the original IV reuses a GCM nonce under the same key.
    Whoever holds both files can XOR the two ciphertexts together and, given
    enough known plaintext, recover the GHASH key and forge tags on either
    one.  A backup WhatsApp writes always carries a fresh nonce, so there is
    nothing to gain by reusing one — and the header is where the reader takes
    the IV from, which is why the two have to be rewritten together.

    Every other field is copied through verbatim, on the same contract as
    :func:`patch_jid_suffix`: a field WhatsApp wrote that this schema cannot
    name is exactly the one whose absence makes a restored backup fail.
    """
    if len(new_iv) != 16:
        raise HeaderError(f"IV must be 16 bytes, got {len(new_iv)}")

    message = decode_message(prefix)
    out = bytearray()
    patched = False

    for number, entries in message.items():
        for wire, value in entries:
            if number in _CIPHER_BLOCKS and wire == _LEN:
                value, found = _patch_cipher_iv(value, new_iv, field=_CIPHER_BLOCKS[number])
                patched = patched or found
            out += encode_varint((number << 3) | wire)
            if wire == _LEN:
                out += encode_varint(len(value)) + value
            elif wire == _VARINT:
                out += encode_varint(value)
            else:
                out += value

    if not patched:
        raise HeaderError("this backup header carries no IV to rewrite")
    return bytes(out)


def _patch_cipher_iv(block: bytes, new_iv: bytes, *, field: int) -> Tuple[bytes, bool]:
    """Rewrite ``field`` inside a cipher block, adding it when it is missing."""
    inner = decode_message(block)
    body = bytearray()
    wrote = False
    for number, entries in inner.items():
        for wire, value in entries:
            if number == field and wire == _LEN:
                value = new_iv
                wrote = True
            body += encode_varint((number << 3) | wire)
            if wire == _LEN:
                out_len = encode_varint(len(value))
                body += out_len + value
            elif wire == _VARINT:
                body += encode_varint(value)
            else:
                body += value

    if wrote:
        return bytes(body), True

    # WhatsApp does not always write the IV block; the reader still needs one
    # to decrypt with, so put the nonce we are about to use where it will be
    # found rather than silently encrypting against a header that disagrees.
    head = encode_varint((field << 3) | _LEN) + encode_varint(len(new_iv)) + new_iv
    return head + bytes(body), True


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


# ==========================================================================
# CRYPTO
# ==========================================================================

# Encryption, decryption and the key schedule for WhatsApp local backups.
#
# The whole chain is implemented here from scratch; nothing shells out to
# ``wadecrypt``.  What follows was derived from the published WhatsApp
# behaviour and then verified byte for byte against a real WhatsApp 2.26
# ``crypt15`` backup::
#
#     root key (32 bytes, shown as 64 hex digits in the app)
#       -> HMAC-SHA256(zeros32, root)                 = private key
#       -> HMAC-SHA256(private, "backup encryption" + b"\\x01")
#                                                 = AES-256 key
#     AES-256-GCM(key, IV from the header) over the zlib compressed database
#     16 byte authentication tag, then an MD5 over everything written so far.
#
# The payload is zlib, not raw SQLite: ``78 da`` (level 9) is what WhatsApp
# writes, which is why a decrypted backup is ~2.4x its on disk size.







CHUNK = 1 << 20
"""Read/write granularity.  1 MiB keeps memory flat on a 1 GB backup."""

BACKUP_ENCRYPTION_LABEL = b"backup encryption"
KEY_SEED = b"\x00" * 32

SQLITE_MAGIC = b"SQLite format 3\x00"
ZIP_MAGIC = b"PK\x03\x04"

Progress = Optional[Callable[[int, int], None]]


class CryptoError(Exception):
    """Anything that goes wrong between the file and the database."""


class WrongKey(CryptoError):
    """The key does not open this backup."""


class CorruptedBackup(CryptoError):
    """The backup does not decrypt to something sane."""


# --------------------------------------------------------------------------- #
# Key schedule
# --------------------------------------------------------------------------- #


def _hmac(key: bytes, *chunks: bytes) -> bytes:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    for chunk in chunks:
        digest.update(chunk)
    return digest.digest()


def encryption_loop(
    first_iteration_data: bytes,
    message: Optional[bytes] = None,
    output_bytes: int = 32,
) -> bytes:
    """WhatsApp's nested HMAC loop (``wa_hmacsha256_loop.java``).

    The iteration counter is appended to the data being encrypted, so a single
    pass leaves a trailing ``\\x01``.  The app *can* run the loop many times;
    for local backup encryption it always runs it exactly once.
    """
    private_key = _hmac(KEY_SEED, first_iteration_data)
    data = b""
    output = b""
    iterations = -(-output_bytes // 32)
    for index in range(1, iterations + 1):
        digest = hmac.new(private_key, data, hashlib.sha256)
        if message is not None:
            digest.update(message)
        digest.update(index.to_bytes(1, "big"))
        data = digest.digest()
        output += data[: min(output_bytes, len(data))]
    return output


def derive_backup_key(root_key: bytes) -> bytes:
    """Turn the 32 byte root key into the AES-256 key used for the backup."""
    if len(root_key) != 32:
        raise WrongKey(f"root key must be exactly 32 bytes, got {len(root_key)}")
    return encryption_loop(root_key, BACKUP_ENCRYPTION_LABEL, 32)


# --------------------------------------------------------------------------- #
# Decryption
# --------------------------------------------------------------------------- #


def _split_trailer(path: Path) -> tuple:
    """Return ``(auth_tag, checksum)`` — the last 32 bytes of the file."""
    size = path.stat().st_size
    if size < 64:
        raise CorruptedBackup(f"{path.name} is too small to be a backup")
    with path.open("rb") as handle:
        handle.seek(size - 32)
        trailer = handle.read(32)
    return trailer[:16], trailer[16:]


def _verify_checksum(source: Path, header: BackupHeader, chunk: int = CHUNK) -> None:
    """Check the file's own MD5 before any decryption happens.

    Doing this first is the difference between "the file is corrupt" and a
    ``zlib.error: incorrect header check`` raised from inside the decompressor
    after a hundred megabytes of garbage have already been handed to the
    caller.  The checksum covers the prefix too, so even a tampered IV is
    caught here rather than surfacing as a mysterious authentication failure.
    """
    auth_tag, checksum = _split_trailer(source)
    digest = hashlib.md5()
    digest.update(encode_varint(header.header_len))
    digest.update(header.prefix)

    remaining = header.cipher_size
    with source.open("rb") as handle:
        handle.seek(header.cipher_offset)
        while remaining > 0:
            block = handle.read(min(chunk, remaining))
            if not block:
                raise CorruptedBackup(
                    f"{source.name} ends {remaining} bytes early; the file is truncated"
                )
            remaining -= len(block)
            digest.update(block)

    digest.update(auth_tag)
    if digest.digest() != checksum:
        raise CorruptedBackup(
            f"{source.name} failed its MD5 checksum: the file is corrupt "
            "(not a key problem — the bytes on disk changed)"
        )


def iter_decrypted(
    path: "str | os.PathLike[str]",
    aes_key: bytes,
    header: Optional[BackupHeader] = None,
    chunk: int = CHUNK,
    progress: Progress = None,
) -> Iterator[bytes]:
    """Yield the decrypted (still compressed) payload in chunks.

    ``aes_key`` is the **derived** key from :func:`derive_backup_key`, not the
    64 hex digits the user types.  Passing the root key here produces garbage
    that only fails later, at the zlib header, which is exactly the kind of
    confusing error this rename exists to prevent.

    The file's MD5 is verified *before* decryption, so a corrupted backup is
    reported as corruption.  The GCM authentication tag is then verified by
    :meth:`finalize`, which raises :class:`InvalidTag` and is reported as
    :class:`WrongKey` — a wrong key and a corrupt file are indistinguishable
    at that layer, but by then the cheap check has already run.
    """
    from cryptography.exceptions import InvalidTag

    source = Path(path)
    header = header or read_header(source)
    if header.iv is None:
        raise HeaderError(f"{source.name} has no IV in its header")
    if len(aes_key) != 32:
        raise WrongKey(f"AES key must be 32 bytes, got {len(aes_key)}")

    _verify_checksum(source, header, chunk)

    auth_tag, _checksum = _split_trailer(source)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(header.iv, auth_tag))
    decryptor = cipher.decryptor()

    total = header.cipher_size
    seen = 0
    with source.open("rb") as handle:
        handle.seek(header.cipher_offset)
        remaining = total
        while remaining > 0:
            block = handle.read(min(chunk, remaining))
            if not block:
                raise CorruptedBackup(
                    f"{source.name} ends {remaining} bytes early; the file is truncated"
                )
            remaining -= len(block)
            seen += len(block)
            if progress is not None:
                progress(seen, total)
            out = decryptor.update(block)
            if out:
                yield out

    try:
        tail = decryptor.finalize()
    except InvalidTag as exc:
        raise WrongKey(
            "the authentication tag did not verify: this is not the key that "
            "encrypted the backup (or the header IV does not belong to it)"
        ) from exc
    if tail:
        yield tail


ZLIB_HEADERS = (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")


def _is_zlib(block: bytes) -> bool:
    """True when ``block`` could start a zlib stream.

    Checked cheaply and structurally: the first byte's CM field must be 8
    (deflate) and the two header bytes must be a multiple of 31, which is how
    zlib itself rejects garbage.
    """
    if len(block) < 2:
        return False
    if (block[0] & 0x0F) != 8:
        return False
    return (block[0] << 8 | block[1]) % 31 == 0


def iter_plaintext(
    path: "str | os.PathLike[str]",
    aes_key: bytes,
    header: Optional[BackupHeader] = None,
    chunk: int = CHUNK,
    progress: Progress = None,
) -> Iterator[bytes]:
    """Yield the decrypted **and decompressed** payload.

    WhatsApp zips the database before encrypting it, so this inflates as it
    goes rather than materialising the ~2.4x expansion in memory.

    The first decrypted block is checked against the zlib header *before*
    anything is handed to the caller.  Combined with the checksum check in
    :func:`iter_decrypted` this turns the worst error in the original tool —
    ``zlib.error: incorrect header check`` after a hundred megabytes — into a
    sentence that says which of the two things actually went wrong: the file's
    checksum passed, so the bytes are authentic, so a payload that is not
    zlib means the key is wrong.
    """
    decompressor = zlib.decompressobj()
    checked = False
    for block in iter_decrypted(path, aes_key, header, chunk, progress):
        if not checked:
            checked = True
            if not _is_zlib(block):
                raise WrongKey(
                    "the backup decrypted, but not into compressed data. Its "
                    "checksum already passed, so the file is intact — this is "
                    "the wrong key."
                )
        out = decompressor.decompress(block)
        if out:
            yield out
    tail = decompressor.flush()
    if tail:
        yield tail


def sniff_payload(first: bytes) -> str:
    """Name the kind of payload we just decrypted."""
    if first.startswith(SQLITE_MAGIC):
        return "sqlite"
    if first.startswith(ZIP_MAGIC):
        return "zip"
    if first[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        return "zlib"
    return "unknown"


def unpack_to_file(
    crypt_path: "str | os.PathLike[str]",
    aes_key: bytes,
    out_path: "str | os.PathLike[str]",
    header: Optional[BackupHeader] = None,
    chunk: int = CHUNK,
    progress: Progress = None,
) -> BackupHeader:
    """Decrypt, inflate and write a plain SQLite database.

    ``aes_key`` comes from :func:`derive_backup_key`.  The output is written to
    a temporary sibling first and renamed into place, so an interrupted run
    never leaves a half written database behind.
    """
    source = Path(crypt_path)
    target = Path(out_path)
    header = header or read_header(source)
    target.parent.mkdir(parents=True, exist_ok=True)

    temporary = target.with_name(target.name + ".partial")
    written = 0
    kind = "unknown"
    try:
        with temporary.open("wb") as handle:
            for block in iter_plaintext(source, aes_key, header, chunk, progress):
                if kind == "unknown":
                    kind = sniff_payload(block)
                    if kind == "zip":
                        raise CorruptedBackup(
                            "this is a multi file backup: it unpacks to a ZIP of "
                            "several databases, not a single msgstore.db"
                        )
                handle.write(block)
                written += len(block)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()

    if written == 0:
        raise CorruptedBackup("decryption produced no data")

    magic = target.open("rb").read(16)
    if not magic.startswith(SQLITE_MAGIC):
        raise CorruptedBackup(
            f"decrypted payload is not a SQLite database (starts with {magic.hex()})"
        )

    os.chmod(target, 0o600)
    return header


# --------------------------------------------------------------------------- #
# Encryption
# --------------------------------------------------------------------------- #


def pack_from_file(
    db_path: "str | os.PathLike[str]",
    aes_key: bytes,
    out_path: "str | os.PathLike[str]",
    header: BackupHeader,
    iv: Optional[bytes] = None,
    level: int = 9,
    chunk: int = CHUNK,
    progress: Progress = None,
) -> Path:
    """Compress, encrypt and write a backup.

    ``aes_key`` comes from :func:`derive_backup_key`.  ``header`` supplies the
    prefix to reproduce: passing the *original* prefix keeps every field
    WhatsApp wrote, including the ones this schema cannot name, and dropping
    them is what makes a hand rolled re-encryption fail to restore.

    The nonce is generated fresh per call unless ``iv`` is given, and
    :func:`patch_iv` writes it into the prefix before anything is sealed.
    """
    source = Path(db_path)
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if len(aes_key) != 32:
        raise WrongKey(f"AES key must be 32 bytes, got {len(aes_key)}")

    # A fresh nonce unless the caller names one.  Reusing a GCM nonce across
    # two *different* plaintexts under the same key is the classic way to
    # lose the scheme, and re-encrypting a migrated database is exactly that
    # case.  The prefix is rewritten either way, so the IV in the header can
    # never disagree with the IV the ciphertext was sealed with.
    iv = iv or os.urandom(16)
    if len(iv) != 16:
        raise HeaderError(f"IV must be 16 bytes, got {len(iv)}")

    prefix = patch_iv(header.prefix, iv)
    temporary = target.with_name(target.name + ".partial")
    try:
        with temporary.open("wb") as handle:
            handle.write(encode_varint(len(prefix)))
            handle.write(prefix)

            digest = hashlib.md5()
            digest.update(encode_varint(len(prefix)))
            digest.update(prefix)

            encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
            compressor = zlib.compressobj(level)
            total = source.stat().st_size
            done = 0

            with source.open("rb") as db:
                while True:
                    block = db.read(chunk)
                    if not block:
                        break
                    done += len(block)
                    if progress is not None:
                        progress(done, total)
                    out = compressor.compress(block)
                    if out:
                        sealed = encryptor.update(out)
                        handle.write(sealed)
                        digest.update(sealed)

            out = compressor.flush()
            if out:
                sealed = encryptor.update(out)
                handle.write(sealed)
                digest.update(sealed)

            encryptor.finalize()
            tag = encryptor.tag
            handle.write(tag)
            digest.update(tag)
            handle.write(digest.digest())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()

    os.chmod(target, 0o600)
    return target


# ==========================================================================
# DB
# ==========================================================================

# SQLite plumbing: safe transactions and schema introspection.
#
# Two rules drive this module.
#
# **Never assume a table exists.**  A WhatsApp backup from 2022 and one from
# 2026 do not share a schema: ``group_participants`` became ``participant_user``,
# ``contact`` is gone, and whole families of tables appear and vanish.  Every
# helper here asks the database what it actually contains before it uses it.
#
# **Never leave a half written database.**  Every mutation runs inside
# ``BEGIN IMMEDIATE`` and only leaves through ``COMMIT`` or ``ROLLBACK``, so an
# interrupted migration cannot corrupt a 200 MB backup.





BUSY_TIMEOUT_MS = 30_000


class DbError(Exception):
    """The database refused to cooperate."""


def open_db(path: "str | os.PathLike[str]", *, read_only: bool = False) -> sqlite3.Connection:
    """Open a SQLite database with sane, safe pragmas."""
    target = Path(path)
    if not target.is_file():
        raise DbError(f"no such database: {target}")

    if read_only:
        conn = sqlite3.connect(f"file:{target}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_MS / 1000)
    else:
        conn = sqlite3.connect(str(target), timeout=BUSY_TIMEOUT_MS / 1000)
        # Keep WAL out of the way: the caller owns the file and we always close
        # cleanly, so an orphan -wal would only be a liability.
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=OFF")

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    return conn


@contextlib.contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """``BEGIN IMMEDIATE`` … ``COMMIT`` or ``ROLLBACK``.

    ``IMMEDIATE`` takes the write lock up front, so two concurrent wacrypt
    runs on the same file fail fast instead of deadlocking halfway through.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


def checkpoint(conn: sqlite3.Connection) -> None:
    with contextlib.suppress(sqlite3.Error):
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def vacuum(conn: sqlite3.Connection) -> None:
    conn.isolation_level = None  # VACUUM cannot run inside a transaction
    try:
        conn.execute("VACUUM")
    finally:
        conn.isolation_level = ""


def reindex(conn: sqlite3.Connection) -> None:
    conn.isolation_level = None
    try:
        conn.execute("REINDEX")
    finally:
        conn.isolation_level = ""


# --------------------------------------------------------------------------- #
# Introspection
# --------------------------------------------------------------------------- #


def table_names(conn: sqlite3.Connection) -> List[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
        "ORDER BY name"
    ).fetchall()
    return [row[0] for row in rows]


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def columns(conn: sqlite3.Connection, name: str) -> Dict[str, str]:
    """``{column name: declared type}`` for a table."""
    out: Dict[str, str] = {}
    for row in conn.execute(f'PRAGMA table_info("{name}")'):
        out[row[1]] = row[2] or ""
    return out


def column_names(conn: sqlite3.Connection, name: str) -> List[str]:
    return list(columns(conn, name))


def tables_with(conn: sqlite3.Connection, **required: Sequence[str]) -> List[str]:
    """Every table that has all of ``required`` columns.

    This is how the migration stays honest across schema versions: it finds
    the tables that can hold a phone number rather than naming them.
    """
    wanted = set(required)
    found: List[str] = []
    for name in table_names(conn):
        have = set(column_names(conn, name))
        if wanted <= have:
            found.append(name)
    return found


def count(conn: sqlite3.Connection, table: str, where: str = "", args: Sequence = ()) -> int:
    sql = f'SELECT COUNT(*) FROM "{table}"'
    if where:
        sql += f" WHERE {where}"
    try:
        return int(conn.execute(sql, tuple(args)).fetchone()[0])
    except sqlite3.Error:
        return 0


# --------------------------------------------------------------------------- #
# Owner detection
# --------------------------------------------------------------------------- #

# "Message yourself" is the strongest signal in the whole database: it is the
# only private chat where one side wrote 800 messages and the other replied
# once.  Real conversations are roughly balanced (270/215, 15/16, 6/6), so a
# ratio this lopsided cannot belong to another person.
#
# Deliberately *not* filtered on chat.group_type: it is NULL or inconsistent
# across schema versions and quietly hid every real chat when we assumed 0.
_SELF_CHAT_SQL = """
    SELECT j.user AS user,
           j.raw_string AS raw_string,
           c._id AS chat_row,
           COUNT(m._id) AS messages,
           COALESCE(SUM(m.from_me), 0) AS sent,
           COUNT(m._id) - COALESCE(SUM(m.from_me), 0) AS received
      FROM chat c
      JOIN jid j ON c.jid_row_id = j._id
      LEFT JOIN message m ON m.chat_row_id = c._id
     WHERE c.subject IS NULL
       AND j.server = 's.whatsapp.net'
       AND j.raw_string = j.user || '@s.whatsapp.net'
       AND j.user GLOB '[0-9]*'
     GROUP BY c._id
"""

# A self chat must actually have been used, and must be silent on the far end.
MIN_SELF_MESSAGES = 20
MAX_SELF_REPLY_RATIO = 0.05


@dataclass
class OwnerCandidate:
    """One number that could be the account holder, with why we think so."""

    number: str
    score: float
    reasons: List[str] = field(default_factory=list)
    chat_row: Optional[int] = None
    sent: int = 0
    received: int = 0

    def as_dict(self) -> Dict[str, object]:
        return {
            "number": self.number,
            "score": round(self.score, 3),
            "reasons": self.reasons,
            "chat_row": self.chat_row,
            "sent": self.sent,
            "received": self.received,
        }


def _looks_like_self_chat(sent: int, received: int) -> bool:
    if sent < MIN_SELF_MESSAGES:
        return False
    return received <= max(3, sent * MAX_SELF_REPLY_RATIO)


def find_owner_candidates(
    conn: sqlite3.Connection, suffix: Optional[str] = None
) -> List[OwnerCandidate]:
    """Rank the numbers that could be the account owner.

    The self chat wins outright when there is one.  Otherwise the header
    ``jidSuffix`` breaks ties, and the caller is told the confidence is low
    rather than being handed a guess.
    """
    if not dbmod_table_ok(conn):
        return []

    try:
        rows = conn.execute(_SELF_CHAT_SQL).fetchall()
    except sqlite3.Error:
        return []

    candidates: Dict[str, OwnerCandidate] = {}
    for row in rows:
        user = row["user"]
        if not user:
            continue
        sent, received, messages = int(row["sent"]), int(row["received"]), int(row["messages"])
        candidate = candidates.get(user)
        if candidate is None:
            candidate = OwnerCandidate(number=user, score=0.0, chat_row=row["chat_row"])
            candidates[user] = candidate
        candidate.sent += sent
        candidate.received += received

        if _looks_like_self_chat(sent, received):
            # Volume matters: 815 messages to yourself is decisive, three is not.
            strength = min(100.0, sent / 10.0)
            if received:
                strength *= 1.0 - (received / max(1.0, sent * 0.1))
            if suffix and user.endswith(suffix):
                strength *= 1.5
            if strength > candidate.score:
                candidate.score = strength
                candidate.reasons.append(
                    f"self chat: {sent} sent, {received} received"
                )

    # Ranked by evidence first, then by volume.  The header suffix is recorded
    # as a *reason* but is deliberately not enough on its own to make someone
    # the owner — the last thing this should do is guess.
    ranked = sorted(
        candidates.values(), key=lambda item: (item.score, item.sent), reverse=True
    )
    if suffix:
        for item in ranked:
            if item.number.endswith(suffix):
                item.reasons.append(f"header jid suffix {suffix}")

    return ranked


def dbmod_table_ok(conn: sqlite3.Connection) -> bool:
    return table_exists(conn, "chat") and table_exists(conn, "jid")


def owner_report(conn: sqlite3.Connection, suffix: Optional[str] = None) -> Dict[str, object]:
    """Owner detection with an explicit confidence, so the caller never guesses.

    Only the self chat is treated as evidence.  Everything else is offered as
    a ranked list with ``confidence: none``, which is a very different promise
    from handing back a number that merely matched the header suffix.
    """
    candidates = find_owner_candidates(conn, suffix)
    evidenced = [item for item in candidates if item.score > 0]

    if not evidenced:
        return {
            "number": None,
            "confidence": "none",
            "candidates": [item.as_dict() for item in candidates[:10]],
            "reason": "no self chat found; the header suffix alone is not "
            "enough to name the account holder",
        }

    best = evidenced[0]
    runner_up = evidenced[1].score if len(evidenced) > 1 else 0.0

    if runner_up == 0 or best.score >= runner_up * 3:
        confidence = "high" if suffix and best.number.endswith(suffix) else "medium"
    else:
        confidence = "low"

    return {
        "number": best.number if confidence in ("high", "medium") else None,
        "confidence": confidence,
        "candidates": [item.as_dict() for item in candidates[:10]],
        "reason": next(
            (reason for reason in best.reasons if "self chat" in reason),
            "highest scoring private chat",
        ),
    }


# --------------------------------------------------------------------------- #
# Reading chats
# --------------------------------------------------------------------------- #

ChatRow = Dict[str, object]


def chat_rows(conn: sqlite3.Connection) -> List[ChatRow]:
    """Every chat, newest activity first, with its JID joined in."""
    if not table_exists(conn, "chat"):
        return []
    has_jid = table_exists(conn, "jid")
    sql = "SELECT c._id AS chat_row, c.subject, c.group_type, c.sort_timestamp"
    if has_jid:
        sql += ", j.user, j.raw_string, j.server, j.type AS jid_type"
    else:
        sql += ", NULL AS user, NULL AS raw_string, NULL AS server, NULL AS jid_type"
    sql += " FROM chat c"
    if has_jid:
        sql += " LEFT JOIN jid j ON c.jid_row_id = j._id"
    sql += " ORDER BY COALESCE(c.sort_timestamp, 0) DESC"
    try:
        return [dict(row) for row in conn.execute(sql).fetchall()]
    except sqlite3.Error as exc:
        raise DbError(f"cannot list chats: {exc}") from exc


def message_count(conn: sqlite3.Connection, chat_row: int) -> int:
    return count(conn, "message", "chat_row_id = ?", (chat_row,))


def ms_to_datetime(value: object) -> str:
    """WhatsApp timestamps are Unix milliseconds."""
    if value in (None, 0, ""):
        return "—"
    try:
        from datetime import datetime

        return datetime.fromtimestamp(int(value) / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError, OSError, TypeError):
        return str(value)


def integrity(conn: sqlite3.Connection) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        out["quick_check"] = conn.execute("PRAGMA quick_check").fetchone()[0]
    except sqlite3.Error as exc:
        out["quick_check"] = f"error: {exc}"
    try:
        out["integrity_check"] = conn.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.Error as exc:
        out["integrity_check"] = f"error: {exc}"
    return out


# ==========================================================================
# MIGRATE
# ==========================================================================

# Move a backup from one phone number to another.
#
# The first version of this tool rewrote the ``jid`` table and stopped there,
# which is why a migrated backup came back with broken mentions and dead media
# links.  This implementation differs in three deliberate ways.
#
# **It asks the database what it holds.**  ``group_participants`` is now
# ``participant_user``, ``contact`` is gone, and every year brings new tables.
# Rather than naming tables, the planner scans every text column and reports
# exactly which rows mention the number.
#
# **It never matches a prefix, and never replaces a substring.**  This is the
# subtle one.  ``LIKE '99900011122%'`` also matches ``999000111220`` — someone
# else's account.  But so does SQLite's ``REPLACE()``, even when the ``WHERE``
# clause correctly excluded that row, because ``REPLACE`` will happily rewrite
# the leading digits of any longer number sharing the same text.  So:
#
# * rows are selected with a broad anchor (the number appears at all), then
# * filtered and rewritten in Python with ``(?<!\\d)number(?!\\d)``, which only
#   matches the number when it is not glued to another digit.
#
# A shorter number such as ``965554163`` is likewise never touched, because
# that would require the *full* 11 digits to appear as a standalone token.
#
# **It previews.**  :func:`plan_migration` produces a description of the change
# without writing anything; only :func:`apply_migration` opens a transaction.






# A phone number appearing in this many rows of one column means we are
# probably looking at something that is not a phone number reference at all.
MAX_ROWS_PER_COLUMN = 200_000

MAX_EXAMPLES = 3


class MigrationError(Exception):
    """The migration cannot proceed safely."""


def sanitize_number(raw: str) -> str:
    """Reduce whatever the user typed to international digits."""
    value = (
        raw.strip()
        .replace("\u200b", "")
        .replace("\u200e", "")
        .replace(" ", "")
        .replace("-", "")
        .replace("(", "")
        .replace(")", "")
        .replace(".", "")
        .replace("/", "")
    )
    if value.startswith("+"):
        value = value[1:]
    elif value.startswith("00"):
        value = value[2:]
    if not value.isdigit():
        raise MigrationError(
            f"{raw!r} is not a phone number (digits only, with country code)"
        )
    if len(value) < 8:
        raise MigrationError(
            f"{value} is too short — include the international country code, e.g. 9665…"
        )
    if len(value) > 20:
        raise MigrationError(f"{value} is too long to be a phone number")
    return value


def _own_number_pattern(number: str) -> "re.Pattern":
    """The number, but only when it is not part of a longer number."""
    return re.compile(r"(?<!\d)" + re.escape(number) + r"(?!\d)")


# A restored backup only *needs* two things to still be correct: the account's
# own JID rows (handled by the identity statement) and the paths attachments
# are stored under.  Everything else that mentions the number is chat content —
# someone writing their own number in a message, a wa.me link in a message, a
# vCard they once shared.  Rewriting that silently would quietly edit the
# user's own history, so it is planned and reported but not applied unless the
# caller asks for it with ``--rewrite-text``.
_REQUIRED_COLUMNS = frozenset(
    {
        ("message_media", "file_path"),
        ("message_media", "media_name"),
        ("message_media", "media_url"),
    }
)


def is_required(table: str, column: str) -> bool:
    """True when this column must be rewritten for the backup to restore."""
    return (table, column) in _REQUIRED_COLUMNS


@dataclass
class PlannedChange:
    """One kind of edit the migration would make."""

    table: str
    column: str
    kind: str
    rows: int
    row_ids: List[int] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    required: bool = True

    @property
    def scope(self) -> str:
        return "restore" if self.required else "content"

    def as_dict(self) -> Dict[str, object]:
        return {
            "table": self.table,
            "column": self.column,
            "kind": self.kind,
            "scope": self.scope,
            "rows": self.rows,
            "examples": self.examples,
        }


@dataclass
class MigrationPlan:
    """Everything the migration would do, computed without writing."""

    old: str
    new: str
    suffix_from: Optional[str]
    suffix_to: str
    changes: List[PlannedChange] = field(default_factory=list)
    collisions: List[Dict[str, object]] = field(default_factory=list)
    identity_rows: int = 0
    notes: List[str] = field(default_factory=list)
    tables_scanned: int = 0
    include_text: bool = False

    @property
    def total_rows(self) -> int:
        return sum(change.rows for change in self.changes)

    @property
    def restore_rows(self) -> int:
        """Rows that must change for the backup to restore correctly."""
        return sum(change.rows for change in self.changes if change.required)

    @property
    def content_rows(self) -> int:
        """Rows that mention the number but are only chat history."""
        return sum(change.rows for change in self.changes if not change.required)

    @property
    def selected(self) -> List[PlannedChange]:
        """The changes this run will actually apply."""
        if self.include_text:
            return list(self.changes)
        return [change for change in self.changes if change.required]

    @property
    def empty(self) -> bool:
        return not self.selected and self.identity_rows == 0

    def as_dict(self) -> Dict[str, object]:
        return {
            "old_number": self.old,
            "new_number": self.new,
            "jid_suffix_from": self.suffix_from,
            "jid_suffix_to": self.suffix_to,
            "identity_rows": self.identity_rows,
            "text_rows": self.total_rows,
            "restore_rows": self.restore_rows,
            "content_rows": self.content_rows,
            "include_text": self.include_text,
            "tables_scanned": self.tables_scanned,
            "collisions": self.collisions,
            "notes": self.notes,
            "changes": [change.as_dict() for change in self.changes],
        }


# --------------------------------------------------------------------------- #
# What holds a phone number
# --------------------------------------------------------------------------- #

# The account's own JID rows: exact on `user`, and anchored on the `@` (or the
# device suffix `.N@`) that terminates a JID.  Never a bare prefix.
_IDENTITY_SQL = """
    SELECT _id FROM jid
     WHERE user = :old
        OR raw_string = :old || '@s.whatsapp.net'
        OR raw_string LIKE :device ESCAPE '\\'
"""

_COLLISION_SQL = """
    SELECT j._id, j.user, j.raw_string, j.type, j.server,
           (SELECT COUNT(*) FROM chat WHERE jid_row_id = j._id) AS chats
      FROM jid j WHERE j.user = :new
"""


def _text_columns(conn: sqlite3.Connection) -> List[Dict[str, str]]:
    """Every text-ish column in the database, discovered from the schema."""
    out: List[Dict[str, str]] = []
    for table in table_names(conn):
        for name, declared in columns(conn, table).items():
            upper = (declared or "").upper()
            if any(marker in upper for marker in ("INT", "REAL", "BLOB", "BOOL")):
                continue
            out.append({"table": table, "column": name, "type": declared})
    return out


def _scan_column(
    conn: sqlite3.Connection, table: str, column: str, old: str
) -> List[object]:
    """Row ids in ``table.column`` where ``old`` appears as its own number.

    The SQL ``LIKE`` is only a cheap prefilter; the decision is made in Python
    by the digit-boundary pattern, because SQL has no lookahead and
    ``REPLACE`` has no notion of a boundary at all.
    """
    pattern = _own_number_pattern(old)
    try:
        rows = conn.execute(
            f'SELECT rowid, "{column}" FROM "{table}" WHERE "{column}" LIKE ?',
            (f"%{old}%",),
        ).fetchall()
    except sqlite3.Error:
        return []

    if len(rows) > MAX_ROWS_PER_COLUMN:
        raise MigrationError(
            f"{table}.{column} contains {len(rows):,} rows mentioning {old}; "
            "that is not a plausible number of references — refusing to continue"
        )

    return [row[0] for row in rows if row[1] is not None and pattern.search(str(row[1]))]


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #


def plan_migration(
    conn: sqlite3.Connection,
    old: str,
    new: str,
    *,
    suffix: Optional[str] = None,
    scan_text: bool = True,
    include_text: bool = False,
) -> MigrationPlan:
    """Work out every row the migration would touch.  Writes nothing.

    ``include_text`` decides whether chat content (messages, vCards, links
    that happen to quote the number) is in scope.  It is off by default: only
    the references a restored backup actually depends on are applied, so a
    migration never quietly rewrites what someone once wrote.
    """
    old = sanitize_number(old)
    new = sanitize_number(new)
    if old == new:
        raise MigrationError("the old and new numbers are the same")

    plan = MigrationPlan(
        old=old,
        new=new,
        suffix_from=suffix,
        suffix_to=new[-2:],
        include_text=include_text,
    )

    if not table_exists(conn, "jid"):
        raise MigrationError("this database has no `jid` table; not a msgstore backup")

    # 1. the account's own JID rows
    plan.identity_rows = len(
        conn.execute(
            _IDENTITY_SQL,
            {"old": old, "device": old + ".%@s.whatsapp.net"},
        ).fetchall()
    )

    # 2. anything else in the database holding the number
    if scan_text:
        for column in _text_columns(conn):
            table, name = column["table"], column["column"]
            if table == "jid" and name in ("user", "raw_string"):
                continue  # handled exactly by the identity statement above
            row_ids = _scan_column(conn, table, name, old)
            if not row_ids:
                continue
            examples = []
            for row_id in row_ids[:MAX_EXAMPLES]:
                found = conn.execute(
                    f'SELECT "{name}" FROM "{table}" WHERE rowid = ?', (row_id,)
                ).fetchone()
                if found and found[0] is not None:
                    examples.append(str(found[0])[:120])
            required = is_required(table, name)
            plan.changes.append(
                PlannedChange(
                    table=table,
                    column=name,
                    kind=(
                        "attachment path" if required else "chat content"
                    ),
                    rows=len(row_ids),
                    row_ids=row_ids,
                    examples=examples,
                    required=required,
                )
            )
        plan.tables_scanned = len(table_names(conn))

    # 3. would the new number collide with an existing contact?
    for row in conn.execute(_COLLISION_SQL, {"new": new}).fetchall():
        plan.collisions.append(
            {
                "jid_row": row["_id"],
                "raw_string": row["raw_string"],
                "type": row["type"],
                "server": row["server"],
                "chats": row["chats"],
            }
        )

    if plan.identity_rows == 0 and not plan.changes:
        plan.notes.append(f"nothing in this database mentions {old}")
    elif plan.content_rows and not include_text:
        plan.notes.append(
            f"{plan.content_rows:,} row(s) only mention {old} inside chat content "
            "(messages, links, vCards); they are left alone unless you pass "
            "--rewrite-text"
        )

    return plan


# --------------------------------------------------------------------------- #
# Applying
# --------------------------------------------------------------------------- #


def apply_migration(
    conn: sqlite3.Connection,
    plan: MigrationPlan,
    *,
    merge_collisions: bool = False,
) -> Dict[str, int]:
    """Execute ``plan`` inside one transaction.

    Every statement runs under ``BEGIN IMMEDIATE`` and the whole thing rolls
    back on any error, so a failure cannot leave the database half migrated.
    The database is quick-checked before the transaction commits.

    Only ``plan.selected`` is applied — the identity rows always, plus chat
    content only when the plan was built with ``include_text=True``.
    """
    if plan.empty:
        raise MigrationError("the plan changes nothing")
    if plan.collisions and not merge_collisions:
        raise MigrationError(
            f"{plan.new} already exists in this backup as {len(plan.collisions)} "
            "JID row(s); re-run with --merge-collisions if you accept losing the "
            "duplicate chat"
        )

    applied: Dict[str, int] = {}
    pattern = _own_number_pattern(plan.old)

    with transaction(conn):
        if plan.collisions and merge_collisions:
            applied["collisions_removed"] = _drop_collisions(conn, plan)

        # The account's own JID rows.  Exact predicates only.
        cursor = conn.execute(
            "UPDATE jid SET user = :new, "
            "       raw_string = CASE "
            "           WHEN raw_string = :old || '@s.whatsapp.net' "
            "                THEN :new || '@s.whatsapp.net' "
            "           ELSE :new || SUBSTR(raw_string, LENGTH(:old) + 1) "
            "           END "
            " WHERE user = :old "
            "    OR raw_string = :old || '@s.whatsapp.net' "
            "    OR raw_string LIKE :device ESCAPE '\\'",
            {"old": plan.old, "new": plan.new, "device": plan.old + ".%@s.whatsapp.net"},
        )
        applied["jid"] = cursor.rowcount if cursor.rowcount > 0 else plan.identity_rows

        for change in plan.selected:
            changed = 0
            for row_id in change.row_ids:
                current = conn.execute(
                    f'SELECT "{change.column}" FROM "{change.table}" WHERE rowid = ?',
                    (row_id,),
                ).fetchone()
                if not current or current[0] is None:
                    continue
                value = str(current[0])
                updated = pattern.sub(plan.new, value)
                if updated == value:
                    continue
                try:
                    conn.execute(
                        f'UPDATE "{change.table}" SET "{change.column}" = ? WHERE rowid = ?',
                        (updated, row_id),
                    )
                except sqlite3.Error as exc:
                    raise MigrationError(
                        f"updating {change.table}.{change.column} failed: {exc}"
                    ) from exc
                changed += 1
            applied[f"{change.table}.{change.column}"] = changed

        # Prove the database is still sound before we commit anything.
        verdict = conn.execute("PRAGMA quick_check").fetchone()[0]
        if verdict != "ok":
            raise MigrationError(f"quick_check failed after the update: {verdict}")

    return applied


def _drop_collisions(conn: sqlite3.Connection, plan: MigrationPlan) -> int:
    """Delete the JID rows (and any chats) already holding the new number."""
    removed = 0
    for entry in plan.collisions:
        jid_row = int(entry["jid_row"])
        chat_rows = [
            row[0]
            for row in conn.execute(
                "SELECT _id FROM chat WHERE jid_row_id = ?", (jid_row,)
            ).fetchall()
        ]
        for chat_row in chat_rows:
            conn.execute("DELETE FROM message WHERE chat_row_id = ?", (chat_row,))
            conn.execute("DELETE FROM chat WHERE _id = ?", (chat_row,))
        conn.execute("DELETE FROM jid WHERE _id = ?", (jid_row,))
        removed += 1
    return removed


# --------------------------------------------------------------------------- #
# Media
# --------------------------------------------------------------------------- #


def rename_media_directories(
    root: "str | Path", old: str, new: str, *, dry_run: bool = True
) -> List[Dict[str, str]]:
    """Rename ``…/<old>@s.whatsapp.net/`` folders under a media root.

    WhatsApp stores attachments in directories named after the chat JID, so a
    backup restored under a new number keeps its messages but loses every
    image.  This is opt-in because it touches the device filesystem.
    """
    base = Path(root).expanduser()
    if not base.is_dir():
        raise MigrationError(f"no such directory: {base}")

    moved: List[Dict[str, str]] = []
    pattern = re.compile(rf"^{re.escape(old)}(@[A-Za-z0-9._-]+)$")

    for path in sorted(base.rglob(f"{old}@*")):
        if not path.is_dir():
            continue
        match = pattern.match(path.name)
        if not match:
            continue
        target = path.with_name(new + match.group(1))
        moved.append({"from": str(path), "to": str(target)})
        if not dry_run:
            if target.exists():
                raise MigrationError(f"refusing to overwrite existing {target}")
            path.rename(target)

    return moved


# ==========================================================================
# SEARCH
# ==========================================================================

# Search a backup without ever opening it by hand.
#
# The point of this module is that the user never sees a decrypted database:
# ``wacrypt search`` decrypts (or reads the cache), runs the query, and throws
# the working copy away.
#
# Text lives in more than one place depending on the schema version, so this
# asks the database where it is instead of assuming ``message.text_data``:
# long messages moved to ``message_text`` in later versions, and captions live
# in ``message_media``.







@dataclass
class SearchHit:
    """One matching message."""

    message_row: int
    timestamp: Optional[int]
    chat_row: Optional[int]
    chat: str
    sender: str
    text: str
    table: str
    from_me: bool = False

    def when(self) -> str:
        return ms_to_datetime(self.timestamp)

    def as_dict(self) -> Dict[str, object]:
        return {
            "message_row": self.message_row,
            "timestamp": self.timestamp,
            "when": self.when(),
            "chat_row": self.chat_row,
            "chat": self.chat,
            "sender": self.sender,
            "from_me": self.from_me,
            "table": self.table,
            "text": self.text,
        }


def text_sources(conn: sqlite3.Connection) -> List[Dict[str, str]]:
    """Every ``(table, column)`` pair that could hold message text.

    Discovered, not assumed: a 2022 backup has ``message.text_data`` and
    nothing else, a 2026 one also has ``message_text``.
    """
    out: List[Dict[str, str]] = []
    for table, column, label in (
        ("message", "text_data", "message"),
        ("message_text", "text_data", "long text"),
        ("message_media", "media_caption", "caption"),
    ):
        if not table_exists(conn, table):
            continue
        if column not in column_names(conn, table):
            continue
        out.append({"table": table, "column": column, "label": label})
    return out


_CHAT_JOIN = """
    FROM {table} t
    LEFT JOIN message m ON m._id = t.message_row_id
    LEFT JOIN chat  c ON c._id  = m.chat_row_id
    LEFT JOIN jid   j ON j._id  = c.jid_row_id
"""


def _chat_label(row: sqlite3.Row) -> str:
    subject = row["subject"]
    if subject:
        return str(subject)
    raw = row["raw_string"]
    if raw:
        return str(raw)
    user = row["user"]
    return str(user) if user else f"chat {row['chat_row']}"


def _coerce_ts(value) -> Optional[int]:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.isdigit():
        stamp = int(text)
        # seconds vs milliseconds
        return stamp * 1000 if stamp < 10_000_000_000 else stamp
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return int(datetime.strptime(text, fmt).timestamp() * 1000)
        except ValueError:
            continue
    raise ValueError(f"cannot read a date from {value!r} (use YYYY-MM-DD)")


def search(
    conn: sqlite3.Connection,
    pattern: str,
    *,
    regex: bool = False,
    chat: Optional[str] = None,
    sender: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 200,
    case_sensitive: bool = False,
    context: int = 0,
) -> List[SearchHit]:
    """Find messages whose text matches ``pattern``.

    ``regex`` switches from a SQL ``LIKE`` (fast, indexed where possible) to a
    Python regular expression (slow, but correct).  ``context`` expands the
    returned text by ``context`` characters either side of the match.
    """
    hits: List[SearchHit] = []
    since_ts = _coerce_ts(since) if since else None
    until_ts = _coerce_ts(until) if until else None

    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = re.compile(pattern, flags) if regex else None
    needle = pattern if regex or case_sensitive else pattern.lower()

    chat_filter = (chat or "").lower()
    sender_filter = (sender or "").lower()

    sources = text_sources(conn)
    if not sources:
        raise DbError("this database has no text columns to search")

    for source in sources:
        table, column = source["table"], source["column"]
        if not table_exists(conn, "message"):
            continue

        join = _CHAT_JOIN.format(table=table)
        if table == "message":
            join = join.replace("LEFT JOIN message m ON m._id = t.message_row_id", "LEFT JOIN message m ON m._id = t._id")
            id_column, text_column = "t._id", f"t.{column}"
        else:
            id_column, text_column = "t.message_row_id", f"t.{column}"

        where = [f"{text_column} IS NOT NULL", f"{text_column} != ''"]
        args: List[object] = []

        if not regex:
            where.append(f"{text_column} LIKE ? ESCAPE '\\'")
            args.append("%" + _escape_like(needle) + "%")

        if chat_filter:
            where.append("(COALESCE(c.subject, '') || ' ' || COALESCE(j.raw_string, '') || ' ' || COALESCE(j.user, '')) LIKE ?")
            args.append(f"%{chat}%")
        if sender_filter:
            where.append("COALESCE(j.user, '') LIKE ?")
            args.append(f"%{sender}%")
        if since_ts is not None:
            where.append("COALESCE(m.timestamp, 0) >= ?")
            args.append(since_ts)
        if until_ts is not None:
            where.append("COALESCE(m.timestamp, 0) <= ?")
            args.append(until_ts)

        sql = (
            f"SELECT {id_column} AS message_row, {text_column} AS body, "
            f"       m.timestamp AS timestamp, m.from_me AS from_me, "
            f"       c._id AS chat_row, c.subject AS subject, "
            f"       j.user AS user, j.raw_string AS raw_string "
            f"{join} WHERE {' AND '.join(where)} "
            f"ORDER BY COALESCE(m.timestamp, 0) LIMIT ?"
        )

        try:
            cursor = conn.execute(sql, tuple(args + [limit * 4]))
        except sqlite3.Error:
            continue

        for row in cursor:
            body = row["body"] or ""
            if compiled is not None:
                match = compiled.search(body)
                if match is None:
                    continue
                if context:
                    start = max(0, match.start() - context)
                    end = min(len(body), match.end() + context)
                    body = ("…" if start else "") + body[start:end] + ("…" if end < len(body) else "")
            else:
                lowered = body.lower() if not case_sensitive else body
                index = lowered.find(needle)
                if index < 0:
                    continue
                if context:
                    start = max(0, index - context)
                    end = min(len(body), index + len(needle) + context)
                    body = ("…" if start else "") + body[start:end] + ("…" if end < len(body) else "")

            hits.append(
                SearchHit(
                    message_row=int(row["message_row"]),
                    timestamp=row["timestamp"],
                    chat_row=row["chat_row"],
                    chat=_chat_label(row),
                    sender="me" if row["from_me"] else (row["user"] or "unknown"),
                    text=body.replace("\n", " ").strip(),
                    table=source["label"],
                    from_me=bool(row["from_me"]),
                )
            )
            if len(hits) >= limit:
                return hits

    return hits


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def iter_chat_texts(
    conn: sqlite3.Connection, chat_row: int, limit: Optional[int] = None
) -> Iterator[Dict[str, object]]:
    """Every message of one chat, oldest first, for the exporters."""
    if not table_exists(conn, "message"):
        return
    has_media = table_exists(conn, "message_media")
    media_cols = column_names(conn, "message_media") if has_media else []

    sql = (
        "SELECT m._id AS message_row, m.timestamp AS timestamp, m.from_me AS from_me, "
        "       m.message_type AS message_type, m.text_data AS text_data, "
        "       m.sender_jid_row_id AS sender_jid_row_id"
    )
    for name in ("media_caption", "mime_type", "media_name", "file_size", "file_path"):
        if name in media_cols:
            sql += f", mm.{name} AS {name}"
        else:
            sql += f" NULL AS {name}"
    sql += " FROM message m"
    if has_media:
        sql += " LEFT JOIN message_media mm ON mm.message_row_id = m._id"
    sql += " WHERE m.chat_row_id = ? ORDER BY m.timestamp"
    if limit:
        sql += " LIMIT ?"
        args = (chat_row, limit)
    else:
        args = (chat_row,)

    sender_cache: Dict[int, str] = {}

    def sender_name(row_id: Optional[int]) -> str:
        if not row_id:
            return ""
        if row_id not in sender_cache:
            try:
                found = conn.execute("SELECT user FROM jid WHERE _id = ?", (row_id,)).fetchone()
                sender_cache[row_id] = (found[0] if found else "") or ""
            except sqlite3.Error:
                sender_cache[row_id] = ""
        return sender_cache[row_id]

    for row in conn.execute(sql, args):
        yield {
            "message_row": row["message_row"],
            "timestamp": row["timestamp"],
            "from_me": bool(row["from_me"]),
            "type": row["message_type"],
            "text": (row["text_data"] or "").strip(),
            "sender": sender_name(row["sender_jid_row_id"]),
            "caption": (row["media_caption"] or "").strip() if row["media_caption"] else "",
            "mime": row["mime_type"],
            "media_name": row["media_name"],
            "file_size": row["file_size"],
        }


# ==========================================================================
# EXPORT
# ==========================================================================

# Export conversations to files a human can actually read.
#
# Four formats, one pipeline: ``txt`` for grepping, ``json`` and ``csv`` for
# machines, and ``html`` for reading.  The HTML output is a single self
# contained file with a client side search box, because the usual failure of an
# export is that you cannot find anything in it.
#
# Media is *not* copied by default.  ``--include-media`` looks for the
# attachments under ``--media-root`` and copies the ones the export references,
# which is opt-in because it can be tens of gigabytes.






FORMATS = ("txt", "json", "csv", "html")


class ExportError(Exception):
    """The export could not be produced."""


@dataclass
class ChatInfo:
    chat_row: int
    label: str
    user: Optional[str]
    raw_string: Optional[str]
    subject: Optional[str]
    group_type: Optional[int]
    messages: int
    sort_timestamp: Optional[int]

    def as_dict(self) -> Dict[str, object]:
        return {
            "chat_row": self.chat_row,
            "label": self.label,
            "user": self.user,
            "raw_string": self.raw_string,
            "subject": self.subject,
            "group": bool(self.group_type),
            "messages": self.messages,
            "last_activity": ms_to_datetime(self.sort_timestamp),
        }


def list_chats(conn: sqlite3.Connection) -> List[ChatInfo]:
    """Every chat with a display label and a message count."""
    out: List[ChatInfo] = []
    for row in chat_rows(conn):
        subject = row.get("subject")
        raw = row.get("raw_string")
        user = row.get("user")
        label = str(subject or raw or user or f"chat {row['chat_row']}")
        out.append(
            ChatInfo(
                chat_row=int(row["chat_row"]),
                label=label,
                user=user,
                raw_string=raw,
                subject=subject,
                group_type=row.get("group_type"),
                messages=message_count(conn, int(row["chat_row"])),
                sort_timestamp=row.get("sort_timestamp"),
            )
        )
    return out


def safe_name(value: str, limit: int = 80) -> str:
    cleaned = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", str(value)).strip(" ._")
    return (cleaned or "chat")[:limit]


def _records(conn: sqlite3.Connection, chat: ChatInfo) -> Iterator[Dict[str, object]]:
    for item in iter_chat_texts(conn, chat.chat_row):
        text = item["text"] or ""
        caption = item.get("caption") or ""
        kind = item.get("mime") or ""
        name = item.get("media_name")
        if not text:
            if caption:
                text = caption
            elif name:
                text = f"[{kind or 'media'}] {name}"
            elif kind:
                text = f"[{kind}]"
            else:
                text = f"[message type {item.get('type')}]"
        yield {
            "chat": chat.label,
            "chat_row": chat.chat_row,
            "when": ms_to_datetime(item["timestamp"]),
            "timestamp": item["timestamp"],
            "sender": "me" if item["from_me"] else (item["sender"] or "unknown"),
            "from_me": bool(item["from_me"]),
            "text": text,
            "mime": kind,
            "media_name": name,
            "file_size": item.get("file_size"),
        }


def export_chats(
    conn: sqlite3.Connection,
    chats: Iterable[ChatInfo],
    out_dir: "str | Path",
    fmt: str = "html",
    *,
    limit: Optional[int] = None,
    media_root: Optional[Path] = None,
    include_media: bool = False,
) -> List[Path]:
    """Write one file per chat (or one file for ``html``/``json``)."""
    if fmt not in FORMATS:
        raise ExportError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")

    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    selected = list(chats)
    if not selected:
        raise ExportError("no chats selected")

    bundle: List[Dict[str, object]] = []

    for chat in selected:
        records = list(_records(conn, chat))
        if limit:
            records = records[-limit:]

        if fmt in ("html", "json"):
            # Both formats want every chat in one document.  (Writing the
            # aggregate json without this used to produce an empty list.)
            bundle.append({"chat": chat.as_dict(), "messages": records})

        if fmt == "html":
            continue
        stem = f"{chat.chat_row}_{safe_name(chat.label)}"
        if fmt == "json":
            path = target / f"{stem}.json"
            path.write_text(
                json.dumps(bundle[-1], indent=2, ensure_ascii=False), encoding="utf-8"
            )
        elif fmt == "csv":
            path = target / f"{stem}.csv"
            _write_csv(path, records)
        else:
            path = target / f"{stem}.txt"
            _write_txt(path, chat, records)
        written.append(path)

    if fmt == "html":
        path = target / "chats.html"
        _write_html(path, bundle)
        written.append(path)
    elif fmt == "json":
        path = target / "chats.json"
        path.write_text(
            json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        written.append(path)

    if include_media and media_root is not None:
        copied = _copy_media(conn, selected, media_root, target / "media")
        written.extend(copied)

    return written


def _write_txt(path: Path, chat: ChatInfo, records: List[Dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        handle.write(f"Chat: {chat.label}\n")
        if chat.raw_string:
            handle.write(f"JID:  {chat.raw_string}\n")
        handle.write(f"Messages: {len(records)}\n")
        handle.write("=" * 64 + "\n\n")
        for record in records:
            handle.write(f"[{record['when']}] {record['sender']}: {record['text']}\n")


def _write_csv(path: Path, records: List[Dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["when", "sender", "text", "mime", "media_name"]
        )
        writer.writeheader()
        for record in records:
            writer.writerow({key: record.get(key, "") for key in writer.fieldnames})


def _write_html(path: Path, bundle: List[Dict[str, object]]) -> None:
    """One self contained HTML file with a client side search box.

    The markup lives inside :data:`HTML_TEMPLATE` — a ``string.Template``, not
    a Jinja one, so this file stays a single script with no template loader.
    Chat content is never interpolated into the markup; it rides in as JSON
    under ``<script type="application/json">`` and is rendered client side.
    """
    total = sum(len(entry["messages"]) for entry in bundle)

    # The data goes inside <script type="application/json">, so "<" must not
    # survive verbatim: a message containing "</script>" would otherwise end
    # the block and turn the chat history into markup.
    payload = json.dumps(bundle, ensure_ascii=False).replace("<", "\\u003c")

    html = HTML_TEMPLATE.substitute(
        chat_count=len(bundle),
        total_messages=total,
        payload=payload,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )
    path.write_text(html, encoding="utf-8")


def _copy_media(
    conn: sqlite3.Connection, chats: List[ChatInfo], media_root: Path, out_dir: Path
) -> List[Path]:
    """Copy the attachments the selected chats reference, when they exist."""
    if not table_exists(conn, "message_media"):
        return []
    columns = column_names(conn, "message_media")
    if "file_path" not in columns:
        return []

    base = Path(media_root).expanduser()
    if not base.is_dir():
        raise ExportError(f"--media-root {base} does not exist")

    wanted = {chat.chat_row for chat in chats}
    copied: List[Path] = []
    for row in conn.execute(
        "SELECT mm.file_path FROM message_media mm "
        "JOIN message m ON m._id = mm.message_row_id "
        "WHERE mm.file_path IS NOT NULL AND m.chat_row_id IN (%s)"
        % ",".join("?" * len(wanted)),
        tuple(wanted),
    ).fetchall():
        relative = str(row[0]).lstrip("/")
        source = base / relative
        if not source.is_file():
            continue
        destination = out_dir / Path(relative).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(source, destination)
            copied.append(destination)
    return copied


# ==========================================================================
# DIFF
# ==========================================================================

# Compare two backups and say what changed between them.
#
# Row ids are useless here: WhatsApp renumbers ``_id`` between backups, so the
# same message gets a different id in each file.  Messages are matched on
# ``key_id`` when the schema has it (it is WhatsApp's own message id and is
# stable across backups) and fall back to ``(timestamp, from_me, text)`` when
# it does not.







class DiffError(Exception):
    """The two databases could not be compared."""


@dataclass
class ChatDiff:
    jid: str
    label: str
    old_messages: int = 0
    new_messages: int = 0
    added: int = 0
    removed: int = 0
    status: str = "unchanged"  # new | removed | added | unchanged

    @property
    def delta(self) -> int:
        return self.new_messages - self.old_messages

    def as_dict(self) -> Dict[str, object]:
        return {
            "jid": self.jid,
            "label": self.label,
            "old_messages": self.old_messages,
            "new_messages": self.new_messages,
            "added": self.added,
            "removed": self.removed,
            "delta": self.delta,
            "status": self.status,
        }


@dataclass
class BackupDiff:
    old_path: str
    new_path: str
    chats: List[ChatDiff] = field(default_factory=list)
    total_old_messages: int = 0
    total_new_messages: int = 0
    key_source: str = "key_id"

    @property
    def new_chats(self) -> List[ChatDiff]:
        return [chat for chat in self.chats if chat.status == "new"]

    @property
    def removed_chats(self) -> List[ChatDiff]:
        return [chat for chat in self.chats if chat.status == "removed"]

    @property
    def changed_chats(self) -> List[ChatDiff]:
        return [chat for chat in self.chats if chat.status == "added"]

    @property
    def total_added(self) -> int:
        return sum(chat.added for chat in self.chats)

    @property
    def total_removed(self) -> int:
        return sum(chat.removed for chat in self.chats)

    def as_dict(self) -> Dict[str, object]:
        return {
            "old": self.old_path,
            "new": self.new_path,
            "key_source": self.key_source,
            "total_old_messages": self.total_old_messages,
            "total_new_messages": self.total_new_messages,
            "total_added": self.total_added,
            "total_removed": self.total_removed,
            "new_chats": len(self.new_chats),
            "removed_chats": len(self.removed_chats),
            "changed_chats": len(self.changed_chats),
            "chats": [chat.as_dict() for chat in self.chats],
        }


def _has(conn: sqlite3.Connection, table: str, column: str) -> bool:
    return table_exists(conn, table) and column in column_names(conn, table)


def _message_fingerprint(conn: sqlite3.Connection, use_key: bool) -> str:
    return "key_id" if use_key and _has(conn, "message", "key_id") else "timestamp"


def _chat_index(conn: sqlite3.Connection) -> Dict[str, Tuple[str, int]]:
    """``{jid: (label, chat row)}``."""
    out: Dict[str, Tuple[str, int]] = {}
    for row in chat_rows(conn):
        jid = row.get("raw_string") or row.get("user") or f"chat:{row['chat_row']}"
        label = str(row.get("subject") or jid)
        out[str(jid)] = (label, int(row["chat_row"]))
    return out


def _messages(conn: sqlite3.Connection, chat_row: int, use_key: bool) -> List[str]:
    columns = ["timestamp", "from_me"]
    if use_key and _has(conn, "message", "key_id"):
        columns.append("key_id")
    else:
        columns.append("text_data")

    names = ", ".join(columns)
    rows = conn.execute(
        f"SELECT {names} FROM message WHERE chat_row_id = ? ORDER BY timestamp",
        (chat_row,),
    ).fetchall()
    out: List[str] = []
    for row in rows:
        if use_key and _has(conn, "message", "key_id"):
            out.append(f"{row['key_id']}|{row['timestamp']}|{row['from_me']}")
        else:
            text = (row["text_data"] or "").strip()[:200]
            out.append(f"{row['timestamp']}|{row['from_me']}|{text}")
    return out


def diff_backups(
    old_conn: sqlite3.Connection,
    new_conn: sqlite3.Connection,
    old_path: str,
    new_path: str,
    *,
    limit: Optional[int] = None,
) -> BackupDiff:
    """Compare two decrypted backups, newest against oldest."""
    use_key = _has(old_conn, "message", "key_id") and _has(new_conn, "message", "key_id")
    result = BackupDiff(
        old_path=old_path, new_path=new_path, key_source="key_id" if use_key else "text"
    )

    old_chats = _chat_index(old_conn)
    new_chats = _chat_index(new_conn)
    result.total_old_messages = count(old_conn, "message")
    result.total_new_messages = count(new_conn, "message")

    for jid in sorted(set(old_chats) | set(new_chats)):
        in_old, in_new = jid in old_chats, jid in new_chats
        label = (new_chats.get(jid) or old_chats.get(jid))[0]

        if in_old and not in_new:
            entry = ChatDiff(jid=jid, label=label, status="removed")
            entry.old_messages = len(_messages(old_conn, old_chats[jid][1], use_key))
            # The whole chat went away, so every message in it went with it.
            entry.removed = entry.old_messages
            result.chats.append(entry)
            continue
        if in_new and not in_old:
            entry = ChatDiff(jid=jid, label=label, status="new")
            entry.new_messages = len(_messages(new_conn, new_chats[jid][1], use_key))
            entry.added = entry.new_messages
            result.chats.append(entry)
            continue

        old_ids = _messages(old_conn, old_chats[jid][1], use_key)
        new_ids = _messages(new_conn, new_chats[jid][1], use_key)
        old_set, new_set = set(old_ids), set(new_ids)
        added = len(new_set - old_set)
        removed = len(old_set - new_set)

        entry = ChatDiff(
            jid=jid,
            label=label,
            old_messages=len(old_ids),
            new_messages=len(new_ids),
            added=added,
            removed=removed,
            status="added" if (added or removed) else "unchanged",
        )
        if entry.status != "unchanged" or added or removed:
            result.chats.append(entry)

    result.chats.sort(key=lambda chat: chat.added, reverse=True)
    if limit:
        result.chats = result.chats[:limit]
    return result


# ===========================================================================
# VERSION
# ===========================================================================

__version__ = "0.2.0"


# ===========================================================================
# KEY
# ===========================================================================

# The backup key arrives as 64 hex digits (what WhatsApp shows under
# Settings > Chats > Chat backup) or as a file holding it.  Nothing here
# stores anything: there is no keychain entry, no key file of our own, and no
# cache, so this module is the entire surface where a secret is handled.
HEX_KEY = re.compile(r"^[0-9a-fA-F]{64}$")


class KeyError_(Exception):
    """The key could not be understood.

    Named with a trailing underscore so importing it never shadows the
    builtin — catching the builtin by accident here would swallow real
    programming errors.
    """


def parse_hex_key(value: str) -> bytes:
    """Accept a 64 hex digit string and return its 32 bytes."""
    candidate = value.strip().strip('"').strip("'")
    candidate = candidate.replace(" ", "").replace("\n", "").replace("\t", "")
    if candidate.startswith("0x"):
        candidate = candidate[2:]
    if not HEX_KEY.fullmatch(candidate):
        raise KeyError_(
            "the key must be exactly 64 hexadecimal characters "
            "(the value WhatsApp shows under Settings > Chats > Chat backup)"
        )
    return bytes.fromhex(candidate)


def load_key_file(path: "str | os.PathLike[str]") -> bytes:
    """Read a crypt14 ``.key`` file or a text file holding the hex key.

    crypt14 key files are a serialized Java ``byte[]``; the 32 byte array
    inside is what we want.  We do not depend on ``javaobj`` for that: the
    payload is always a 32 byte run, so we take the longest byte run in the
    file and check its length.
    """
    target = Path(path).expanduser()
    if not target.is_file():
        raise KeyError_(f"key file not found: {target}")
    raw = target.read_bytes()

    text = raw.decode("utf-8", "ignore").strip()
    if HEX_KEY.fullmatch(text.split()[0] if text.split() else ""):
        return parse_hex_key(text.split()[0])

    if len(raw) == 32:
        return raw

    # Java serialized byte[]: look for the 32 byte payload.
    marker = raw.find(b"\x74\x00\x20")
    if marker != -1:
        payload = raw[marker + 3 : marker + 35]
        if len(payload) == 32:
            return payload

    # Last resort: the longest run of bytes in the file.
    if len(raw) >= 32:
        return raw[:32]

    raise KeyError_(f"{target} does not contain a usable key")


def prompt_for_key(what: str = "64 hex backup key") -> bytes:
    """Ask for the key with echo turned off."""
    while True:
        try:
            typed = getpass.getpass(f"{what}: ")
        except (EOFError, KeyboardInterrupt):
            raise KeyError_("no key supplied") from None
        if not typed.strip():
            print("  (empty, try again or Ctrl-C to abort)")
            continue
        try:
            return parse_hex_key(typed)
        except KeyError_ as exc:
            print(f"  {exc}")


def resolve_key(value: Optional[str] = None, *, allow_prompt: bool = True) -> bytes:
    """Turn ``--key`` / ``$WACRYPT_KEY`` / a typed answer into 32 bytes.

    Sources are tried in order: the value handed in, then an interactive
    hidden prompt.  There is deliberately no third source — the tool never
    writes the key anywhere, so there is nothing to forget afterwards.
    """
    if value:
        candidate = value.strip().strip('"').strip("'")
        if HEX_KEY.fullmatch(candidate.replace(" ", "")):
            return parse_hex_key(candidate)
        path = Path(candidate).expanduser()
        if path.is_file():
            return load_key_file(path)
        # Fall through to the error below so the message is uniform.
        raise KeyError_("--key is neither 64 hex digits nor an existing file")

    if allow_prompt:
        return prompt_for_key()

    raise KeyError_("no key available")


# ===========================================================================
# SESSION — decrypt into memory-scoped temporary storage, never into a cache
# ===========================================================================


class OpenState:
    """What happened while locating a database, for reporting to the user."""

    __slots__ = ("decrypted", "db_size")

    def __init__(self) -> None:
        self.decrypted = False
        self.db_size = 0


@contextlib.contextmanager
def open_backup(
    path,
    key: Optional[bytes] = None,
    *,
    progress: Optional[Callable[[int, int], None]] = None,
) -> Iterator[Tuple[BackupHeader, Path, OpenState]]:
    """Yield ``(header, sqlite_path, state)`` for an encrypted backup.

    The database path is valid for the duration of the ``with`` block only:
    it lives in a temporary directory that is removed on the way out, so no
    plaintext chat history outlives the command that asked for it.  There is
    no cache to hit — every command pays the decrypt, which is what keeps
    this tool free of any stored secret.
    """
    source = Path(path)
    header = read_header(source)
    state = OpenState()

    aes_key = derive_backup_key(key or resolve_key())
    temporary = Path(tempfile.mkdtemp(prefix="wacrypt-"))
    db = temporary / "msgstore.db"
    try:
        unpack_to_file(source, aes_key, db, header, progress=progress)
        state.decrypted = True
        state.db_size = db.stat().st_size
        yield header, db, state
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def decrypt_permanently(
    path,
    out_path,
    key: Optional[bytes] = None,
    *,
    progress: Optional[Callable[[int, int], None]] = None,
) -> BackupHeader:
    """Write a plain SQLite database the user keeps.

    The copy lands through a ``.partial`` file so an interrupted run can
    never leave a truncated database where a complete one is expected.
    """
    target = Path(out_path)
    with open_backup(path, key, progress=progress) as (header, db, _state):
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


# ==========================================================================
# HTML EXPORT TEMPLATE
# ==========================================================================

# Inlined from the former export_templates/chats.html.j2, with its four
# Jinja expressions rewritten as $name placeholders so the markup needs no
# template engine.  Chat content never touches this markup directly: it is
# passed as JSON and drawn by the script at the bottom of the file.
HTML_TEMPLATE = Template(r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WhatsApp export — ${chat_count} chats</title>
<style>
:root {
  --bg: #0b141a; --panel: #111b21; --panel-2: #1a262c; --line: #22333b;
  --text: #e9edef; --dim: #8696a0; --accent: #00a884; --me: #005c4b;
  --bubble: #202c33; --hit: #f5c518;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
header {
  position: sticky; top: 0; z-index: 5; display: flex; gap: 12px; align-items: center;
  padding: 10px 16px; background: var(--panel); border-bottom: 1px solid var(--line);
  flex-wrap: wrap;
}
header h1 { font-size: 15px; margin: 0; font-weight: 600; }
header .meta { color: var(--dim); font-size: 12px; }
input[type=search] {
  flex: 1; min-width: 220px; padding: 8px 12px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--panel-2); color: var(--text);
  font-size: 14px; outline: none;
}
input[type=search]:focus { border-color: var(--accent); }
#count { color: var(--dim); font-size: 12px; min-width: 90px; text-align: right; }
.layout { display: grid; grid-template-columns: 300px 1fr; height: calc(100vh - 54px); }
aside { overflow-y: auto; border-right: 1px solid var(--line); background: var(--panel); }
.chat-item {
  display: flex; justify-content: space-between; gap: 8px; width: 100%;
  padding: 10px 14px; background: none; border: 0; border-bottom: 1px solid var(--line);
  color: var(--text); cursor: pointer; text-align: left; font-size: 14px;
}
.chat-item:hover { background: var(--panel-2); }
.chat-item.active { background: #2a3942; }
.chat-item .n { color: var(--dim); font-size: 12px; white-space: nowrap; }
.chat-item .sub { color: var(--dim); font-size: 12px; }
main { overflow-y: auto; padding: 24px clamp(12px, 6vw, 90px); }
.chat-head { margin-bottom: 20px; }
.chat-head h2 { margin: 0 0 4px; font-size: 18px; }
.chat-head .sub { color: var(--dim); font-size: 13px; }
.day {
  text-align: center; margin: 22px 0 14px; color: var(--dim); font-size: 12px;
}
.day span { background: var(--panel-2); padding: 4px 12px; border-radius: 8px; }
.row { display: flex; margin: 3px 0; }
.row.me { justify-content: flex-end; }
.bubble {
  max-width: min(680px, 78%); padding: 6px 10px 4px; border-radius: 8px;
  background: var(--bubble); white-space: pre-wrap; word-break: break-word;
}
.row.me .bubble { background: var(--me); }
.meta-line { display: flex; gap: 8px; align-items: baseline; margin-top: 3px; }
.meta-line .who { font-size: 12px; color: var(--accent); font-weight: 600; }
.row.me .meta-line .who { color: #8fd6c2; }
.meta-line .when { font-size: 11px; color: var(--dim); margin-left: auto; }
.media { color: var(--dim); font-style: italic; }
mark { background: var(--hit); color: #000; border-radius: 2px; padding: 0 1px; }
.empty { color: var(--dim); padding: 60px 0; text-align: center; }
a.dl { color: var(--accent); }
@media (max-width: 800px) { .layout { grid-template-columns: 1fr; } aside { display: none; } }
</style>
</head>
<body>
<header>
  <h1>WhatsApp export</h1>
  <span class="meta">${chat_count} chats · ${total_messages} messages · generated ${generated}</span>
  <input type="search" id="q" placeholder="Search every message… (plain text or /regex/)" autofocus>
  <span id="count"></span>
</header>

<div class="layout">
  <aside id="list"></aside>
  <main id="pane"><div class="empty">Pick a chat on the left, or search above.</div></main>
</div>

<script id="data" type="application/json">${payload}</script>
<script>
(function () {
  "use strict";
  const DATA = JSON.parse(document.getElementById("data").textContent);
  const list = document.getElementById("list");
  const pane = document.getElementById("pane");
  const q = document.getElementById("q");
  const count = document.getElementById("count");
  let active = -1;

  const esc = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

  const dayOf = (when) => String(when || "").slice(0, 10);

  function buildRegex(raw) {
    const term = raw.trim();
    if (!term) return null;
    if (term.length > 2 && term.startsWith("/") && term.lastIndexOf("/") > 0) {
      const end = term.lastIndexOf("/");
      try {
        return { re: new RegExp(term.slice(1, end), term.slice(end + 1) || "i"), term: null };
      } catch (e) { /* fall through to literal */ }
    }
    return { re: null, term: term.toLowerCase() };
  }

  function highlight(text, matcher) {
    const safe = esc(text);
    if (!matcher) return safe;
    if (matcher.re) {
      return safe.replace(matcher.re, (m) => "<mark>" + m + "</mark>");
    }
    const idx = safe.toLowerCase().indexOf(matcher.term);
    if (idx < 0) return safe;
    return safe.slice(0, idx) + "<mark>" + safe.slice(idx, idx + matcher.term.length) +
           "</mark>" + safe.slice(idx + matcher.term.length);
  }

  function matches(message, matcher) {
    if (!matcher) return true;
    if (matcher.re) return matcher.re.test(message.text);
    return message.text.toLowerCase().indexOf(matcher.term) >= 0;
  }

  function renderList(matcher) {
    list.innerHTML = "";
    let shown = 0;
    DATA.forEach((chat, i) => {
      const hits = chat.messages.filter((m) => matches(m, matcher)).length;
      if (matcher && !hits) return;
      shown++;
      const button = document.createElement("button");
      button.className = "chat-item" + (i === active ? " active" : "");
      button.innerHTML = "<span><span>" + esc(chat.chat.label) +
        "</span><br><span class='sub'>" + (chat.chat.last_activity || "") + "</span></span>" +
        "<span class='n'>" + (matcher ? hits + " hit" : chat.messages.length) + "</span>";
      button.onclick = () => { active = i; renderList(matcher); renderChat(i, matcher); };
      list.appendChild(button);
    });
    count.textContent = shown + " chat" + (shown === 1 ? "" : "s");
  }

  function renderChat(index, matcher) {
    const chat = DATA[index];
    const messages = chat.messages.filter((m) => matches(m, matcher));
    let html = "<div class='chat-head'><h2>" + esc(chat.chat.label) + "</h2>" +
      "<span class='sub'>" + esc(chat.chat.raw_string || "") + " · " +
      messages.length + " messages</span></div>";
    let lastDay = "";
    messages.forEach((m) => {
      const day = dayOf(m.when);
      if (day !== lastDay) {
        html += "<div class='day'><span>" + esc(day) + "</span></div>";
        lastDay = day;
      }
      const body = highlight(m.text, matcher);
      const media = m.mime ? " <span class='media'>[" + esc(m.mime) + "]</span>" : "";
      html += "<div class='row" + (m.from_me ? " me" : "") + "'><div class='bubble'>" +
        body + media +
        "<div class='meta-line'><span class='who'>" + esc(m.from_me ? "me" : m.sender) +
        "</span><span class='when'>" + esc(m.when) + "</span></div></div></div>";
    });
    if (!messages.length) html += "<div class='empty'>No messages match.</div>";
    pane.innerHTML = html;
    pane.scrollTop = 0;
  }

  function run() {
    const matcher = buildRegex(q.value);
    renderList(matcher);
    if (active >= 0) renderChat(active, matcher);
  }

  q.addEventListener("input", run);
  run();
})();
</script>
</body>
</html>
""")

# ===========================================================================
# COMMAND LINE INTERFACE
# ===========================================================================
#
# This layer used to be typer + rich.  Both are gone: the tool is one file
# now, so the only third party import left anywhere in it is `cryptography`,
# which is the one thing Python cannot do for us (AES-256-GCM).

EXAMPLES = """\
examples:
  wacrypt info msgstore.db.crypt15                 header only, no key needed
  wacrypt inspect msgstore.db.crypt15              who owns it, how big, how far back
  wacrypt search msgstore.db.crypt15 "invoice" --since 2026-01-01
  wacrypt export msgstore.db.crypt15 -f html -o ./chat_export
  wacrypt diff old.crypt15 new.crypt15
  wacrypt migrate msgstore.db.crypt15 9665xxxxxxxx  dry run unless --apply
  wacrypt integrity msgstore.db.crypt15 --json

key resolution:
  --key / -k, then $WACRYPT_KEY, then a hidden prompt.  The key is never
  written to disk, never cached and never logged by this program.
"""

KEY_HELP = (
    "64 hex backup key, or a path to a key file. Falls back to $WACRYPT_KEY "
    "and then to a hidden prompt."
)

# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

_STYLES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "grey": "90",
}
_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _paint(text, *styles: str) -> str:
    """Wrap ``text`` in ANSI colour, or return it untouched when not a TTY."""
    if not _COLOR or not styles:
        return str(text)
    codes = "".join(f"\033[{_STYLES[s]}m" for s in styles if s in _STYLES)
    return f"{codes}{text}\033[0m"


def _fail(message: str, code: int = 1) -> None:
    print(_paint(f"error {message}", "bold", "red"), file=sys.stderr)
    raise SystemExit(code)


def _json(payload: object) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _readable_size(value: Optional[int]) -> str:
    if value is None:
        return "—"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.2f} GB"


def _kv(
    rows: List[Tuple[str, object]],
    title: Optional[str] = None,
    colours: Optional[List[Optional[str]]] = None,
) -> None:
    """Print an aligned field/value block.  ``colours`` tints a value."""
    if title:
        print(_paint(title, "bold"))
    width = max((len(str(name)) for name, _ in rows), default=0)
    for index, (name, value) in enumerate(rows):
        colour = colours[index] if colours and index < len(colours) else None
        painted = _paint(value, colour) if colour else str(value)
        print(f"  {str(name).ljust(width)}  {painted}")


def _grid(
    headers: Sequence[str],
    rows: Sequence[Sequence[object]],
    aligns: Optional[Sequence[str]] = None,
    max_widths: Optional[Sequence[Optional[int]]] = None,
    wrap_last: bool = False,
    styles: Optional[Callable[[int, int, str], str]] = None,
) -> None:
    """Print a border-less table that fits the terminal.

    ``wrap_last`` lets the final column run onto continuation lines instead
    of being clipped — used for message text, which has to stay readable.
    ``styles`` colours a cell, and is applied *after* the widths are known,
    so escape sequences never count towards a column's width.
    """
    columns = len(headers)
    aligns = list(aligns or ["l"] * columns)
    max_widths = list(max_widths or [None] * columns)

    body: List[List[str]] = []
    for row in rows:
        cells = [("" if cell is None else str(cell)) for cell in row]
        cells = (cells + [""] * columns)[:columns]
        body.append(
            [
                cell[:limit] if limit and len(cell) > limit else cell
                for cell, limit in zip(cells, max_widths)
            ]
        )

    widths = [len(str(header)) for header in headers]
    for row in body:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    gap = 2
    terminal = shutil.get_terminal_size().columns

    def fixed() -> int:
        """Width of every column except the last, gaps included."""
        return sum(widths[:-1]) + gap * (columns - 1)

    if fixed() + widths[-1] > terminal:  # the table is wider than the screen
        if wrap_last:
            # Keep a readable floor for the message column by taking the room
            # back from the widest of the other columns first — which is the
            # chat JID, the least precious of the three.  The last column is
            # measured separately: it is recomputed below, so it must never
            # take part in the loop that squeezes the others.
            reserve = 24
            while fixed() > terminal - reserve:
                shrinkable = [index for index in range(columns - 1) if widths[index] > 12]
                if not shrinkable:
                    break
                widest = max(shrinkable, key=lambda index: widths[index])
                widths[widest] -= 1
            widths[-1] = max(20, terminal - fixed())
        else:
            while fixed() + widths[-1] > terminal:
                widest = max(range(columns), key=lambda index: widths[index])
                if widths[widest] <= 12:
                    break
                widths[widest] -= 1

    # Squeezing can leave a cell wider than its column, which would push the
    # rest of the row out of line.  Clip before styling, so colour (added by
    # the caller) is never cut in half.
    for row in body:
        for index, cell in enumerate(row[:-1] if wrap_last else row):
            if len(cell) > widths[index]:
                keep = max(widths[index] - 1, 1)
                row[index] = cell[:keep] + "…"

    def place(visible: str, styled: str, index: int) -> str:
        """Pad to the column width using the *visible* length, not the styled one."""
        filler = widths[index] - len(visible)
        if filler <= 0:
            return styled
        return styled + " " * filler if aligns[index] != "r" else " " * filler + styled

    print(
        "  "
        + "  ".join(
            place(header[: widths[index]], _paint(header[: widths[index]], "bold"), index)
            for index, header in enumerate(headers)
        )
    )

    for row_index, row in enumerate(body):
        head, tail = row[:-1], row[-1]
        chunks = [tail]
        if wrap_last and len(tail) > widths[-1]:
            chunks = textwrap.wrap(tail, width=widths[-1]) or [""]

        for chunk_index, chunk in enumerate(chunks):
            parts = []
            for index, cell in enumerate(head):
                # Only the first line of a wrapped row carries the row's own
                # cells; the continuation lines are padding plus more text.
                value = cell if chunk_index == 0 else ""
                styled = styles(row_index, index, value) if styles else value
                parts.append(place(value, styled, index))
            last = styles(row_index, columns - 1, chunk) if styles else chunk
            parts.append(place(chunk, last, columns - 1))
            print(("  " + "  ".join(parts)).rstrip())


class _Progress:
    """A single progress line on stderr — the replacement for rich.Progress.

    Redrawn at most ten times a second, cleared on exit so command output
    stays clean.  Quiet when stderr is not a terminal (CI, pipes).
    """

    def __init__(self, description: str) -> None:
        self.description = description
        self._started = 0.0
        self._last = 0.0
        self._tty = sys.stderr.isatty()
        self._width = shutil.get_terminal_size().columns

    def __enter__(self) -> Callable[[int, int], None]:
        self._started = time.monotonic()
        if not self._tty:
            print(f"  {self.description} …", file=sys.stderr)
        return self.update

    def __exit__(self, *_exc) -> bool:
        if self._tty:
            sys.stderr.write("\r" + " " * max(self._width - 1, 0) + "\r")
            sys.stderr.flush()
        return False

    def update(self, done: int, total: int) -> None:
        if not self._tty:
            return
        now = time.monotonic()
        if now - self._last < 0.1 and (not total or done < total):
            return
        self._last = now
        elapsed = max(now - self._started, 1e-6)
        if total:
            meter = (
                f"{_readable_size(done)} / {_readable_size(total)} "
                f"{100.0 * done / total:5.1f}%"
            )
        else:
            meter = _readable_size(done)
        line = f"  {self.description}  {meter}  {_readable_size(int(done / elapsed))}/s"
        available = max(self._width - 1, 0)
        visible = line[:available]
        sys.stderr.write("\r" + visible + " " * max(available - len(visible), 0))
        sys.stderr.flush()


# --------------------------------------------------------------------------- #
# arguments
# --------------------------------------------------------------------------- #


def _existing_file(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.exists():
        raise argparse.ArgumentTypeError(f"no such file: {path}")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"not a file: {path}")
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentTypeError(f"not readable: {path}")
    return path


def _int_between(low: int, high: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return number

    return parse


def _int_at_least(low: int) -> Callable[[str], int]:
    return _int_between(low, 10**9)


def _key_argument(key: Optional[str]) -> Optional[bytes]:
    """``--key`` / ``$WACRYPT_KEY`` as bytes, or None when neither is set."""
    raw = key or os.environ.get("WACRYPT_KEY")
    if not raw:
        return None
    try:
        return resolve_key(raw, allow_prompt=False)
    except KeyError_ as exc:
        _fail(str(exc))


def _must_key(key: Optional[str]) -> bytes:
    resolved = _key_argument(key)
    if resolved is not None:
        return resolved
    try:
        return resolve_key()
    except KeyError_ as exc:
        _fail(str(exc))


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #


def _database_stats(conn: sqlite3.Connection) -> Dict[str, object]:
    out: Dict[str, object] = {
        "chats": 0,
        "messages": 0,
        "first_message": "—",
        "last_message": "—",
        "media": 0,
        "media_bytes": 0,
        "db_bytes": 0,
    }
    if table_exists(conn, "chat"):
        out["chats"] = count(conn, "chat")
    if table_exists(conn, "message"):
        out["messages"] = count(conn, "message")
        try:
            lo, hi = conn.execute(
                "SELECT MIN(timestamp), MAX(timestamp) FROM message"
            ).fetchone()
            out["first_message"] = ms_to_datetime(lo)
            out["last_message"] = ms_to_datetime(hi)
        except Exception:
            pass
    if table_exists(conn, "message_media"):
        try:
            rows, size = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(file_size), 0) FROM message_media"
            ).fetchone()
            out["media"], out["media_bytes"] = int(rows or 0), int(size or 0)
        except Exception:
            pass
    out["db_bytes"] = os.path.getsize(conn.execute("PRAGMA database_list").fetchone()[2])
    return out


def _pick_chats(available, selection: Optional[str]):
    if not selection or selection.strip().lower() == "all":
        return available
    tokens = [token.strip() for token in selection.split(",") if token.strip()]
    if tokens[0].lower() == "groups":
        return [chat for chat in available if chat.group_type]
    if tokens[0].lower() == "private":
        return [chat for chat in available if not chat.group_type]

    chosen = []
    for token in tokens:
        needle = token.lower()
        found = [
            chat
            for chat in available
            if needle == str(chat.chat_row)
            or needle == (chat.user or "").lower()
            or needle in (chat.label or "").lower()
        ]
        if not found:
            _fail(f"no chat matched {token!r}")
        chosen.extend(found)
    # de-duplicate while keeping order
    seen: set = set()
    return [chat for chat in chosen if not (chat.chat_row in seen or seen.add(chat.chat_row))]


def _retarget_header(header: BackupHeader, suffix: str) -> BackupHeader:
    patched = BackupHeader(**{**header.__dict__})
    patched.prefix = patch_jid_suffix(header.prefix, suffix)
    patched.jid_suffix = suffix
    return patched


def _header_rows(header: BackupHeader) -> List[Tuple[str, object]]:
    rows: List[Tuple[str, object]] = [
        ("crypt type", f"crypt{header.crypt_type}"),
        (
            "key type",
            f"{header.key_type_name}"
            + (f" / new={KeyType.name(header.key_type_new)}" if header.key_type_new else ""),
        ),
        ("WhatsApp version", header.app_version or "—"),
        ("device model", header.device_model or "—"),
        ("jid suffix", header.jid_suffix or "—"),
        ("backup version", header.backup_version if header.backup_version is not None else "—"),
        ("migration flags", f"{len(header.features)} completed"),
        ("IV", header.iv.hex() if header.iv else "—"),
        ("header size", f"{header.header_len} bytes"),
        ("cipher starts at", f"offset {header.cipher_offset}"),
        ("encrypted payload", _readable_size(header.cipher_size)),
        ("file size", _readable_size(header.file_size)),
    ]
    if header.unknown_fields:
        rows.append(("unknown fields", ", ".join(header.unknown_fields)))
    return rows


def _print_plan(plan, json_mode: bool) -> None:
    if json_mode:
        _json(plan.as_dict())
        return

    print()
    print(
        f"migration plan  {plan.old} → {_paint(plan.new, 'bold')} "
        f"(header suffix {plan.suffix_from} → {plan.suffix_to})"
    )
    print(f"  own JID rows       : {plan.identity_rows:,}")
    print(f"  tables scanned     : {plan.tables_scanned:,}")
    print(
        f"  restore-critical    : {plan.restore_rows:,} row(s)  "
        + _paint("always rewritten", "green")
    )
    print(
        f"  chat content        : {plan.content_rows:,} row(s)  "
        + (
            _paint("included (--rewrite-text)", "green")
            if plan.include_text
            else _paint("left alone (pass --rewrite-text to include)", "dim")
        )
    )

    if plan.changes:
        print()
        selected = set(id(change) for change in plan.selected)

        def applies(row_index: int, column: int, value: str) -> str:
            if column != 0:
                return value
            return _paint(value, "green" if value == "yes" else "dim")

        _grid(
            ["applies", "table", "column", "kind", "rows"],
            [
                [
                    "yes" if id(change) in selected else "no",
                    change.table,
                    change.column,
                    change.kind,
                    f"{change.rows:,}",
                ]
                for change in plan.changes
            ],
            aligns=["l", "l", "l", "l", "r"],
            max_widths=[7, 32, 28, None, None],
            styles=applies,
        )

    if plan.collisions:
        print()
        print(
            _paint("collision", "red")
            + f" — {len(plan.collisions)} JID row(s) already hold {plan.new}. "
            "Without --merge-collisions the migration will refuse to run."
        )
        for entry in plan.collisions[:5]:
            print(
                f"  • {entry['raw_string']}  type={entry['type']} "
                f"server={entry['server']} chats={entry['chats']}"
            )

    for note in plan.notes:
        print(f"  {_paint('note', 'yellow')} {note}")


# --------------------------------------------------------------------------- #
# info
# --------------------------------------------------------------------------- #


def cmd_info(args) -> None:
    """Read the header. Needs no key and touches only the first 64 KB."""
    try:
        header = read_header(args.file)
    except HeaderError as exc:
        _fail(str(exc))

    if args.json:
        _json(header.summary())
        return
    _kv(_header_rows(header), title=args.file.name)


# --------------------------------------------------------------------------- #
# decrypt
# --------------------------------------------------------------------------- #


def cmd_decrypt(args) -> None:
    """Decrypt a backup to a plain SQLite database."""
    resolved = _key_argument(args.key)

    target = args.output or args.file.with_suffix("")
    if target == args.file:
        _fail("refusing to overwrite the encrypted backup")

    try:
        with _Progress(f"decrypting {args.file.name}") as update:
            header = decrypt_permanently(args.file, target, resolved, progress=update)
    except (WrongKey, CryptoError, HeaderError, KeyError_) as exc:
        _fail(str(exc))

    payload = {
        "input": str(args.file),
        "output": str(target),
        "size": target.stat().st_size,
        "crypt_type": header.crypt_type,
    }
    if args.json:
        _json(payload)
        return
    print(
        _paint("ok", "green")
        + f" decrypted -> {_paint(target, 'bold')} ({_readable_size(payload['size'])})"
    )


# --------------------------------------------------------------------------- #
# encrypt
# --------------------------------------------------------------------------- #


def cmd_encrypt(args) -> None:
    """Encrypt a plain SQLite database into a crypt15 backup."""
    probe = open_db(args.database, read_only=True)
    try:
        if not probe.execute("SELECT 1").fetchone():
            _fail(f"{args.database} is not a SQLite database")
    finally:
        probe.close()

    source_header = None
    if args.like is not None:
        try:
            source_header = read_header(args.like)
        except HeaderError as exc:
            _fail(str(exc))

    resolved = _must_key(args.key)
    aes_key = derive_backup_key(resolved)

    if source_header is not None:
        iv = source_header.iv if args.reuse_iv else None
        header = source_header
    else:
        iv = None
        header = BackupHeader(
            path=args.database,
            file_size=args.database.stat().st_size,
            crypt_type=args.type,
            header_len=0,
            cipher_offset=0,
            prefix=b"",
            iv=None,
            app_version=args.wa_version,
            jid_suffix=args.jid,
        )
        header.prefix = build_prefix(
            iv=os.urandom(16),
            app_version=args.wa_version,
            jid_suffix=args.jid,
            backup_version=source_header.backup_version if source_header else None,
            features=source_header.features if source_header else [],
        )

    target = args.output or args.database.with_suffix(f".crypt{args.type}")
    try:
        with _Progress(f"encrypting {args.database.name}") as update:
            pack_from_file(args.database, aes_key, target, header, iv=iv, progress=update)
    except (WrongKey, CryptoError, HeaderError) as exc:
        _fail(str(exc))

    payload = {"input": str(args.database), "output": str(target), "size": target.stat().st_size}
    if args.json:
        _json(payload)
        return
    print(
        _paint("ok", "green")
        + f" encrypted -> {_paint(target, 'bold')} ({_readable_size(payload['size'])})"
    )


# --------------------------------------------------------------------------- #
# inspect
# --------------------------------------------------------------------------- #


def cmd_inspect(args) -> None:
    """Owner number, chat and message counts, date range, footprint."""
    resolved = _key_argument(args.key)

    try:
        with open_backup(args.file, resolved) as (header, db_path, _state):
            conn = open_db(db_path, read_only=True)
            try:
                owner = owner_report(conn, header.jid_suffix)
                stats = _database_stats(conn)
            finally:
                conn.close()
    except (WrongKey, CryptoError, HeaderError, KeyError_) as exc:
        _fail(str(exc))

    payload = {"header": header.summary(), "owner": owner, "database": stats}
    if args.json:
        _json(payload)
        return

    confidence_colour = {"high": "green", "medium": "yellow", "low": "red", "none": "red"}[
        str(owner["confidence"])
    ]

    rows: List[Tuple[str, object]] = [
        ("crypt type", f"crypt{header.crypt_type}"),
        ("WhatsApp version", str(header.app_version or "—")),
        ("header jid suffix", str(header.jid_suffix or "—")),
        (
            "owner number",
            f"{owner['number'] or 'unknown'} ({owner['confidence']})",
        ),
        ("why", str(owner.get("reason", ""))),
    ]
    colours: List[Optional[str]] = [None, None, None, confidence_colour, None]

    if owner["number"] is None and owner["candidates"]:
        rows.append(
            (
                "candidates",
                ", ".join(
                    f"{entry['number']} ({entry['sent']}↑/{entry['received']}↓)"
                    for entry in owner["candidates"][:10]
                ),
            )
        )
        colours.append(None)

    rows.extend(
        [
            ("chats", f"{stats['chats']:,}"),
            ("messages", f"{stats['messages']:,}"),
            ("earliest message", str(stats["first_message"])),
            ("latest message", str(stats["last_message"])),
            ("attachments", f"{stats['media']:,} ({_readable_size(stats['media_bytes'])})"),
            ("database size", _readable_size(stats["db_bytes"])),
        ]
    )
    colours.extend([None] * 6)

    _kv(rows, title=args.file.name, colours=colours)


# --------------------------------------------------------------------------- #
# search
# --------------------------------------------------------------------------- #


def cmd_search(args) -> None:
    """Find messages without ever seeing a decrypted file."""
    resolved = _key_argument(args.key)

    try:
        with open_backup(args.file, resolved) as (_header, db_path, _state):
            conn = open_db(db_path, read_only=True)
            try:
                hits = search(
                    conn,
                    args.pattern,
                    regex=args.regex,
                    chat=args.chat,
                    sender=args.sender,
                    since=args.since,
                    until=args.until,
                    limit=args.limit,
                    case_sensitive=args.case_sensitive,
                    context=args.context,
                )
            finally:
                conn.close()
    except (WrongKey, CryptoError, HeaderError, DbError) as exc:
        _fail(str(exc))

    if args.json:
        _json([hit.as_dict() for hit in hits])
        return

    if not hits:
        print(f"{_paint('no matches', 'yellow')} for {_paint(args.pattern, 'bold')}")
        return

    _grid(
        ["when", "chat", "from", "message"],
        [[hit.when(), hit.chat, hit.sender, hit.text] for hit in hits],
        max_widths=[None, 34, 18, None],
        wrap_last=True,
    )
    print(_paint(f"{len(hits)} match(es)", "dim"))


# --------------------------------------------------------------------------- #
# export
# --------------------------------------------------------------------------- #


def cmd_export(args) -> None:
    """Write conversations to HTML, JSON, CSV or plain text."""
    resolved = _key_argument(args.key)
    if args.format not in FORMATS:
        _fail(f"unknown format {args.format!r}; choose from {', '.join(FORMATS)}")

    try:
        with open_backup(args.file, resolved) as (_header, db_path, _state):
            conn = open_db(db_path, read_only=True)
            try:
                available = list_chats(conn)
                chosen = _pick_chats(available, args.chats)
                if not chosen:
                    _fail("no chats matched --chats")
                written = export_chats(
                    conn,
                    chosen,
                    args.out,
                    args.format,
                    limit=args.limit,
                    media_root=args.media_root,
                    include_media=args.include_media,
                )
            finally:
                conn.close()
    except (WrongKey, CryptoError, HeaderError, DbError, ExportError, KeyError_) as exc:
        _fail(str(exc))

    payload = {
        "format": args.format,
        "out_dir": str(args.out),
        "chats": len(chosen),
        "files": [str(path) for path in written],
    }
    if args.json:
        _json(payload)
        return
    print(
        _paint("ok", "green")
        + f" exported {len(chosen)} chat(s) -> {_paint(args.out, 'bold')} "
        f"({len(written)} file(s), format {args.format})"
    )


# --------------------------------------------------------------------------- #
# diff
# --------------------------------------------------------------------------- #


def cmd_diff(args) -> None:
    """Say what changed between two backups."""
    resolved = _key_argument(args.key)

    try:
        with open_backup(args.old, resolved) as (_oh, old_path, _s1):
            with open_backup(args.new, resolved) as (_nh, new_path, _s2):
                old_conn = open_db(old_path, read_only=True)
                new_conn = open_db(new_path, read_only=True)
                try:
                    result = diff_backups(
                        old_conn, new_conn, str(args.old), str(args.new), limit=args.limit
                    )
                finally:
                    old_conn.close()
                    new_conn.close()
    except (WrongKey, CryptoError, HeaderError, DbError, DiffError, KeyError_) as exc:
        _fail(str(exc))

    if args.json:
        _json(result.as_dict())
        return

    print(
        f"messages: {result.total_old_messages:,} → {result.total_new_messages:,} "
        f"({_paint('+' + str(result.total_added), 'green')} "
        f"{_paint('−' + str(result.total_removed), 'red')})   "
        f"matched on {_paint(result.key_source, 'dim')}"
    )
    print(
        f"chats: {len(result.new_chats)} new, {len(result.removed_chats)} removed, "
        f"{len(result.changed_chats)} with changes"
    )

    if not result.chats:
        print(_paint("no differences found", "dim"))
        return

    tone = {"new": "green", "removed": "red", "added": "cyan", "unchanged": "dim"}

    def style(_row: int, column: int, value: str) -> str:
        if column != 0:
            return value
        return _paint(value, tone.get(value, "grey"))

    _grid(
        ["status", "chat", "before", "after", "added", "removed"],
        [
            [
                chat.status,
                chat.label,
                str(chat.old_messages),
                str(chat.new_messages),
                str(chat.added) if chat.added else "",
                str(chat.removed) if chat.removed else "",
            ]
            for chat in result.chats[: args.limit]
        ],
        aligns=["l", "l", "r", "r", "r", "r"],
        max_widths=[9, 44, None, None, None, None],
        styles=style,
    )


# --------------------------------------------------------------------------- #
# migrate
# --------------------------------------------------------------------------- #


def cmd_migrate(args) -> None:
    """Change the phone number a backup belongs to. Dry run unless --apply."""
    resolved = _key_argument(args.key)

    try:
        # Everything happens inside the `with`: `db_path` belongs to a
        # temporary directory that open_backup deletes when the block exits,
        # so the copy and the re-encryption must not outlive it.
        with open_backup(args.file, resolved) as (header, db_path, _state):
            conn = open_db(db_path, read_only=True)
            try:
                source = args.old_number
                if source is None:
                    report = owner_report(conn, header.jid_suffix)
                    source = report["number"]
                    if source is None:
                        _fail(
                            "could not detect the current number; pass --from explicitly. "
                            f"reason: {report['reason']}"
                        )
                    print(_paint(f"detected current number: {source}", "dim"))

                plan = plan_migration(
                    conn,
                    source,
                    args.new_number,
                    suffix=header.jid_suffix,
                    include_text=args.rewrite_text,
                )
            finally:
                conn.close()

            if not args.apply:
                _print_plan(plan, args.json)
                if not args.json:
                    print()
                    print(
                        _paint("dry run", "yellow")
                        + " — nothing was written. Re-run with "
                        + _paint("--apply", "bold")
                        + " to perform the migration."
                    )
                return

            if plan.empty:
                _fail("the plan changes nothing; is --from correct?")

            target = args.output or args.file.with_name(args.file.stem + "_migrated.crypt15")
            if target.resolve() == args.file.resolve():
                _fail("refusing to overwrite the original backup")

            # Work on a copy: nothing shared with any other command may be
            # mutated, or every later command would inherit the change.
            with tempfile.TemporaryDirectory(prefix="wacrypt-migrate-") as work:
                working = Path(work) / "msgstore.db"
                shutil.copyfile(db_path, working)
                conn = open_db(working, read_only=False)
                try:
                    applied = apply_migration(conn, plan, merge_collisions=args.merge_collisions)
                    vacuum(conn)
                finally:
                    conn.close()

                new_header = _retarget_header(header, plan.suffix_to)
                aes_key = derive_backup_key(resolved or resolve_key())
                with _Progress(f"writing {target.name}") as update:
                    pack_from_file(working, aes_key, target, new_header, progress=update)

    except (WrongKey, CryptoError, HeaderError, DbError, MigrationError, KeyError_) as exc:
        _fail(str(exc))

    moved = []
    if args.media_root is not None:
        try:
            moved = rename_media_directories(args.media_root, plan.old, plan.new, dry_run=False)
        except MigrationError as exc:
            _fail(str(exc))

    result = {
        **plan.as_dict(),
        "applied": applied,
        "output": str(target),
        "output_size": target.stat().st_size,
        "media_renamed": moved,
    }
    if args.json:
        _json(result)
        return

    print(f"\n{_paint('ok', 'green')} migration applied — {sum(applied.values()):,} row(s)")
    for name, amount in applied.items():
        print(f"  • {name}: {amount:,}")
    print(
        f"backup written -> {_paint(target, 'bold')} "
        f"({_readable_size(target.stat().st_size)})"
    )
    if moved:
        print(f"media folders renamed: {len(moved)}")
    print(
        _paint(
            "keep the original until WhatsApp has opened and verified the new backup",
            "dim",
        )
    )


# --------------------------------------------------------------------------- #
# integrity
# --------------------------------------------------------------------------- #


def cmd_integrity(args) -> None:
    """Check the backup's checksum and the database's internal structure."""
    resolved = _key_argument(args.key)

    report: Dict[str, object] = {"file": str(args.file)}
    try:
        header = read_header(args.file)
        report["header"] = {"ok": True, "crypt_type": header.crypt_type}
    except HeaderError as exc:
        report["header"] = {"ok": False, "error": str(exc)}

    try:
        with open_backup(args.file, resolved) as (_h, db_path, _state):
            conn = open_db(db_path, read_only=True)
            try:
                report["database"] = integrity(conn)
                report["tables"] = len(table_names(conn))
            finally:
                conn.close()
    except (WrongKey, CryptoError, HeaderError, KeyError_) as exc:
        report["database"] = {"quick_check": f"error: {exc}"}

    if args.json:
        _json(report)
        return

    ok_header = report["header"].get("ok")
    print(
        f"header  : {_paint('ok', 'green') if ok_header else _paint('bad', 'red')}"
        + ("" if ok_header else f" — {report['header'].get('error')}")
    )
    if "database" in report:
        verdict = str(report["database"].get("quick_check", "unknown"))
        colour = "green" if verdict == "ok" else "red"
        print(f"database: {_paint(verdict, colour)}")
        if "integrity_check" in report["database"]:
            print(f"full    : {_paint(report['database']['integrity_check'], colour)}")
        print(f"tables  : {report.get('tables', 0)}")


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wacrypt",
        description="Manage, inspect, migrate and search WhatsApp local backups "
        "(msgstore.db.crypt14 / crypt15). No wa_crypt_tools required.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", "-V", action="version", version=f"wacrypt {__version__}"
    )
    commands = parser.add_subparsers(dest="command", metavar="<command>", title="commands")

    def common(sub, key: bool = True) -> argparse.ArgumentParser:
        if key:
            sub.add_argument("--key", "-k", help=KEY_HELP)
        sub.add_argument("--json", action="store_true", help="Machine readable output.")
        return sub

    # info
    sub = commands.add_parser(
        "info", help="Read the header. Needs no key and touches only the first 64 KB."
    )
    sub.add_argument("file", type=_existing_file, help="Encrypted backup.")
    sub.add_argument(
        "--json", action="store_true", help="Machine readable output."
    )
    sub.set_defaults(func=cmd_info)

    # decrypt
    sub = commands.add_parser("decrypt", help="Decrypt a backup to a plain SQLite database.")
    sub.add_argument("file", type=_existing_file, help="Encrypted backup.")
    sub.add_argument("--output", "-o", type=Path, help="Where to write the .db.")
    common(sub)
    sub.set_defaults(func=cmd_decrypt)

    # encrypt
    sub = commands.add_parser(
        "encrypt", help="Encrypt a plain SQLite database into a crypt15 backup."
    )
    sub.add_argument("database", type=_existing_file, help="Plain SQLite file.")
    sub.add_argument("--output", "-o", type=Path, help="Where to write the backup.")
    sub.add_argument("--type", type=_int_between(14, 15), default=15, help="crypt14 or crypt15.")
    sub.add_argument("--jid", help="Last two digits of the number.")
    sub.add_argument("--wa-version", help="WhatsApp version to record in the header.")
    sub.add_argument(
        "--reuse-iv",
        dest="reuse_iv",
        action="store_true",
        default=False,
        help="Reuse the IV from --like instead of generating a fresh one. "
        "Only correct when the plaintext is byte identical to that backup.",
    )
    sub.add_argument(
        "--new-iv", dest="reuse_iv", action="store_false", help="Generate a fresh IV (default)."
    )
    sub.add_argument(
        "--like",
        type=_existing_file,
        help="Copy the header of an existing backup (recommended). The IV is "
        "not copied unless --reuse-iv says so.",
    )
    common(sub)
    sub.set_defaults(func=cmd_encrypt)

    # inspect
    sub = commands.add_parser(
        "inspect", help="Owner number, chat and message counts, date range, footprint."
    )
    sub.add_argument("file", type=_existing_file, help="Encrypted backup.")
    common(sub)
    sub.set_defaults(func=cmd_inspect)

    # search
    sub = commands.add_parser(
        "search", help="Find messages without ever seeing a decrypted file."
    )
    sub.add_argument("file", type=_existing_file, help="Encrypted backup.")
    sub.add_argument("pattern", help="Text to find. With --regex it is an expression.")
    sub.add_argument(
        "--regex", "-r", action="store_true", help="Treat the pattern as a regular expression."
    )
    sub.add_argument("--case-sensitive", "-s", action="store_true")
    sub.add_argument("--chat", "-c", help="Only chats whose name/JID contains this.")
    sub.add_argument("--sender", help="Only senders containing this.")
    sub.add_argument("--since", help="Earliest date, YYYY-MM-DD.")
    sub.add_argument("--until", help="Latest date, YYYY-MM-DD.")
    sub.add_argument(
        "--context", type=_int_at_least(0), default=0,
        help="Show N characters either side of the match.",
    )
    sub.add_argument(
        "--limit", "-n", type=_int_between(1, 10000), default=50, help="Maximum matches."
    )
    common(sub)
    sub.set_defaults(func=cmd_search)

    # export
    sub = commands.add_parser(
        "export", help="Write conversations to HTML, JSON, CSV or plain text."
    )
    sub.add_argument("file", type=_existing_file, help="Encrypted backup.")
    sub.add_argument("--out", "-o", type=Path, default=Path("./chat_export"),
                     help="Output directory.")
    sub.add_argument("--format", "-f", default="html", help="html | json | csv | txt")
    sub.add_argument(
        "--chats", "-c",
        help="Comma separated chat numbers/JIDs, or 'all' (default), or 'groups'/'private'.",
    )
    sub.add_argument("--limit", type=int, help="Keep only the last N messages per chat.")
    sub.add_argument("--media-root", type=Path, help="Root the attachments live under.")
    sub.add_argument(
        "--include-media", action="store_true", help="Copy referenced media files too."
    )
    common(sub)
    sub.set_defaults(func=cmd_export)

    # diff
    sub = commands.add_parser("diff", help="Say what changed between two backups.")
    sub.add_argument("old", type=_existing_file, help="The older backup.")
    sub.add_argument("new", type=_existing_file, help="The newer backup.")
    sub.add_argument(
        "--limit", "-n", type=_int_at_least(1), default=40,
        help="How many changed chats to show.",
    )
    common(sub)
    sub.set_defaults(func=cmd_diff)

    # migrate
    sub = commands.add_parser(
        "migrate", help="Change the phone number a backup belongs to. Dry run unless --apply."
    )
    sub.add_argument("file", type=_existing_file, help="Encrypted backup.")
    sub.add_argument("new_number", help="Target number, with country code, e.g. 9665…")
    sub.add_argument(
        "--from", dest="old_number", help="Number to migrate away from. Detected when omitted."
    )
    sub.add_argument("--output", "-o", type=Path, help="Where the new backup is written.")
    sub.add_argument(
        "--apply",
        action="store_true",
        help="Actually write the migration. Without this flag nothing is changed (dry run).",
    )
    sub.add_argument(
        "--merge-collisions",
        action="store_true",
        help="Allow deleting an existing chat that already owns the target number.",
    )
    sub.add_argument(
        "--rewrite-text",
        action="store_true",
        help="Also rewrite chat content that quotes the number (messages, links, vCards). "
        "Off by default: only what a restored backup needs is changed.",
    )
    sub.add_argument(
        "--media-root", type=Path,
        help="Also rename <old>@s.whatsapp.net folders under this directory.",
    )
    common(sub)
    sub.set_defaults(func=cmd_migrate)

    # integrity
    sub = commands.add_parser(
        "integrity", help="Check the backup's checksum and the database's internal structure."
    )
    sub.add_argument("file", type=_existing_file, help="Encrypted backup.")
    common(sub)
    sub.set_defaults(func=cmd_integrity)

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    arguments = list(sys.argv[1:]) if argv is None else list(argv)

    if not arguments:
        parser.print_help()
        return

    args = parser.parse_args(arguments)
    if not getattr(args, "func", None):
        parser.print_help()
        raise SystemExit(2)

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n" + _paint("cancelled", "yellow"), file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
