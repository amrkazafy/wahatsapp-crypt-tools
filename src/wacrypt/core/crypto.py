"""Encryption, decryption and the key schedule for WhatsApp local backups.

The whole chain is implemented here from scratch; nothing shells out to
``wadecrypt``.  What follows was derived from the published WhatsApp
behaviour and then verified byte for byte against a real WhatsApp 2.26
``crypt15`` backup::

    root key (32 bytes, shown as 64 hex digits in the app)
      -> HMAC-SHA256(zeros32, root)                 = private key
      -> HMAC-SHA256(private, "backup encryption" + b"\\x01")
                                                = AES-256 key
    AES-256-GCM(key, IV from the header) over the zlib compressed database
    16 byte authentication tag, then an MD5 over everything written so far.

The payload is zlib, not raw SQLite: ``78 da`` (level 9) is what WhatsApp
writes, which is why a decrypted backup is ~2.4x its on disk size.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import zlib
from pathlib import Path
from typing import Callable, Iterator, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .header import BackupHeader, HeaderError, encode_varint, read_header

__all__ = [
    "CryptoError",
    "WrongKey",
    "CorruptedBackup",
    "derive_backup_key",
    "encryption_loop",
    "iter_decrypted",
    "iter_plaintext",
    "unpack_to_file",
    "pack_from_file",
    "sniff_payload",
]

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
    """
    source = Path(db_path)
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if len(aes_key) != 32:
        raise WrongKey(f"AES key must be 32 bytes, got {len(aes_key)}")

    iv = iv or header.iv or os.urandom(16)
    if len(iv) != 16:
        raise HeaderError(f"IV must be 16 bytes, got {len(iv)}")

    prefix = header.prefix
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
