"""Key storage and the decrypted-database cache.

Two different secrets live here and they are kept apart on purpose.

**The backup key** never touches the filesystem: it goes straight into the
platform keychain (macOS Keychain, Secret Service, Windows Credential
Manager).  wacrypt asks for it once and never again.

**The decrypted database** is 200+ MB of every conversation the user has.
Leaving that as a plain ``msgstore.db`` in a temp folder is how people leak
their entire chat history, so the cache is AES-256-GCM encrypted at rest with
a key that is itself only in the keychain.  A plaintext copy exists for the
lifetime of one command and is unlinked afterwards.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .crypto import CHUNK
from .header import BackupHeader  # noqa: F401  (re-exported for callers)

__all__ = [
    "VaultError",
    "cache_root",
    "session_root",
    "fingerprint",
    "has_cache",
    "store_cache",
    "materialize",
    "stale",
    "purge",
    "status",
]

CACHE_VERSION = 1
DEFAULT_TTL = 4 * 3600
"""How long a cached decryption stays valid before wacrypt re-reads the backup."""

SERVICE = "wacrypt"
VAULT_ACCOUNT = "vault-key"
NONCE_SIZE = 16


class VaultError(Exception):
    """The cache or the keychain could not be used."""


# --------------------------------------------------------------------------- #
# Locations
# --------------------------------------------------------------------------- #


def _data_home() -> Path:
    override = os.environ.get("WACRYPT_HOME")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "wacrypt"
    return Path.home() / ".local" / "share" / "wacrypt"


def cache_root() -> Path:
    return _data_home() / "cache"


def session_root() -> Path:
    return _data_home() / "sessions"


def _private(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    return directory


# --------------------------------------------------------------------------- #
# Vault key (keychain)
# --------------------------------------------------------------------------- #


def vault_key() -> bytes:
    """The 32 byte key that protects the cache, created on first use."""
    import keyring

    stored = keyring.get_password(SERVICE, VAULT_ACCOUNT)
    if stored:
        try:
            key = bytes.fromhex(stored)
            if len(key) == 32:
                return key
        except ValueError:
            pass

    key = secrets.token_bytes(32)
    try:
        keyring.set_password(SERVICE, VAULT_ACCOUNT, key.hex())
    except Exception as exc:  # pragma: no cover - depends on the platform
        raise VaultError(
            f"cannot store the cache key in the keychain ({exc}); "
            "run with --no-cache to skip the cache entirely"
        ) from exc
    return key


# --------------------------------------------------------------------------- #
# Cache identity
# --------------------------------------------------------------------------- #


def fingerprint(path) -> str:
    """A stable id for one specific backup file.

    The size and mtime are part of it, so replacing ``msgstore.db.crypt15``
    with a newer backup invalidates the cache automatically instead of serving
    yesterday's chats.
    """
    target = Path(path)
    stat = target.stat()
    payload = f"{target.resolve()}|{stat.st_size}|{int(stat.st_mtime)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _paths(fp: str):
    root = _private(cache_root())
    return root / f"{fp}.enc", root / f"{fp}.meta.json"


def _session_path(fp: str) -> Path:
    return _private(session_root()) / f"{fp}.db"


# --------------------------------------------------------------------------- #
# Encrypt / decrypt helpers
# --------------------------------------------------------------------------- #


def _encrypt_stream(source: Path, target: Path, key: bytes) -> None:
    """AES-256-GCM the cache entry, streaming, nonce prefixed on disk."""
    nonce = secrets.token_bytes(NONCE_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    with source.open("rb") as src, target.open("wb") as dst:
        dst.write(nonce)
        while True:
            block = src.read(CHUNK)
            if not block:
                break
            dst.write(encryptor.update(block))
        encryptor.finalize()
        dst.write(encryptor.tag)


def _decrypt_stream(source: Path, target: Path, key: bytes) -> None:
    """Undo :func:`_encrypt_stream`.  Layout is nonce | ciphertext | tag."""
    from cryptography.exceptions import InvalidTag

    size = source.stat().st_size
    if size < NONCE_SIZE + 16:
        raise VaultError("cache entry is truncated")
    with source.open("rb") as src:
        nonce = src.read(NONCE_SIZE)
        # The tag is the last 16 bytes of the file, not the next 16.
        src.seek(size - 16)
        tag = src.read(16)
        src.seek(NONCE_SIZE)

        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        remaining = size - NONCE_SIZE - 16
        with target.open("wb") as dst:
            while remaining > 0:
                block = src.read(min(CHUNK, remaining))
                if not block:
                    raise VaultError("cache entry is truncated")
                remaining -= len(block)
                dst.write(decryptor.update(block))
            try:
                tail = decryptor.finalize()
            except InvalidTag as exc:
                raise VaultError("cache entry failed authentication") from exc
            if tail:
                dst.write(tail)
    os.chmod(target, 0o600)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def has_cache(fp: str) -> bool:
    enc, meta = _paths(fp)
    if not (enc.is_file() and meta.is_file()):
        return False
    try:
        return json.loads(meta.read_text())["version"] == CACHE_VERSION
    except Exception:
        return False


def stale(fp: str, ttl: int = DEFAULT_TTL) -> bool:
    if not has_cache(fp):
        return True
    _, meta = _paths(fp)
    try:
        created = float(json.loads(meta.read_text())["created"])
    except Exception:
        return True
    return (time.time() - created) > ttl


def store_cache(fp: str, db_path: Path, source: Path) -> None:
    """Encrypt a freshly decrypted database into the cache."""
    key = vault_key()
    enc, meta = _paths(fp)
    temporary = enc.with_name(enc.name + ".partial")
    try:
        _encrypt_stream(db_path, temporary, key)
        os.replace(temporary, enc)
        os.chmod(enc, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()

    meta.write_text(
        json.dumps(
            {
                "version": CACHE_VERSION,
                "created": time.time(),
                "source": str(source),
                "source_size": source.stat().st_size,
                "db_size": db_path.stat().st_size,
            },
            indent=2,
        )
    )
    os.chmod(meta, 0o600)


def materialize(fp: str, dest) -> Optional[Path]:
    """Decrypt the cache into ``dest`` and return the plain database.

    ``dest`` is a directory the **caller owns and will delete**: every command
    passes a fresh temporary directory, so no plaintext outlives the command
    that needed it.  That is deliberate — the cache exists precisely so that
    248 MB of chat history is never sitting on disk in the clear, and keeping a
    long-lived "fast path" copy around would defeat the entire point of
    encrypting it.  Decrypting the cache costs about 0.17 s, which is a price
    worth paying.

    Returns ``None`` when there is nothing cached for ``fp``.
    """
    if not has_cache(fp):
        return None

    directory = Path(dest)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass

    target = directory / f"{fp}.db"
    key = vault_key()
    enc, _ = _paths(fp)
    _decrypt_stream(enc, target, key)
    return target


def purge(fp: Optional[str] = None) -> int:
    """Delete cached and materialised databases.  Returns files removed.

    The session directory is also swept: it is where materialised databases
    used to accumulate in the clear, and clearing it is how an existing
    install gets rid of them.
    """
    removed = 0
    for directory in (cache_root(), session_root()):
        if not directory.is_dir():
            continue
        for entry in directory.iterdir():
            if fp and not entry.name.startswith(fp):
                continue
            entry.unlink()
            removed += 1
    return removed


def status() -> dict:
    out = {
        "cache_dir": str(cache_root()),
        "session_dir": str(session_root()),
        "entries": [],
        "key_in_keychain": False,
    }
    try:
        import keyring

        out["key_in_keychain"] = bool(keyring.get_password(SERVICE, VAULT_ACCOUNT))
    except Exception:
        pass

    if cache_root().is_dir():
        for enc in sorted(cache_root().glob("*.enc")):
            fp = enc.stem
            entry = {"fingerprint": fp, "cache_bytes": enc.stat().st_size}
            _, meta = _paths(fp)
            if meta.is_file():
                try:
                    info = json.loads(meta.read_text())
                    entry["source"] = info.get("source")
                    entry["created"] = info.get("created")
                except Exception:
                    pass
            session = _session_path(fp)
            # Should always be False: nothing keeps a plaintext copy any more.
            # It is reported so that a leftover from an older version shows up.
            entry["plaintext_on_disk"] = session.is_file()
            out["entries"].append(entry)
    return out
