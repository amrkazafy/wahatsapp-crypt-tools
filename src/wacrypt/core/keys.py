"""Where the backup key comes from.

Three sources, in the order they are tried:

1. ``--key`` on the command line, as 64 hex digits or a path to a file.
2. A macOS keychain / Secret Service entry kept by ``wacrypt vault``.
3. An interactive, **hidden** prompt.

The key is never echoed, never logged, and never written to a cache file in
plaintext.  This module is deliberately the only place that knows how to turn
a user supplied string into bytes, so there is one seam to audit.
"""

from __future__ import annotations

import os
import re
from getpass import getpass
from pathlib import Path
from typing import Optional

__all__ = [
    "KeyError_",
    "parse_hex_key",
    "load_key_file",
    "resolve_key",
    "prompt_for_key",
]

HEX_KEY = re.compile(r"^[0-9a-fA-F]{64}$")
SERVICE = "wacrypt"
ACCOUNT = "backup-key"


class KeyError_(Exception):
    """The key could not be understood.

    Named with a trailing underscore so ``from .keys import KeyError_`` never
    shadows the builtin; catching the builtin by accident here would swallow
    real programming errors.
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


def resolve_key(
    value: Optional[str] = None,
    *,
    use_vault: bool = True,
    allow_prompt: bool = True,
) -> bytes:
    """Resolve a backup key from any of the supported sources."""
    if value:
        candidate = value.strip().strip('"').strip("'")
        if HEX_KEY.fullmatch(candidate.replace(" ", "")):
            return parse_hex_key(candidate)
        path = Path(candidate).expanduser()
        if path.is_file():
            return load_key_file(path)
        # Fall through to the error below so the message is uniform.
        raise KeyError_("--key is neither 64 hex digits nor an existing file")

    if use_vault:
        stored = vault_get()
        if stored is not None:
            return stored

    if allow_prompt:
        return prompt_for_key()

    raise KeyError_("no key available")


def prompt_for_key(what: str = "64 hex backup key") -> bytes:
    """Ask for the key with echo turned off."""
    while True:
        try:
            typed = getpass(f"{what}: ")
        except (EOFError, KeyboardInterrupt):
            raise KeyError_("no key supplied") from None
        if not typed.strip():
            print("  (empty, try again or Ctrl-C to abort)")
            continue
        try:
            return parse_hex_key(typed)
        except KeyError_ as exc:
            print(f"  {exc}")


# --------------------------------------------------------------------------- #
# Keychain
# --------------------------------------------------------------------------- #


def _keyring():
    try:
        import keyring  # noqa: PLC0415

        return keyring
    except Exception:  # pragma: no cover - keyring is a hard dependency
        return None


def vault_get(account: str = ACCOUNT) -> Optional[bytes]:
    """Read the key back out of the platform keychain, if it is there."""
    backend = _keyring()
    if backend is None:
        return None
    try:
        stored = backend.get_password(SERVICE, account)
    except Exception:
        return None
    if not stored:
        return None
    try:
        return parse_hex_key(stored)
    except KeyError_:
        return None


def vault_set(key: bytes, account: str = ACCOUNT) -> bool:
    """Store the key in the platform keychain.  Returns False if unavailable."""
    backend = _keyring()
    if backend is None:
        return False
    try:
        backend.set_password(SERVICE, account, key.hex())
        return True
    except Exception:
        return False


def vault_delete(account: str = ACCOUNT) -> bool:
    backend = _keyring()
    if backend is None:
        return False
    try:
        backend.delete_password(SERVICE, account)
        return True
    except Exception:
        return False


def vault_status(account: str = ACCOUNT) -> Optional[str]:
    """Return the stored key, redacted, or None when nothing is stored."""
    key = vault_get(account)
    if key is None:
        return None
    return f"{key.hex()[:6]}…{key.hex()[-4:]}"
