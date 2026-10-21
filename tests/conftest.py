"""Shared fixtures.

Everything here is built from a **synthetic** database: a small msgstore-shaped
schema with a hand made owner self-chat, two real conversations and a group.
No user data is read by the tests and none is written outside the temp
directory pytest hands out.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from wacrypt import build_prefix, derive_backup_key, pack_from_file, read_header, unpack_to_file

# A fixed root key so failures reproduce.  This is a test key, never a real one.
TEST_ROOT_KEY = bytes(range(32))
OWNER = "99900011122"
SUFFIX = OWNER[-2:]


def _schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE jid (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT, server TEXT, agent INTEGER, device INTEGER,
            type INTEGER, raw_string TEXT
        );
        CREATE TABLE chat (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            jid_row_id INTEGER, hidden INTEGER, subject TEXT,
            group_type INTEGER, sort_timestamp INTEGER
        );
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_row_id INTEGER, sender_jid_row_id INTEGER, from_me INTEGER,
            timestamp INTEGER, key_id TEXT, message_type INTEGER, text_data TEXT
        );
        CREATE TABLE message_media (
            message_row_id INTEGER PRIMARY KEY, media_caption TEXT,
            mime_type TEXT, media_name TEXT, file_size INTEGER, file_path TEXT
        );
        """
    )


def _jid(conn, user, server="s.whatsapp.net", device=0, jtype=0, raw=None):
    raw = raw or f"{user}@{server}"
    cur = conn.execute(
        "INSERT INTO jid (user, server, agent, device, type, raw_string) "
        "VALUES (?,?,?,?,?,?)",
        (user, server, 0, device, jtype, raw),
    )
    return cur.lastrowid


def _chat(conn, jid_row, subject=None, group_type=0, sort_timestamp=0):
    cur = conn.execute(
        "INSERT INTO chat (jid_row_id, hidden, subject, group_type, sort_timestamp) "
        "VALUES (?,?,?,?,?)",
        (jid_row, 0, subject, group_type, sort_timestamp),
    )
    return cur.lastrowid


def _msg(conn, chat_row, sender, from_me, ts, text, key_id=None, message_type=0):
    cur = conn.execute(
        "INSERT INTO message (chat_row_id, sender_jid_row_id, from_me, timestamp, "
        "key_id, message_type, text_data) VALUES (?,?,?,?,?,?,?)",
        (chat_row, sender, from_me, ts, key_id or f"key{_msg.counter}", message_type, text),
    )
    _msg.counter += 1
    return cur.lastrowid


_msg.counter = 0


def build_database(path: Path) -> dict:
    """Create a small but realistic msgstore.  Returns a summary of what is in it."""
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    _schema(conn)

    owner_jid = _jid(conn, OWNER, device=0)
    # A second device row for the same account, in WhatsApp's agent:device form.
    _jid(conn, OWNER, device=5, raw=f"{OWNER}.0:5@s.whatsapp.net")
    # A DIFFERENT account whose number merely starts with the owner's.  Every
    # prefix-matching implementation corrupts this one; ours must not.
    confusable = "999000111220"
    _jid(conn, confusable)
    # …and one whose number is a strict *prefix* of the owner's — the other
    # direction of the same boundary rule.
    shorter = OWNER[:10]
    _jid(conn, shorter)
    friend_jid = _jid(conn, "99900099988")
    group_jid = _jid(conn, "120363012345678901", server="g.us", jtype=1)

    # The self chat: lopsided on purpose.  60 sent, 1 received clears both
    # thresholds in db._looks_like_self_chat.
    self_chat = _chat(conn, owner_jid, sort_timestamp=1_700_000_000_000)
    base = int(time.mktime((2024, 1, 1, 10, 0, 0, 0, 0, 0))) * 1000
    for index in range(60):
        _msg(conn, self_chat, owner_jid, 1, base + index * 1000,
             f"note to self {index}", key_id=f"self{index}")
    _msg(conn, self_chat, owner_jid, 0, base + 61_000, "echo", key_id="selfEcho")

    # A balanced one-to-one conversation: this is what must NOT be mistaken
    # for the owner.
    friend_chat = _chat(conn, friend_jid, sort_timestamp=1_700_000_100_000)
    for index in range(40):
        _msg(conn, friend_chat, friend_jid, 0, base + index * 2000,
             f"hi there {index}" if index % 2 else "reply", key_id=f"f{index}")

    # A group, plus a caption and a media row.
    group_chat = _chat(conn, group_jid, subject="Team", group_type=1,
                       sort_timestamp=1_700_000_200_000)
    mid = _msg(conn, group_chat, friend_jid, 0, base + 500_000, "", message_type=1)
    conn.execute(
        "INSERT INTO message_media (message_row_id, media_caption, mime_type, media_name, "
        "file_size, file_path) VALUES (?,?,?,?,?,?)",
        (mid, f"holiday photo from {OWNER}@s.whatsapp.net and {confusable}@s.whatsapp.net",
         "image/jpeg", f"{OWNER}.jpg", 2048,
         f"Media/{OWNER}@s.whatsapp.net/thumb/{OWNER}-1.jpg"),
    )

    conn.commit()
    summary = {
        "owner": OWNER,
        "confusable": confusable,
        "chats": conn.execute("SELECT COUNT(*) FROM chat").fetchone()[0],
        "messages": conn.execute("SELECT COUNT(*) FROM message").fetchone()[0],
    }
    conn.close()
    return summary


def test_header() -> object:
    """A crypt15 header shaped like the real thing, without any real metadata."""
    return build_prefix(
        iv=bytes(range(16)),
        key_type=1,
        key_type_new=3,
        app_version="2.26.40.73",
        jid_suffix=SUFFIX,
        backup_version=1,
        features=list(range(5, 38)),
        cleaned_db=True,
    )


@pytest.fixture(scope="session")
def root_key() -> bytes:
    return TEST_ROOT_KEY


@pytest.fixture(scope="session")
def aes_key(root_key) -> bytes:
    return derive_backup_key(root_key)


@pytest.fixture(scope="session")
def plain_db(tmp_path_factory) -> Path:
    """A synthetic msgstore.db."""
    path = tmp_path_factory.mktemp("db") / "msgstore.db"
    build_database(path)
    return path


@pytest.fixture(scope="session")
def backup(plain_db, tmp_path_factory, root_key) -> Path:
    """The synthetic database, encrypted to a real crypt15 file."""
    out = tmp_path_factory.mktemp("crypt") / "msgstore.db.crypt15"
    pack_from_file(plain_db, derive_backup_key(root_key), out, _fixture_header(plain_db))
    return out


def _fixture_header(plain_db: Path):
    from wacrypt import BackupHeader

    prefix = test_header()
    return BackupHeader(
        path=plain_db,
        file_size=plain_db.stat().st_size,
        crypt_type=15,
        header_len=len(prefix),
        cipher_offset=0,
        prefix=prefix,
        iv=bytes(range(16)),
        app_version="2.26.40.73",
        jid_suffix=SUFFIX,
        backup_version=1,
        features=list(range(5, 38)),
        cleaned_db=True,
    )


@pytest.fixture(scope="session")
def decrypted(tmp_path_factory, backup, aes_key) -> Path:
    """The fixture backup, decrypted back to SQLite."""
    out = tmp_path_factory.mktemp("plain") / "out.db"
    unpack_to_file(backup, aes_key, out)
    return out


@pytest.fixture()
def conn(decrypted):
    database = sqlite3.connect(f"file:{decrypted}?mode=ro", uri=True)
    database.row_factory = sqlite3.Row
    try:
        yield database
    finally:
        database.close()


@pytest.fixture()
def writable(tmp_path, plain_db) -> Path:
    """A fresh copy of the fixture database the tests are allowed to mutate."""
    import shutil

    target = tmp_path / "work.db"
    shutil.copyfile(plain_db, target)
    return target


@pytest.fixture()
def key_hex() -> str:
    return TEST_ROOT_KEY.hex()


# Keep the tests hermetic.  The tool reads the key from --key, $WACRYPT_KEY or
# an interactive prompt, so a key exported in the developer's shell would
# otherwise follow the suite around; every test must start from nothing and
# must never reach for anything outside the temp directory pytest hands out.
@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch):
    monkeypatch.delenv("WACRYPT_KEY", raising=False)
