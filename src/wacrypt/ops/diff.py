"""Compare two backups and say what changed between them.

Row ids are useless here: WhatsApp renumbers ``_id`` between backups, so the
same message gets a different id in each file.  Messages are matched on
``key_id`` when the schema has it (it is WhatsApp's own message id and is
stable across backups) and fall back to ``(timestamp, from_me, text)`` when
it does not.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..core import db as dbmod

__all__ = ["DiffError", "ChatDiff", "BackupDiff", "diff_backups"]


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
    return dbmod.table_exists(conn, table) and column in dbmod.column_names(conn, table)


def _message_fingerprint(conn: sqlite3.Connection, use_key: bool) -> str:
    return "key_id" if use_key and _has(conn, "message", "key_id") else "timestamp"


def _chat_index(conn: sqlite3.Connection) -> Dict[str, Tuple[str, int]]:
    """``{jid: (label, chat row)}``."""
    out: Dict[str, Tuple[str, int]] = {}
    for row in dbmod.chat_rows(conn):
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
    result.total_old_messages = dbmod.count(old_conn, "message")
    result.total_new_messages = dbmod.count(new_conn, "message")

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
