"""Search a backup without ever opening it by hand.

The point of this module is that the user never sees a decrypted database:
``wacrypt search`` decrypts (or reads the cache), runs the query, and throws
the working copy away.

Text lives in more than one place depending on the schema version, so this
asks the database where it is instead of assuming ``message.text_data``:
long messages moved to ``message_text`` in later versions, and captions live
in ``message_media``.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterator, List, Optional

from ..core import db as dbmod

__all__ = ["SearchHit", "search", "text_sources"]


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
        return dbmod.ms_to_datetime(self.timestamp)

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
        if not dbmod.table_exists(conn, table):
            continue
        if column not in dbmod.column_names(conn, table):
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
        raise dbmod.DbError("this database has no text columns to search")

    for source in sources:
        table, column = source["table"], source["column"]
        if not dbmod.table_exists(conn, "message"):
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
    if not dbmod.table_exists(conn, "message"):
        return
    has_media = dbmod.table_exists(conn, "message_media")
    media_cols = dbmod.column_names(conn, "message_media") if has_media else []

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
