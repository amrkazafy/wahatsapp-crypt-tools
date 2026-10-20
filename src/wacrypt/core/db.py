"""SQLite plumbing: safe transactions and schema introspection.

Two rules drive this module.

**Never assume a table exists.**  A WhatsApp backup from 2022 and one from
2026 do not share a schema: ``group_participants`` became ``participant_user``,
``contact`` is gone, and whole families of tables appear and vanish.  Every
helper here asks the database what it actually contains before it uses it.

**Never leave a half written database.**  Every mutation runs inside
``BEGIN IMMEDIATE`` and only leaves through ``COMMIT`` or ``ROLLBACK``, so an
interrupted migration cannot corrupt a 200 MB backup.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence

__all__ = [
    "DbError",
    "open_db",
    "transaction",
    "table_names",
    "table_exists",
    "columns",
    "column_names",
    "OwnerCandidate",
    "find_owner_candidates",
    "owner_report",
    "chat_rows",
    "ms_to_datetime",
]

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
