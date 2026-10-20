"""Move a backup from one phone number to another.

The first version of this tool rewrote the ``jid`` table and stopped there,
which is why a migrated backup came back with broken mentions and dead media
links.  This implementation differs in three deliberate ways.

**It asks the database what it holds.**  ``group_participants`` is now
``participant_user``, ``contact`` is gone, and every year brings new tables.
Rather than naming tables, the planner scans every text column and reports
exactly which rows mention the number.

**It never matches a prefix, and never replaces a substring.**  This is the
subtle one.  ``LIKE '99900011122%'`` also matches ``999000111220`` — someone
else's account.  But so does SQLite's ``REPLACE()``, even when the ``WHERE``
clause correctly excluded that row, because ``REPLACE`` will happily rewrite
the leading digits of any longer number sharing the same text.  So:

* rows are selected with a broad anchor (the number appears at all), then
* filtered and rewritten in Python with ``(?<!\\d)number(?!\\d)``, which only
  matches the number when it is not glued to another digit.

A shorter number such as ``965554163`` is likewise never touched, because
that would require the *full* 11 digits to appear as a standalone token.

**It previews.**  :func:`plan_migration` produces a description of the change
without writing anything; only :func:`apply_migration` opens a transaction.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..core import db as dbmod

__all__ = [
    "MigrationError",
    "PlannedChange",
    "MigrationPlan",
    "sanitize_number",
    "plan_migration",
    "apply_migration",
    "rename_media_directories",
]

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
    for table in dbmod.table_names(conn):
        for name, declared in dbmod.columns(conn, table).items():
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

    if not dbmod.table_exists(conn, "jid"):
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
        plan.tables_scanned = len(dbmod.table_names(conn))

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

    with dbmod.transaction(conn):
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
