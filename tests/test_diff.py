"""Comparing two backups."""

from __future__ import annotations

import pytest

from wacrypt.core import db as dbmod
from wacrypt.ops import diff as diffmod
from wacrypt.ops.migrate import apply_migration, plan_migration

OWNER = "99900011122"
NEW = "99900077733"


@pytest.fixture()
def second(writable):
    """A second copy of the fixture database the tests may mutate."""
    import shutil

    import tempfile
    from pathlib import Path

    directory = Path(tempfile.mkdtemp())
    target = directory / "second.db"
    shutil.copyfile(writable, target)
    return target


@pytest.fixture()
def conn1(writable):
    """A writable copy of the fixture database (``conn`` is read-only)."""
    database = dbmod.open_db(writable, read_only=False)
    try:
        yield database
    finally:
        database.close()


@pytest.fixture()
def conn2(second):
    database = dbmod.open_db(second, read_only=False)
    try:
        yield database
    finally:
        database.close()


def test_identical_backups_report_nothing(conn, conn2):
    result = diffmod.diff_backups(conn, conn2, "a", "b")
    assert result.total_added == 0
    assert result.total_removed == 0
    assert result.chats == []


def test_a_new_message_is_counted(conn, conn2):
    conn2.execute(
        "INSERT INTO message (chat_row_id, sender_jid_row_id, from_me, timestamp, "
        "key_id, message_type, text_data) VALUES (2, 2, 0, 2000000000000, 'newkey', 0, 'yo')"
    )
    conn2.commit()

    result = diffmod.diff_backups(conn, conn2, "a", "b")
    assert result.total_added == 1
    assert result.total_removed == 0
    (changed,) = result.changed_chats
    assert changed.added == 1
    assert changed.new_messages == changed.old_messages + 1


def test_a_removed_message_is_counted(conn, conn2):
    conn2.execute("DELETE FROM message WHERE key_id = 'f0'")
    conn2.commit()

    result = diffmod.diff_backups(conn, conn2, "a", "b")
    assert result.total_removed == 1
    assert result.total_added == 0


def test_a_whole_chat_appearing_and_disappearing(conn, conn2):
    apply_migration(conn2, plan_migration(conn2, OWNER, NEW))

    result = diffmod.diff_backups(conn, conn2, "a", "b")
    assert len(result.new_chats) == 1
    assert len(result.removed_chats) == 1
    assert result.new_chats[0].jid == f"{NEW}@s.whatsapp.net"
    assert result.removed_chats[0].jid == f"{OWNER}@s.whatsapp.net"
    # The messages moved rather than vanished.
    assert result.new_chats[0].added == 61
    assert result.removed_chats[0].removed == 61
    assert result.total_added == result.total_removed == 61


def test_the_key_source_is_reported(conn, conn2):
    assert diffmod.diff_backups(conn, conn2, "a", "b").key_source == "key_id"


def test_the_key_source_degrades_when_key_id_is_absent(conn1, conn2):
    conn1.execute("ALTER TABLE message RENAME COLUMN key_id TO something_else")
    conn1.commit()
    result = diffmod.diff_backups(conn1, conn2, "a", "b")
    assert result.key_source == "text"


def test_the_limit_is_applied(conn, conn2):
    for index in range(10):
        conn2.execute(
            "INSERT INTO message (chat_row_id, sender_jid_row_id, from_me, timestamp, "
            "key_id, message_type, text_data) VALUES (2, 2, 0, ?, ?, 0, 'x')",
            (2000000000000 + index, f"bulk{index}"),
        )
    conn2.commit()
    result = diffmod.diff_backups(conn, conn2, "a", "b", limit=1)
    assert len(result.chats) == 1


def test_results_serialise(conn, conn2):
    payload = diffmod.diff_backups(conn, conn2, "a", "b").as_dict()
    assert payload["old"] == "a"
    assert payload["new"] == "b"
    assert payload["chats"] == []
