"""Migration: the dry-run contract, and the prefix bug v1 shipped with.

``wacrypt migrate 99900011122 99900077733`` must leave ``999000111220`` — a
completely different account whose number happens to start with the same
eleven digits — untouched, everywhere, in every column.
"""

from __future__ import annotations

import pytest

from wacrypt import (
    MigrationError,
    apply_migration,
    plan_migration,
    rename_media_directories,
    sanitize_number,
)
from wacrypt import count, open_db

OWNER = "99900011122"
CONFUSABLE = "999000111220"
NEW = "99900077733"


@pytest.fixture()
def rw(writable):
    conn = open_db(writable, read_only=False)
    try:
        yield conn
    finally:
        conn.close()


class TestSanitize:
    @pytest.mark.parametrize(
        "given,expected",
        [
            ("99900077733", NEW),
            ("+99900077733", NEW),
            ("0099900077733", NEW),
            (" 999 0007 7733 ", NEW),
            ("999-0007-7733", NEW),
            ("(999) 0007.7733", NEW),
        ],
    )
    def test_normalises(self, given, expected):
        assert sanitize_number(given) == expected

    @pytest.mark.parametrize("given", ["abc", "9665abc", "", "123456", "1" * 21])
    def test_refuses_nonsense(self, given):
        with pytest.raises(MigrationError):
            sanitize_number(given)


class TestPlan:
    """The plan must be computed without touching a single row."""

    def test_plan_writes_nothing(self, rw):
        before = _snapshot(rw)
        plan = plan_migration(rw, OWNER, NEW, suffix=OWNER[-2:])
        assert plan.identity_rows > 0
        assert _snapshot(rw) == before, "planning must not modify the database"

    def test_finds_the_own_jid_rows(self, rw):
        plan = plan_migration(rw, OWNER, NEW)
        # the bare jid plus the .0:5 device row
        assert plan.identity_rows == 2

    def test_finds_the_text_references(self, rw):
        plan = plan_migration(rw, OWNER, NEW)
        by_column = {(c.table, c.column): c.rows for c in plan.changes}
        assert by_column[("message_media", "file_path")] == 1
        assert by_column[("message_media", "media_caption")] == 1

    def test_does_not_count_the_confusable_number(self, rw):
        plan = plan_migration(rw, OWNER, NEW)
        for change in plan.changes:
            for row_id in change.row_ids:
                value = rw.execute(
                    f'SELECT "{change.column}" FROM "{change.table}" WHERE rowid = ?',
                    (row_id,),
                ).fetchone()[0]
                # The row may hold both numbers; it must hold the real one too.
                assert OWNER in str(value)

    def test_same_number_is_refused(self, rw):
        with pytest.raises(MigrationError, match="same"):
            plan_migration(rw, OWNER, OWNER)

    def test_a_foreign_number_is_reported_as_empty(self, rw):
        plan = plan_migration(rw, "12345678901", NEW)
        assert plan.empty
        assert plan.notes


class TestApply:
    def test_migrates_the_own_jid_rows(self, rw):
        plan = plan_migration(rw, OWNER, NEW)
        applied = apply_migration(rw, plan)
        assert applied["jid"] == 2

        users = {
            row[0]
            for row in rw.execute("SELECT DISTINCT user FROM jid WHERE user IN (?,?)",
                                  (OWNER, NEW))
        }
        assert users == {NEW}
        assert count(rw, "jid", "user = ?", (OWNER,)) == 0

    def test_device_suffixes_are_preserved(self, rw):
        apply_migration(rw, plan_migration(rw, OWNER, NEW))
        raw = rw.execute(
            "SELECT raw_string FROM jid WHERE user = ? AND raw_string LIKE '%:%'",
            (NEW,),
        ).fetchone()[0]
        assert raw == f"{NEW}.0:5@s.whatsapp.net"

    def test_the_confusable_account_is_untouched(self, rw):
        """The regression test.  A prefix-matching implementation fails here."""
        apply_migration(rw, plan_migration(rw, OWNER, NEW, include_text=True))

        assert count(rw, "jid", "user = ?", (CONFUSABLE,)) == 1
        assert count(rw, "jid", "user = ?", (NEW,)) == 2

        media = rw.execute("SELECT media_caption FROM message_media").fetchone()[0]
        assert f"{CONFUSABLE}@s.whatsapp.net" in media
        assert f"{NEW}@s.whatsapp.net" in media
        assert CONFUSABLE not in media.replace(f"{CONFUSABLE}@s.whatsapp.net", "")

    def test_a_row_holding_both_numbers_is_partly_rewritten(self, rw):
        """REPLACE() would corrupt the longer number inside a shared row."""
        apply_migration(rw, plan_migration(rw, OWNER, NEW, include_text=True))
        caption = rw.execute("SELECT media_caption FROM message_media").fetchone()[0]
        assert caption == (
            f"holiday photo from {NEW}@s.whatsapp.net and {CONFUSABLE}@s.whatsapp.net"
        )

    def test_file_paths_are_rewritten(self, rw):
        apply_migration(rw, plan_migration(rw, OWNER, NEW))
        path = rw.execute("SELECT file_path FROM message_media").fetchone()[0]
        assert path == f"Media/{NEW}@s.whatsapp.net/thumb/{OWNER}-1.jpg".replace(
            OWNER, NEW, 1
        )

    def test_the_shorter_neighbour_is_untouched(self, rw):
        """A number that is a strict prefix of ours must survive too.

        This is the opposite direction from the confusable-account case: here
        the row holds *less* than the owner's number, so it is reached only by
        an identity match that is too loose (``LIKE '99900011122%'`` against a
        ten-digit ``user`` would not, but a trailing-``%`` written the other
        way round, or a ``REPLACE`` on a substring, would).
        """
        shorter = OWNER[:10]
        assert count(rw, "jid", "user = ?", (shorter,)) == 1, "fixture"
        before = rw.execute(
            "SELECT user, raw_string FROM jid WHERE user = ?", (shorter,)
        ).fetchone()

        apply_migration(rw, plan_migration(rw, OWNER, NEW))

        assert count(rw, "jid", "user = ?", (shorter,)) == 1
        assert rw.execute(
            "SELECT user, raw_string FROM jid WHERE user = ?", (shorter,)
        ).fetchone() == before, "the ten-digit neighbour was rewritten"
        # …and no copy of it was manufactured under the new number either.
        assert count(rw, "jid", "user = ?", (NEW[:10],)) == 0

    def test_database_survives(self, rw):
        apply_migration(rw, plan_migration(rw, OWNER, NEW))
        assert rw.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        # every chat still joins to a jid
        joined = rw.execute(
            "SELECT COUNT(*) FROM chat c JOIN jid j ON j._id = c.jid_row_id"
        ).fetchone()[0]
        assert joined == count(rw, "chat")

    def test_an_empty_plan_refuses_to_run(self, rw):
        plan = plan_migration(rw, "12345678901", NEW)
        with pytest.raises(MigrationError, match="nothing"):
            apply_migration(rw, plan)


class TestContentScope:
    """What a restore needs, versus what is simply the user's own history.

    Rewriting every message that quotes the old number would edit the chat log
    nobody asked to edit, so it is off unless requested — and both halves are
    reported in the plan either way.
    """

    def test_the_plan_reports_both_halves(self, rw):
        plan = plan_migration(rw, OWNER, NEW)
        # restore: file_path + media_name.  content: media_caption.
        assert plan.restore_rows == 2
        assert plan.content_rows == 1
        assert plan.total_rows == 3

    def test_only_restore_critical_rows_are_selected_by_default(self, rw):
        plan = plan_migration(rw, OWNER, NEW)
        assert {c.column for c in plan.selected} == {"file_path", "media_name"}
        assert plan.include_text is False

    def test_rewrite_text_selects_everything(self, rw):
        plan = plan_migration(rw, OWNER, NEW, include_text=True)
        assert {c.column for c in plan.selected} == {"file_path", "media_name",
                                                     "media_caption"}
        assert plan.include_text is True

    def test_the_plan_says_so(self, rw):
        plan = plan_migration(rw, OWNER, NEW)
        assert any("--rewrite-text" in note for note in plan.notes)

    def test_by_default_chat_content_is_left_alone(self, rw):
        apply_migration(rw, plan_migration(rw, OWNER, NEW))
        caption = rw.execute("SELECT media_caption FROM message_media").fetchone()[0]
        assert f"{OWNER}@s.whatsapp.net" in caption, "history should be untouched"
        assert f"{NEW}@s.whatsapp.net" not in caption
        # …but the attachment still resolves under the new number.
        assert f"{NEW}@s.whatsapp.net" in rw.execute(
            "SELECT file_path FROM message_media"
        ).fetchone()[0]

    def test_with_rewrite_text_the_content_moves_too(self, rw):
        apply_migration(rw, plan_migration(rw, OWNER, NEW, include_text=True))
        caption = rw.execute("SELECT media_caption FROM message_media").fetchone()[0]
        assert f"{OWNER}@s.whatsapp.net" not in caption
        assert f"{NEW}@s.whatsapp.net" in caption

    def test_identity_rows_are_always_applied(self, rw):
        apply_migration(rw, plan_migration(rw, OWNER, NEW))
        assert count(rw, "jid", "user = ?", (OWNER,)) == 0
        assert count(rw, "jid", "user = ?", (NEW,)) == 2

    def test_the_split_survives_serialisation(self, rw):
        payload = plan_migration(rw, OWNER, NEW).as_dict()
        assert payload["restore_rows"] == 2
        assert payload["content_rows"] == 1
        assert payload["include_text"] is False
        scopes = {change["scope"] for change in payload["changes"]}
        assert scopes == {"restore", "content"}


class TestCollisions:
    @pytest.fixture()
    def collided(self, rw):
        """A backup that already contains a contact on the target number."""
        rw.execute(
            "INSERT INTO jid (user, server, agent, device, type, raw_string) "
            "VALUES (?,?,?,?,?,?)",
            (NEW, "s.whatsapp.net", 0, 0, 0, f"{NEW}@s.whatsapp.net"),
        )
        rw.commit()
        return rw

    def test_is_detected(self, collided):
        plan = plan_migration(collided, OWNER, NEW)
        assert len(plan.collisions) == 1
        assert plan.collisions[0]["raw_string"] == f"{NEW}@s.whatsapp.net"

    def test_apply_refuses_by_default(self, collided):
        plan = plan_migration(collided, OWNER, NEW)
        with pytest.raises(MigrationError, match="merge-collisions"):
            apply_migration(collided, plan)
        assert collided.execute("PRAGMA quick_check").fetchone()[0] == "ok"

    def test_apply_with_merge_removes_it(self, collided):
        plan = plan_migration(collided, OWNER, NEW)
        applied = apply_migration(collided, plan, merge_collisions=True)
        assert applied["collisions_removed"] == 1
        assert collided.execute("PRAGMA quick_check").fetchone()[0] == "ok"

    def test_no_collision_for_an_unrelated_target(self, rw):
        plan = plan_migration(rw, OWNER, "99900044455")
        assert plan.collisions == []


class TestMediaDirectories:
    def test_renames_only_matching_folders(self, tmp_path):
        target = tmp_path / "Media"
        (target / f"{OWNER}@s.whatsapp.net").mkdir(parents=True)
        (target / f"{CONFUSABLE}@s.whatsapp.net").mkdir()
        (target / "other@s.whatsapp.net").mkdir()
        (target / f"{OWNER}@s.whatsapp.net" / "thumb").mkdir()

        moved = rename_media_directories(target, OWNER, NEW, dry_run=True)
        assert len(moved) == 1
        assert (target / f"{OWNER}@s.whatsapp.net").is_dir(), "dry run moved it"

        moved = rename_media_directories(target, OWNER, NEW, dry_run=False)
        assert len(moved) == 1
        assert not (target / f"{OWNER}@s.whatsapp.net").exists()
        assert (target / f"{NEW}@s.whatsapp.net" / "thumb").is_dir()
        assert (target / f"{CONFUSABLE}@s.whatsapp.net").is_dir()

    def test_missing_root_is_named(self, tmp_path):
        with pytest.raises(MigrationError, match="no such directory"):
            rename_media_directories(tmp_path / "nope", OWNER, NEW)


def _snapshot(conn):
    return {
        "jid": count(conn, "jid"),
        "chat": count(conn, "chat"),
        "message": count(conn, "message"),
        "users": sorted(
            row[0] for row in conn.execute("SELECT user FROM jid ORDER BY _id")
        ),
        "media": sorted(
            str(row[0]) for row in conn.execute("SELECT file_path FROM message_media")
        ),
    }
