"""Owner detection.

v1 guessed the account holder from the header suffix and listed ten equally
plausible numbers.  The signal that actually works is the *Message yourself*
chat: it is the only private chat where one side wrote dozens of messages and
the other replied once.
"""

from __future__ import annotations

import pytest

from wacrypt.core import db as dbmod
from wacrypt.ops.migrate import apply_migration, plan_migration

OWNER = "99900011122"
NEW = "99900077733"
# Derived, never typed: the header suffix is just the number's last two digits.
SUFFIX = OWNER[-2:]


@pytest.fixture()
def rw(writable):
    conn = dbmod.open_db(writable, read_only=False)
    try:
        yield conn
    finally:
        conn.close()


def test_the_self_chat_wins(conn):
    report = dbmod.owner_report(conn, suffix=SUFFIX)
    assert report["number"] == OWNER
    assert report["confidence"] == "high"


def test_the_reason_is_stated(conn):
    report = dbmod.owner_report(conn, suffix=SUFFIX)
    assert "self chat" in report["reason"]
    assert report["candidates"][0]["sent"] == 60
    assert report["candidates"][0]["received"] == 1


def test_a_balanced_chat_is_never_the_owner(conn):
    """The 20-message two-way conversation must rank below the self chat."""
    report = dbmod.owner_report(conn, suffix=SUFFIX)
    ranked = [entry["number"] for entry in report["candidates"]]
    assert ranked[0] == OWNER
    assert "99900099988" not in ranked[:1]


def test_candidates_are_ranked_by_evidence(conn):
    candidates = dbmod.find_owner_candidates(conn, suffix=SUFFIX)
    scores = [entry.score for entry in candidates]
    assert scores == sorted(scores, reverse=True)
    assert candidates[0].number == OWNER


def test_every_candidate_carries_a_reason(conn):
    candidates = dbmod.find_owner_candidates(conn, suffix=SUFFIX)
    assert candidates[0].reasons, "the top candidate must say why"
    assert any("self chat" in reason for reason in candidates[0].reasons)


def test_the_suffix_is_a_reason_not_a_verdict(conn):
    """Matching the header suffix must not turn a scoreless chat into an owner."""
    for candidate in dbmod.find_owner_candidates(conn, suffix=SUFFIX):
        if candidate.score == 0:
            assert not any("self chat" in reason for reason in candidate.reasons)


class TestThresholds:
    def test_a_handful_of_messages_is_not_enough(self):
        assert not dbmod._looks_like_self_chat(sent=3, received=0)

    def test_a_conversation_is_not_a_self_chat(self):
        assert not dbmod._looks_like_self_chat(sent=60, received=30)

    def test_a_replied_self_chat_is_not_one(self):
        assert not dbmod._looks_like_self_chat(sent=60, received=10)

    def test_the_real_shape_passes(self):
        assert dbmod._looks_like_self_chat(sent=60, received=1)
        assert dbmod._looks_like_self_chat(sent=815, received=1)
        assert dbmod._looks_like_self_chat(sent=20, received=1)


class TestDegenerateCases:
    def test_no_private_chat_at_all(self, rw):
        rw.execute("DELETE FROM message")
        rw.execute("DELETE FROM chat")
        rw.commit()
        report = dbmod.owner_report(rw, suffix=SUFFIX)
        assert report["number"] is None
        assert report["confidence"] == "none"
        assert report["candidates"] == []

    def test_no_self_chat_falls_back_to_the_list(self, rw):
        rw.execute("DELETE FROM message")
        rw.commit()
        report = dbmod.owner_report(rw, suffix=SUFFIX)
        assert report["number"] is None
        assert report["confidence"] in ("low", "none")
        assert report["candidates"], "it should still show what it found"

    def test_a_database_without_the_tables(self, tmp_path):
        import sqlite3

        path = tmp_path / "empty.db"
        sqlite3.connect(str(path)).close()
        conn = dbmod.open_db(path, read_only=True)
        try:
            assert dbmod.find_owner_candidates(conn) == []
            assert dbmod.owner_report(conn)["confidence"] == "none"
        finally:
            conn.close()


def test_migration_moves_the_self_chat(rw):
    """After migrating, the same detector must find the NEW number."""
    apply_migration(rw, plan_migration(rw, OWNER, "99900077733"))
    report = dbmod.owner_report(rw, suffix=NEW[-2:])
    assert report["number"] == "99900077733"
    assert report["confidence"] == "high"
