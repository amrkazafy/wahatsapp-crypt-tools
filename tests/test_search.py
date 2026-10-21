"""Searching without ever exposing a decrypted file."""

from __future__ import annotations

import pytest
from wacrypt import iter_chat_texts, search, text_sources



def test_finds_a_plain_word(conn):
    hits = search(conn, "holiday")
    assert len(hits) == 1
    assert hits[0].chat == "Team"
    assert hits[0].text.startswith("holiday photo from")


def test_is_case_insensitive_by_default(conn):
    assert len(search(conn, "HI THERE", limit=500)) > 0


def test_case_sensitivity_is_opt_in(conn):
    assert search(conn, "hi there", limit=500)
    assert not search(conn, "HI THERE", limit=500, case_sensitive=True)


def test_regex_mode(conn):
    hits = search(conn, r"note to self 1\d$", regex=True, limit=100)
    assert len(hits) == 10  # "10".."19" and nothing else

def test_regex_is_not_needed_for_ordinary_text(conn):
    assert search(conn, "note to self 7", limit=10)

def test_a_bad_pattern_is_reported(conn):
    import re

    with pytest.raises(re.error):
        search(conn, "[unclosed", regex=True)


def test_the_chat_filter_narrows(conn):
    everything = search(conn, "hi there", limit=1000)
    narrowed = search(conn, "hi there", chat="99900099988", limit=1000)
    assert narrowed
    assert all("99900099988" in hit.chat for hit in narrowed)
    assert len(narrowed) <= len(everything)


def test_the_sender_filter_narrows(conn):
    hits = search(conn, "hi there", sender="99900099988", limit=1000)
    assert hits
    assert all(hit.sender == "99900099988" for hit in hits)


def test_date_filters_accept_a_bare_day(conn):
    assert search(conn, "note to self", since="2030-01-01", limit=1000) == []
    during = search(conn, "note to self", since="2024-01-01", limit=1000)
    assert len(during) == 60  # the self chat's notes
    until = search(conn, "note to self", until="2023-12-31", limit=1000)
    assert until == []


def test_an_unparseable_date_is_named(conn):
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        search(conn, "x", since="last tuesday")


def test_limit_is_respected(conn):
    assert len(search(conn, "note to self", limit=5)) == 5


def test_context_expands_the_match(conn):
    """Context is measured in characters either side of the literal match."""
    [hit] = search(conn, "photo", context=6)
    assert hit.text == "…liday photo from …"


def test_captions_are_searched_too(conn):
    hits = search(conn, "photo from")
    assert hits and hits[0].table == "caption"


def test_text_sources_are_discovered_not_assumed(conn):
    names = {(item["table"], item["column"]) for item in text_sources(conn)}
    assert ("message", "text_data") in names
    assert ("message_media", "media_caption") in names


def test_hits_serialise(conn):
    hit = search(conn, "holiday")[0]
    payload = hit.as_dict()
    assert payload["chat"] == "Team"
    assert payload["table"] == "caption"
    assert isinstance(payload["timestamp"], int)


def test_no_matches_is_an_empty_list(conn):
    assert search(conn, "zzzz-not-present") == []


def test_iter_chat_texts_walks_a_chat(conn):
    rows = list(iter_chat_texts(conn, 1))
    assert len(rows) == 61  # 60 notes + the echo
    assert all(row["from_me"] is True for row in rows[:60])
    assert rows[60]["text"] == "echo"
