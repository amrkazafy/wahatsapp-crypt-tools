"""Exporting conversations to files a human can read."""

from __future__ import annotations

import json

import pytest
from wacrypt import ExportError, export_chats, list_chats, safe_name



def _chats(conn):
    return list_chats(conn)


def test_chats_are_listed_with_a_label_and_a_count(conn):
    chats = _chats(conn)
    assert {chat.label for chat in chats} == {
        "99900011122@s.whatsapp.net",
        "99900099988@s.whatsapp.net",
        "Team",
    }
    team = next(chat for chat in chats if chat.label == "Team")
    assert team.messages == 1
    assert team.group_type


def test_txt(conn, tmp_path):
    written = export_chats(conn, _chats(conn), tmp_path / "out", "txt")
    assert len(written) == 3
    text = (tmp_path / "out" / "3_Team.txt").read_text(encoding="utf-8")
    assert "Chat: Team" in text
    assert "Messages: 1" in text
    assert "photo from" in text


def test_csv(conn, tmp_path):
    export_chats(conn, _chats(conn), tmp_path / "out", "csv")
    lines = (tmp_path / "out" / "3_Team.csv").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "when,sender,text,mime,media_name"
    assert len(lines) == 2


def test_json(conn, tmp_path):
    export_chats(conn, _chats(conn), tmp_path / "out", "json")
    bundle = json.loads((tmp_path / "out" / "chats.json").read_text(encoding="utf-8"))
    assert len(bundle) == 3
    self_chat = next(entry for entry in bundle if entry["chat"]["chat_row"] == 1)
    assert len(self_chat["messages"]) == 61
    assert self_chat["messages"][0]["sender"] == "me"


def test_html(conn, tmp_path):
    export_chats(conn, _chats(conn), tmp_path / "out", "html")
    html = (tmp_path / "out" / "chats.html").read_text(encoding="utf-8")
    assert "<title>WhatsApp export" in html
    assert "note to self 0" in html
    assert "id=\"data\"" in html
    assert "Search every message" in html


def test_html_survives_a_message_that_closes_the_script_tag(conn, tmp_path):
    """A chat containing '</script>' must not break out of the data block."""
    from wacrypt import _write_html

    bundle = [
        {
            "chat": {"label": "<img src=x>", "raw_string": "a&b", "last_activity": ""},
            "messages": [{"text": "</script><script>alert(1)</script>", "when": "2024",
                          "from_me": False, "sender": "x", "mime": "", "chat": ""}],
        }
    ]
    path = tmp_path / "x.html"
    _write_html(path, bundle)
    html = path.read_text(encoding="utf-8")

    assert "alert(1)" in html, "the payload should still be present, encoded"
    # The injected markup must not survive as real markup: < is written out as
    # the ‹ sequence in the JSON payload, so the file has exactly one
    # <script> — the one we emit ourselves.
    assert "<script>alert(1)</script>" not in html
    assert html.count("<script>") == 1
    assert "<img src=x>" not in html.split("<body>")[0], "label must be escaped"


def test_a_single_chat_selection(conn, tmp_path):
    chats = [chat for chat in _chats(conn) if chat.label == "Team"]
    written = export_chats(conn, chats, tmp_path / "one", "txt")
    assert len(written) == 1


def test_limit_keeps_the_tail(conn, tmp_path):
    chats = [chat for chat in _chats(conn) if chat.label.endswith("@s.whatsapp.net")]
    export_chats(conn, chats, tmp_path / "out", "json", limit=5)
    bundle = json.loads((tmp_path / "out" / "chats.json").read_text(encoding="utf-8"))
    for entry in bundle:
        assert len(entry["messages"]) == 5


def test_unknown_format_is_refused(conn, tmp_path):
    with pytest.raises(ExportError, match="unknown format"):
        export_chats(conn, _chats(conn), tmp_path, "pdf")


def test_no_chats_is_an_error(conn, tmp_path):
    with pytest.raises(ExportError, match="no chats"):
        export_chats(conn, [], tmp_path, "txt")


def test_media_copy_is_opt_in_and_reports_missing_files(conn, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    written = export_chats(
        conn, _chats(conn), tmp_path / "out", "txt", media_root=root, include_media=True
    )
    # The fixture's media file does not exist on disk, so nothing is copied and
    # the export still succeeds.
    assert all(path.suffix == ".txt" for path in written)


def test_missing_media_root_is_named(conn, tmp_path):
    with pytest.raises(ExportError, match="does not exist"):
        export_chats(
            conn, _chats(conn), tmp_path / "out", "txt",
            media_root=tmp_path / "nope", include_media=True,
        )


def test_safe_name_strips_path_separators():
    assert "/" not in safe_name("a/b\\c:d")
    assert safe_name("   ") == "chat"
    assert len(safe_name("x" * 500)) == 80
