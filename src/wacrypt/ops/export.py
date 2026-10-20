"""Export conversations to files a human can actually read.

Four formats, one pipeline: ``txt`` for grepping, ``json`` and ``csv`` for
machines, and ``html`` for reading.  The HTML output is a single self
contained file with a client side search box, because the usual failure of an
export is that you cannot find anything in it.

Media is *not* copied by default.  ``--include-media`` looks for the
attachments under ``--media-root`` and copies the ones the export references,
which is opt-in because it can be tens of gigabytes.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional

from ..core import db as dbmod
from .search import iter_chat_texts

__all__ = ["ExportError", "ChatInfo", "list_chats", "export_chats"]

FORMATS = ("txt", "json", "csv", "html")


class ExportError(Exception):
    """The export could not be produced."""


@dataclass
class ChatInfo:
    chat_row: int
    label: str
    user: Optional[str]
    raw_string: Optional[str]
    subject: Optional[str]
    group_type: Optional[int]
    messages: int
    sort_timestamp: Optional[int]

    def as_dict(self) -> Dict[str, object]:
        return {
            "chat_row": self.chat_row,
            "label": self.label,
            "user": self.user,
            "raw_string": self.raw_string,
            "subject": self.subject,
            "group": bool(self.group_type),
            "messages": self.messages,
            "last_activity": dbmod.ms_to_datetime(self.sort_timestamp),
        }


def list_chats(conn: sqlite3.Connection) -> List[ChatInfo]:
    """Every chat with a display label and a message count."""
    out: List[ChatInfo] = []
    for row in dbmod.chat_rows(conn):
        subject = row.get("subject")
        raw = row.get("raw_string")
        user = row.get("user")
        label = str(subject or raw or user or f"chat {row['chat_row']}")
        out.append(
            ChatInfo(
                chat_row=int(row["chat_row"]),
                label=label,
                user=user,
                raw_string=raw,
                subject=subject,
                group_type=row.get("group_type"),
                messages=dbmod.message_count(conn, int(row["chat_row"])),
                sort_timestamp=row.get("sort_timestamp"),
            )
        )
    return out


def safe_name(value: str, limit: int = 80) -> str:
    cleaned = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", str(value)).strip(" ._")
    return (cleaned or "chat")[:limit]


def _records(conn: sqlite3.Connection, chat: ChatInfo) -> Iterator[Dict[str, object]]:
    for item in iter_chat_texts(conn, chat.chat_row):
        text = item["text"] or ""
        caption = item.get("caption") or ""
        kind = item.get("mime") or ""
        name = item.get("media_name")
        if not text:
            if caption:
                text = caption
            elif name:
                text = f"[{kind or 'media'}] {name}"
            elif kind:
                text = f"[{kind}]"
            else:
                text = f"[message type {item.get('type')}]"
        yield {
            "chat": chat.label,
            "chat_row": chat.chat_row,
            "when": dbmod.ms_to_datetime(item["timestamp"]),
            "timestamp": item["timestamp"],
            "sender": "me" if item["from_me"] else (item["sender"] or "unknown"),
            "from_me": bool(item["from_me"]),
            "text": text,
            "mime": kind,
            "media_name": name,
            "file_size": item.get("file_size"),
        }


def export_chats(
    conn: sqlite3.Connection,
    chats: Iterable[ChatInfo],
    out_dir: "str | Path",
    fmt: str = "html",
    *,
    limit: Optional[int] = None,
    media_root: Optional[Path] = None,
    include_media: bool = False,
) -> List[Path]:
    """Write one file per chat (or one file for ``html``/``json``)."""
    if fmt not in FORMATS:
        raise ExportError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")

    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    selected = list(chats)
    if not selected:
        raise ExportError("no chats selected")

    bundle: List[Dict[str, object]] = []

    for chat in selected:
        records = list(_records(conn, chat))
        if limit:
            records = records[-limit:]

        if fmt in ("html", "json"):
            # Both formats want every chat in one document.  (Writing the
            # aggregate json without this used to produce an empty list.)
            bundle.append({"chat": chat.as_dict(), "messages": records})

        if fmt == "html":
            continue
        stem = f"{chat.chat_row}_{safe_name(chat.label)}"
        if fmt == "json":
            path = target / f"{stem}.json"
            path.write_text(
                json.dumps(bundle[-1], indent=2, ensure_ascii=False), encoding="utf-8"
            )
        elif fmt == "csv":
            path = target / f"{stem}.csv"
            _write_csv(path, records)
        else:
            path = target / f"{stem}.txt"
            _write_txt(path, chat, records)
        written.append(path)

    if fmt == "html":
        path = target / "chats.html"
        _write_html(path, bundle)
        written.append(path)
    elif fmt == "json":
        path = target / "chats.json"
        path.write_text(
            json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        written.append(path)

    if include_media and media_root is not None:
        copied = _copy_media(conn, selected, media_root, target / "media")
        written.extend(copied)

    return written


def _write_txt(path: Path, chat: ChatInfo, records: List[Dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        handle.write(f"Chat: {chat.label}\n")
        if chat.raw_string:
            handle.write(f"JID:  {chat.raw_string}\n")
        handle.write(f"Messages: {len(records)}\n")
        handle.write("=" * 64 + "\n\n")
        for record in records:
            handle.write(f"[{record['when']}] {record['sender']}: {record['text']}\n")


def _write_csv(path: Path, records: List[Dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["when", "sender", "text", "mime", "media_name"]
        )
        writer.writeheader()
        for record in records:
            writer.writerow({key: record.get(key, "") for key in writer.fieldnames})


def _write_html(path: Path, bundle: List[Dict[str, object]]) -> None:
    """One self contained HTML file with a client side search box."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    template_dir = Path(__file__).resolve().parent.parent / "export_templates"
    environment = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    total = sum(len(entry["messages"]) for entry in bundle)

    # The data goes inside <script type="application/json">, so "<" must not
    # survive verbatim: a message containing "</script>" would otherwise end
    # the block and turn the chat history into markup.
    payload = json.dumps(bundle, ensure_ascii=False).replace("<", "\\u003c")

    html = environment.get_template("chats.html.j2").render(
        chats=bundle,
        payload=payload,
        total_messages=total,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )
    path.write_text(html, encoding="utf-8")


def _copy_media(
    conn: sqlite3.Connection, chats: List[ChatInfo], media_root: Path, out_dir: Path
) -> List[Path]:
    """Copy the attachments the selected chats reference, when they exist."""
    if not dbmod.table_exists(conn, "message_media"):
        return []
    columns = dbmod.column_names(conn, "message_media")
    if "file_path" not in columns:
        return []

    base = Path(media_root).expanduser()
    if not base.is_dir():
        raise ExportError(f"--media-root {base} does not exist")

    wanted = {chat.chat_row for chat in chats}
    copied: List[Path] = []
    for row in conn.execute(
        "SELECT mm.file_path FROM message_media mm "
        "JOIN message m ON m._id = mm.message_row_id "
        "WHERE mm.file_path IS NOT NULL AND m.chat_row_id IN (%s)"
        % ",".join("?" * len(wanted)),
        tuple(wanted),
    ).fetchall():
        relative = str(row[0]).lstrip("/")
        source = base / relative
        if not source.is_file():
            continue
        destination = out_dir / Path(relative).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(source, destination)
            copied.append(destination)
    return copied
