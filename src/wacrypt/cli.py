"""``wacrypt`` — the command line interface."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.table import Table

from . import __version__
from .core import vault
from .core import db as dbmod
from .core import keys as keysmod
from .core.crypto import CryptoError, WrongKey, derive_backup_key, pack_from_file
from .core.header import BackupHeader, HeaderError, KeyType, read_header
from .core.session import decrypt_permanently, open_backup
from .ops import diff as diffmod
from .ops import export as exportmod
from .ops import migrate as migratemod
from .ops import search as searchmod

app = typer.Typer(
    name="wacrypt",
    help="Manage, inspect, migrate and search WhatsApp local backups "
    "(msgstore.db.crypt14 / crypt15). No wa_crypt_tools required.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
vault_app = typer.Typer(help="Manage the stored key and the decrypted cache.", no_args_is_help=True)
app.add_typer(vault_app, name="vault")

console = Console()
err_console = Console(stderr=True)


def _fail(message: str, code: int = 1) -> None:
    err_console.print(f"[bold red]error[/bold red] {message}")
    raise typer.Exit(code)


def _resolve(key: Optional[str]) -> Optional[bytes]:
    """Turn ``--key`` into bytes, failing with a readable message."""
    try:
        return keysmod.resolve_key(key, use_vault=not key, allow_prompt=not key)
    except keysmod.KeyError_ as exc:
        _fail(str(exc))


def _readable_size(value: Optional[int]) -> str:
    if value is None:
        return "—"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.2f} GB"


def _progress():
    return Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=err_console,
        transient=True,
    )


def _progress_hook(bar):
    def hook(done: int, total: int) -> None:
        task = bar.tasks[0] if bar.tasks else None
        if task is None:
            bar.add_task("", total=total)
        if total and done >= total:
            bar.update(bar.task_ids[0], completed=total)
        else:
            bar.update(bar.task_ids[0], completed=done, total=total)

    return hook


def _emit(data: dict, *, json_mode: bool, table: Optional[Table] = None) -> None:
    if json_mode:
        console.print_json(json.dumps(data))
    elif table is not None:
        console.print(table)


def _key_option() -> object:
    return typer.Option(
        None,
        "--key",
        "-k",
        help="64 hex backup key, or a path to a key file. Omit to use the "
        "keychain or a hidden prompt.",
        envvar="WACRYPT_KEY",
    )


# --------------------------------------------------------------------------- #
# info
# --------------------------------------------------------------------------- #


@app.command()
def info(
    file: Path = typer.Argument(..., exists=True, readable=True, help="Encrypted backup."),
    json_mode: bool = typer.Option(False, "--json", help="Machine readable output."),
) -> None:
    """Read the header. Needs no key and touches only the first 64 KB."""
    try:
        header = read_header(file)
    except HeaderError as exc:
        _fail(str(exc))

    table = Table(title=f"[bold]{file.name}[/bold]", show_header=False, box=None, padding=(0, 2))
    table.add_column("field", style="cyan")
    table.add_column("value")

    rows = [
        ("crypt type", f"crypt{header.crypt_type}"),
        ("key type", f"{header.key_type_name}"
         + (f" / new={KeyType.name(header.key_type_new)}" if header.key_type_new else "")),
        ("WhatsApp version", header.app_version or "—"),
        ("device model", header.device_model or "—"),
        ("jid suffix", header.jid_suffix or "—"),
        ("backup version", header.backup_version if header.backup_version is not None else "—"),
        ("migration flags", f"{len(header.features)} completed"),
        ("IV", header.iv.hex() if header.iv else "—"),
        ("header size", f"{header.header_len} bytes"),
        ("cipher starts at", f"offset {header.cipher_offset}"),
        ("encrypted payload", _readable_size(header.cipher_size)),
        ("file size", _readable_size(header.file_size)),
    ]
    if header.unknown_fields:
        rows.append(("[yellow]unknown fields[/yellow]", ", ".join(header.unknown_fields)))

    for name, value in rows:
        table.add_row(name, str(value))

    _emit(header.summary(), json_mode=json_mode, table=table)


# --------------------------------------------------------------------------- #
# decrypt
# --------------------------------------------------------------------------- #


@app.command()
def decrypt(
    file: Path = typer.Argument(..., exists=True, readable=True),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Where to write the .db."),
    key: Optional[str] = _key_option(),
    use_cache: bool = typer.Option(True, "--cache/--no-cache", help="Use the decrypted cache."),
    json_mode: bool = typer.Option(False, "--json"),
) -> None:
    """Decrypt a backup to a plain SQLite database."""
    resolved = None
    if key:
        try:
            resolved = keysmod.resolve_key(key, use_vault=False, allow_prompt=False)
        except keysmod.KeyError_ as exc:
            _fail(str(exc))

    target = output or file.with_suffix("")
    if target == file:
        _fail("refusing to overwrite the encrypted backup")

    try:
        with _progress() as bar:
            bar.add_task(file.name, total=1)
            header = decrypt_permanently(
                file, target, resolved, use_cache=use_cache, progress=_progress_hook(bar)
            )
    except (WrongKey, CryptoError, HeaderError) as exc:
        _fail(str(exc))

    payload = {
        "input": str(file),
        "output": str(target),
        "size": target.stat().st_size,
        "crypt_type": header.crypt_type,
    }
    if json_mode:
        console.print_json(json.dumps(payload))
    else:
        console.print(
            f"[green]ok[/green] decrypted -> [bold]{target}[/bold] "
            f"({_readable_size(payload['size'])})"
        )


# --------------------------------------------------------------------------- #
# encrypt
# --------------------------------------------------------------------------- #


@app.command("encrypt")
def encrypt_cmd(
    database: Path = typer.Argument(..., exists=True, readable=True, help="Plain SQLite file."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    key: Optional[str] = _key_option(),
    crypt_type: int = typer.Option(15, "--type", min=14, max=15),
    jid_suffix: Optional[str] = typer.Option(None, "--jid", help="Last two digits of the number."),
    wa_version: Optional[str] = typer.Option(None, "--wa-version"),
    keep_iv: bool = typer.Option(True, "--reuse-iv/--new-iv", help="Reuse the IV from --like."),
    like: Optional[Path] = typer.Option(
        None, "--like", help="Copy the header of an existing backup (recommended)."
    ),
    json_mode: bool = typer.Option(False, "--json"),
) -> None:
    """Encrypt a plain SQLite database into a crypt15 backup."""
    if not dbmod.open_db(database, read_only=True).execute("SELECT 1").fetchone():
        _fail(f"{database} is not a SQLite database")

    source_header = None
    if like is not None:
        try:
            source_header = read_header(like)
        except HeaderError as exc:
            _fail(str(exc))

    resolved = None
    try:
        resolved = keysmod.resolve_key(key, use_vault=True, allow_prompt=True)
    except keysmod.KeyError_ as exc:
        _fail(str(exc))

    aes_key = derive_backup_key(resolved)

    if source_header is not None:
        prefix = source_header.prefix
        iv = source_header.iv if keep_iv else None
        header = source_header
    else:
        iv = None
        header = BackupHeader(
            path=database,
            file_size=database.stat().st_size,
            crypt_type=crypt_type,
            header_len=0,
            cipher_offset=0,
            prefix=b"",
            iv=None,
            app_version=wa_version,
            jid_suffix=jid_suffix,
        )
        from .core.header import build_prefix

        header.prefix = build_prefix(
            iv=os.urandom(16),
            app_version=wa_version,
            jid_suffix=jid_suffix,
            backup_version=source_header.backup_version if source_header else None,
            features=source_header.features if source_header else [],
        )

    target = output or database.with_suffix(f".crypt{crypt_type}")
    try:
        with _progress() as bar:
            bar.add_task(database.name, total=1)
            pack_from_file(
                database, aes_key, target, header, iv=iv, progress=_progress_hook(bar)
            )
    except (WrongKey, CryptoError, HeaderError) as exc:
        _fail(str(exc))

    payload = {"input": str(database), "output": str(target), "size": target.stat().st_size}
    if json_mode:
        console.print_json(json.dumps(payload))
    else:
        console.print(f"[green]ok[/green] encrypted -> [bold]{target}[/bold] "
                      f"({_readable_size(payload['size'])})")


# --------------------------------------------------------------------------- #
# inspect
# --------------------------------------------------------------------------- #


@app.command()
def inspect(
    file: Path = typer.Argument(..., exists=True, readable=True),
    key: Optional[str] = _key_option(),
    use_cache: bool = typer.Option(True, "--cache/--no-cache"),
    json_mode: bool = typer.Option(False, "--json"),
) -> None:
    """Owner number, chat and message counts, date range, footprint."""
    resolved = None
    if key:
        try:
            resolved = keysmod.resolve_key(key, use_vault=False, allow_prompt=False)
        except keysmod.KeyError_ as exc:
            _fail(str(exc))

    try:
        with open_backup(file, resolved, use_cache=use_cache) as (header, db_path, state):
            conn = dbmod.open_db(db_path, read_only=True)
            try:
                owner = dbmod.owner_report(conn, header.jid_suffix)
                stats = _database_stats(conn)
            finally:
                conn.close()
    except (WrongKey, CryptoError, HeaderError) as exc:
        _fail(str(exc))

    payload = {"header": header.summary(), "owner": owner, "database": stats,
               "cache_hit": state.cache_hit}

    if json_mode:
        console.print_json(json.dumps(payload))
        return

    table = Table(title=f"[bold]{file.name}[/bold]", show_header=False, box=None, padding=(0, 2))
    table.add_column("field", style="cyan")
    table.add_column("value")

    confidence = {"high": "green", "medium": "yellow", "low": "red", "none": "red"}[
        str(owner["confidence"])
    ]
    table.add_row("crypt type", f"crypt{header.crypt_type}")
    table.add_row("WhatsApp version", str(header.app_version or "—"))
    table.add_row("header jid suffix", str(header.jid_suffix or "—"))
    table.add_row(
        "owner number",
        f"[{confidence}]{owner['number'] or 'unknown'}[/{confidence}] "
        f"([dim]{owner['confidence']}[/dim])",
    )
    table.add_row("why", str(owner.get("reason", "")))
    if owner["number"] is None and owner["candidates"]:
        labels = ", ".join(
            f"{entry['number']} ({entry['sent']}↑/{entry['received']}↓)"
            for entry in owner["candidates"][:10]
        )
        table.add_row("candidates", labels)
    table.add_row("chats", f"{stats['chats']:,}")
    table.add_row("messages", f"{stats['messages']:,}")
    table.add_row("earliest message", stats["first_message"])
    table.add_row("latest message", stats["last_message"])
    table.add_row("attachments", f"{stats['media']:,} ({_readable_size(stats['media_bytes'])})")
    table.add_row("database size", _readable_size(stats["db_bytes"]))
    table.add_row("from cache", "yes" if state.cache_hit else "no")
    console.print(table)


def _database_stats(conn) -> dict:
    out: dict = {
        "chats": 0,
        "messages": 0,
        "first_message": "—",
        "last_message": "—",
        "media": 0,
        "media_bytes": 0,
        "db_bytes": 0,
    }
    if dbmod.table_exists(conn, "chat"):
        out["chats"] = dbmod.count(conn, "chat")
    if dbmod.table_exists(conn, "message"):
        out["messages"] = dbmod.count(conn, "message")
        try:
            lo, hi = conn.execute(
                "SELECT MIN(timestamp), MAX(timestamp) FROM message"
            ).fetchone()
            out["first_message"] = dbmod.ms_to_datetime(lo)
            out["last_message"] = dbmod.ms_to_datetime(hi)
        except Exception:
            pass
    if dbmod.table_exists(conn, "message_media"):
        try:
            rows, size = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(file_size), 0) FROM message_media"
            ).fetchone()
            out["media"], out["media_bytes"] = int(rows or 0), int(size or 0)
        except Exception:
            pass
    out["db_bytes"] = os.path.getsize(conn.execute("PRAGMA database_list").fetchone()[2])
    return out


# --------------------------------------------------------------------------- #
# vault
# --------------------------------------------------------------------------- #


@vault_app.command("add")
def vault_add(
    key: Optional[str] = typer.Option(None, "--key", "-k", envvar="WACRYPT_KEY"),
) -> None:
    """Store the backup key in the system keychain so you never retype it."""
    try:
        resolved = keysmod.resolve_key(key, use_vault=False, allow_prompt=True)
    except keysmod.KeyError_ as exc:
        _fail(str(exc))
    if keysmod.vault_set(resolved):
        console.print(
            f"[green]ok[/green] stored in the keychain "
            f"({resolved.hex()[:6]}…{resolved.hex()[-4:]})"
        )
    else:
        _fail("the platform keychain is not available")


@vault_app.command("status")
def vault_status(json_mode: bool = typer.Option(False, "--json")) -> None:
    """Show what the keychain and the cache hold."""
    info = vault.status()
    stored = keysmod.vault_status()
    info["backup_key"] = stored
    if json_mode:
        console.print_json(json.dumps(info))
        return
    console.print(f"key in keychain : {'yes (' + stored + ')' if stored else 'no'}")
    console.print(f"cache directory : {info['cache_dir']}")
    console.print(f"cached backups  : {len(info['entries'])}")
    leaks = 0
    for entry in info["entries"]:
        leaked = bool(entry.get("plaintext_on_disk"))
        leaks += leaked
        console.print(
            f"  • {entry['fingerprint']}  {_readable_size(entry.get('cache_bytes'))}"
            + ("  [red]plaintext on disk[/red]" if leaked else "  encrypted only")
        )
    console.print(
        "plaintext on disk: "
        + (
            f"[red]yes — {leaks} leftover database file(s), run "
            "`wacrypt vault purge`[/red]"
            if leaks
            else "[green]none[/green] (databases are decrypted per command and "
            "removed afterwards)"
        )
    )


@vault_app.command("purge")
def vault_purge(
    fingerprint: Optional[str] = typer.Option(None, "--fingerprint", "-f"),
) -> None:
    """Delete every cached database, encrypted or otherwise."""
    removed = vault.purge(fingerprint)
    console.print(f"[green]ok[/green] removed {removed} file(s)")


@vault_app.command("forget")
def vault_forget() -> None:
    """Delete the backup key from the keychain."""
    if keysmod.vault_delete():
        console.print("[green]ok[/green] key removed from the keychain")
    else:
        _fail("nothing to remove, or the keychain refused")


# --------------------------------------------------------------------------- #
# search
# --------------------------------------------------------------------------- #


@app.command()
def search(
    file: Path = typer.Argument(..., exists=True, readable=True),
    pattern: str = typer.Argument(..., help="Text to find. With --regex it is an expression."),
    regex: bool = typer.Option(False, "--regex", "-r", help="Treat the pattern as a regular expression."),
    case_sensitive: bool = typer.Option(False, "--case-sensitive", "-s"),
    chat: Optional[str] = typer.Option(None, "--chat", "-c", help="Only chats whose name/JID contains this."),
    sender: Optional[str] = typer.Option(None, "--sender", help="Only senders containing this."),
    since: Optional[str] = typer.Option(None, "--since", help="Earliest date, YYYY-MM-DD."),
    until: Optional[str] = typer.Option(None, "--until", help="Latest date, YYYY-MM-DD."),
    context: int = typer.Option(0, "--context", min=0, help="Show N characters either side of the match."),
    limit: int = typer.Option(50, "--limit", "-n", min=1, max=10000),
    key: Optional[str] = _key_option(),
    use_cache: bool = typer.Option(True, "--cache/--no-cache"),
    json_mode: bool = typer.Option(False, "--json"),
) -> None:
    """Find messages without ever seeing a decrypted file."""
    resolved = _resolve(key) if key else None

    try:
        with open_backup(file, resolved, use_cache=use_cache) as (header, db_path, _state):
            conn = dbmod.open_db(db_path, read_only=True)
            try:
                hits = searchmod.search(
                    conn, pattern,
                    regex=regex, chat=chat, sender=sender, since=since, until=until,
                    limit=limit, case_sensitive=case_sensitive, context=context,
                )
            finally:
                conn.close()
    except (WrongKey, CryptoError, HeaderError, dbmod.DbError) as exc:
        _fail(str(exc))

    if json_mode:
        console.print_json(json.dumps([hit.as_dict() for hit in hits]))
        return

    if not hits:
        console.print(f"[yellow]no matches[/yellow] for [bold]{pattern}[/bold]")
        raise typer.Exit(0)

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("when", style="dim", no_wrap=True)
    table.add_column("chat", max_width=34)
    table.add_column("from", style="cyan", max_width=18)
    table.add_column("message")

    for hit in hits:
        table.add_row(hit.when(), hit.chat[:34], hit.sender[:18], hit.text)

    console.print(table)
    console.print(f"[dim]{len(hits)} match(es)[/dim]")


# --------------------------------------------------------------------------- #
# export
# --------------------------------------------------------------------------- #


@app.command()
def export(
    file: Path = typer.Argument(..., exists=True, readable=True),
    out_dir: Path = typer.Option("./chat_export", "--out", "-o", help="Output directory."),
    fmt: str = typer.Option("html", "--format", "-f", help="html | json | csv | txt"),
    chats: Optional[str] = typer.Option(
        None, "--chats", "-c",
        help="Comma separated chat numbers/JIDs, or 'all' (default), or 'groups'/'private'.",
    ),
    limit: Optional[int] = typer.Option(None, "--limit", help="Keep only the last N messages per chat."),
    media_root: Optional[Path] = typer.Option(None, "--media-root", help="Root the attachments live under."),
    include_media: bool = typer.Option(False, "--include-media", help="Copy referenced media files too."),
    key: Optional[str] = _key_option(),
    use_cache: bool = typer.Option(True, "--cache/--no-cache"),
    json_mode: bool = typer.Option(False, "--json"),
) -> None:
    """Write conversations to HTML, JSON, CSV or plain text."""
    resolved = _resolve(key) if key else None
    if fmt not in exportmod.FORMATS:
        _fail(f"unknown format {fmt!r}; choose from {', '.join(exportmod.FORMATS)}")

    try:
        with open_backup(file, resolved, use_cache=use_cache) as (header, db_path, _state):
            conn = dbmod.open_db(db_path, read_only=True)
            try:
                available = exportmod.list_chats(conn)
                chosen = _pick_chats(available, chats)
                if not chosen:
                    _fail("no chats matched --chats")
                written = exportmod.export_chats(
                    conn, chosen, out_dir, fmt,
                    limit=limit, media_root=media_root, include_media=include_media,
                )
            finally:
                conn.close()
    except (WrongKey, CryptoError, HeaderError, dbmod.DbError, exportmod.ExportError) as exc:
        _fail(str(exc))

    payload = {
        "format": fmt,
        "out_dir": str(out_dir),
        "chats": len(chosen),
        "files": [str(path) for path in written],
    }
    if json_mode:
        console.print_json(json.dumps(payload))
        return
    console.print(
        f"[green]ok[/green] exported {len(chosen)} chat(s) -> [bold]{out_dir}[/bold] "
        f"({len(written)} file(s), format {fmt})"
    )


def _pick_chats(available, selection: Optional[str]):
    if not selection or selection.strip().lower() == "all":
        return available
    tokens = [token.strip() for token in selection.split(",") if token.strip()]
    if tokens[0].lower() == "groups":
        return [chat for chat in available if chat.group_type]
    if tokens[0].lower() == "private":
        return [chat for chat in available if not chat.group_type]

    chosen = []
    for token in tokens:
        needle = token.lower()
        found = [
            chat for chat in available
            if needle == str(chat.chat_row)
            or needle == (chat.user or "").lower()
            or needle in (chat.label or "").lower()
        ]
        if not found:
            _fail(f"no chat matched {token!r}")
        chosen.extend(found)
    # de-duplicate while keeping order
    seen = set()
    return [chat for chat in chosen if not (chat.chat_row in seen or seen.add(chat.chat_row))]


# --------------------------------------------------------------------------- #
# diff
# --------------------------------------------------------------------------- #


@app.command()
def diff(
    old: Path = typer.Argument(..., exists=True, readable=True, help="The older backup."),
    new: Path = typer.Argument(..., exists=True, readable=True, help="The newer backup."),
    limit: int = typer.Option(40, "--limit", "-n", min=1, help="How many changed chats to show."),
    key: Optional[str] = _key_option(),
    use_cache: bool = typer.Option(True, "--cache/--no-cache"),
    json_mode: bool = typer.Option(False, "--json"),
) -> None:
    """Say what changed between two backups."""
    resolved = _resolve(key) if key else None

    try:
        with open_backup(old, resolved, use_cache=use_cache) as (oh, old_path, _s1):
            with open_backup(new, resolved, use_cache=use_cache) as (nh, new_path, _s2):
                old_conn = dbmod.open_db(old_path, read_only=True)
                new_conn = dbmod.open_db(new_path, read_only=True)
                try:
                    result = diffmod.diff_backups(
                        old_conn, new_conn, str(old), str(new), limit=limit
                    )
                finally:
                    old_conn.close()
                    new_conn.close()
    except (WrongKey, CryptoError, HeaderError, dbmod.DbError, diffmod.DiffError) as exc:
        _fail(str(exc))

    if json_mode:
        console.print_json(json.dumps(result.as_dict()))
        return

    console.print(
        f"messages: {result.total_old_messages:,} → {result.total_new_messages:,} "
        f"([green]+{result.total_added}[/green] [red]−{result.total_removed}[/red])   "
        f"matched on [dim]{result.key_source}[/dim]"
    )
    console.print(
        f"chats: {len(result.new_chats)} new, {len(result.removed_chats)} removed, "
        f"{len(result.changed_chats)} with changes"
    )

    if not result.chats:
        console.print("[dim]no differences found[/dim]")
        return

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("status", max_width=9)
    table.add_column("chat", max_width=44)
    table.add_column("before", justify="right")
    table.add_column("after", justify="right")
    table.add_column("added", justify="right", style="green")
    table.add_column("removed", justify="right", style="red")

    style = {"new": "green", "removed": "red", "added": "cyan", "unchanged": "dim"}
    for chat in result.chats[:limit]:
        table.add_row(
            f"[{style[chat.status]}]{chat.status}[/{style[chat.status]}]",
            chat.label[:44],
            str(chat.old_messages),
            str(chat.new_messages),
            str(chat.added) if chat.added else "",
            str(chat.removed) if chat.removed else "",
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# migrate
# --------------------------------------------------------------------------- #


@app.command()
def migrate(
    file: Path = typer.Argument(..., exists=True, readable=True),
    new_number: str = typer.Argument(..., help="Target number, with country code, e.g. 9665…"),
    old_number: Optional[str] = typer.Option(
        None, "--from", help="Number to migrate away from. Detected when omitted."
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Where the new backup is written."),
    apply: bool = typer.Option(
        False, "--apply",
        help="Actually write the migration. Without this flag nothing is changed (dry run).",
    ),
    merge_collisions: bool = typer.Option(
        False, "--merge-collisions",
        help="Allow deleting an existing chat that already owns the target number.",
    ),
    rewrite_text: bool = typer.Option(
        False, "--rewrite-text",
        help="Also rewrite chat content that quotes the number (messages, links, "
             "vCards). Off by default: only what a restored backup needs is changed.",
    ),
    media_root: Optional[Path] = typer.Option(
        None, "--media-root", help="Also rename <old>@s.whatsapp.net folders under this directory.",
    ),
    key: Optional[str] = _key_option(),
    use_cache: bool = typer.Option(True, "--cache/--no-cache"),
    json_mode: bool = typer.Option(False, "--json"),
) -> None:
    """Change the phone number a backup belongs to. Dry run unless --apply."""
    resolved = _resolve(key) if key else None

    # Everything happens inside the `with`: on a cache miss `db_path` is a
    # temporary file that open_backup deletes when the block exits, so the copy
    # and the re-encryption must not outlive it.
    try:
        with open_backup(file, resolved, use_cache=use_cache) as (header, db_path, _state):
            conn = dbmod.open_db(db_path, read_only=True)
            try:
                source = old_number
                if source is None:
                    report = dbmod.owner_report(conn, header.jid_suffix)
                    source = report["number"]
                    if source is None:
                        _fail(
                            "could not detect the current number; pass --from explicitly. "
                            f"reason: {report['reason']}"
                        )
                    console.print(f"[dim]detected current number: {source}[/dim]")

                plan = migratemod.plan_migration(
                    conn, source, new_number,
                    suffix=header.jid_suffix,
                    include_text=rewrite_text,
                )
            finally:
                conn.close()

            if not apply:
                _print_plan(plan, json_mode)
                console.print(
                    "\n[yellow]dry run[/yellow] — nothing was written. "
                    "Re-run with [bold]--apply[/bold] to perform the migration."
                )
                raise typer.Exit(0)

            if plan.empty:
                _fail("the plan changes nothing; is --from correct?")

            target = output or file.with_name(file.stem + "_migrated.crypt15")
            if target.resolve() == file.resolve():
                _fail("refusing to overwrite the original backup")

            # Work on a copy: the cached decrypted database must never be
            # mutated, or every later command would inherit the change.
            with tempfile.TemporaryDirectory(prefix="wacrypt-migrate-") as work:
                working = Path(work) / "msgstore.db"
                shutil.copyfile(db_path, working)
                conn = dbmod.open_db(working, read_only=False)
                try:
                    applied = migratemod.apply_migration(
                        conn, plan, merge_collisions=merge_collisions
                    )
                    dbmod.vacuum(conn)
                finally:
                    conn.close()

                new_header = _retarget_header(header, plan.suffix_to)
                aes_key = derive_backup_key(resolved or keysmod.resolve_key(key))
                with _progress() as bar:
                    bar.add_task(target.name, total=1)
                    pack_from_file(
                        working, aes_key, target, new_header, progress=_progress_hook(bar)
                    )

    except (WrongKey, CryptoError, HeaderError, dbmod.DbError, migratemod.MigrationError) as exc:
        _fail(str(exc))

    moved = []
    if media_root is not None:
        try:
            moved = migratemod.rename_media_directories(media_root, plan.old, plan.new, dry_run=False)
        except migratemod.MigrationError as exc:
            _fail(str(exc))

    result = {
        **plan.as_dict(),
        "applied": applied,
        "output": str(target),
        "output_size": target.stat().st_size,
        "media_renamed": moved,
    }
    if json_mode:
        console.print_json(json.dumps(result))
        return

    console.print(f"\n[green]ok[/green] migration applied — {sum(applied.values()):,} row(s)")
    for name, count_ in applied.items():
        console.print(f"  • {name}: {count_:,}")
    console.print(f"backup written -> [bold]{target}[/bold] "
                  f"({_readable_size(target.stat().st_size)})")
    if moved:
        console.print(f"media folders renamed: {len(moved)}")
    console.print(
        "[dim]keep the original until WhatsApp has opened and verified the new backup[/dim]"
    )


def _retarget_header(header: BackupHeader, suffix: str) -> BackupHeader:
    from .core.header import patch_jid_suffix

    patched = BackupHeader(**{**header.__dict__})
    patched.prefix = patch_jid_suffix(header.prefix, suffix)
    patched.jid_suffix = suffix
    return patched


def _print_plan(plan, json_mode: bool) -> None:
    if json_mode:
        console.print_json(json.dumps(plan.as_dict()))
        return

    console.print(
        f"\n[bold]migration plan[/bold]  {plan.old} → [bold]{plan.new}[/bold] "
        f"(header suffix {plan.suffix_from} → {plan.suffix_to})"
    )
    console.print(f"  own JID rows      : {plan.identity_rows:,}")
    console.print(f"  tables scanned    : {plan.tables_scanned:,}")
    console.print(
        f"  restore-critical   : {plan.restore_rows:,} row(s)  "
        "[green]always rewritten[/green]"
    )
    console.print(
        f"  chat content       : {plan.content_rows:,} row(s)  "
        + (
            "[green]included (--rewrite-text)[/green]"
            if plan.include_text
            else "[dim]left alone (pass --rewrite-text to include)[/dim]"
        )
    )

    if plan.changes:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        table.add_column("applies", no_wrap=True)
        table.add_column("table", max_width=32)
        table.add_column("column", max_width=28)
        table.add_column("kind")
        table.add_column("rows", justify="right")

        selected = set(id(change) for change in plan.selected)
        for change in plan.changes:
            applies = id(change) in selected
            table.add_row(
                "[green]yes[/green]" if applies else "[dim]no[/dim]",
                change.table,
                change.column,
                change.kind,
                f"{change.rows:,}",
            )
        console.print(table)

    if plan.collisions:
        console.print(
            f"\n[red]collision[/red] — {len(plan.collisions)} JID row(s) already hold "
            f"{plan.new}. Without --merge-collisions the migration will refuse to run."
        )
        for entry in plan.collisions[:5]:
            console.print(
                f"  • {entry['raw_string']}  type={entry['type']} server={entry['server']} "
                f"chats={entry['chats']}"
            )

    for note in plan.notes:
        console.print(f"  [yellow]note[/yellow] {note}")


# --------------------------------------------------------------------------- #
# integrity
# --------------------------------------------------------------------------- #


@app.command()
def integrity(
    file: Path = typer.Argument(..., exists=True, readable=True),
    key: Optional[str] = _key_option(),
    use_cache: bool = typer.Option(True, "--cache/--no-cache"),
    json_mode: bool = typer.Option(False, "--json"),
) -> None:
    """Check the backup's checksum and the database's internal structure."""
    resolved = _resolve(key) if key else None

    report: dict = {"file": str(file)}
    try:
        header = read_header(file)
        report["header"] = {"ok": True, "crypt_type": header.crypt_type}
    except HeaderError as exc:
        report["header"] = {"ok": False, "error": str(exc)}

    try:
        with open_backup(file, resolved, use_cache=use_cache) as (_h, db_path, _state):
            conn = dbmod.open_db(db_path, read_only=True)
            try:
                report["database"] = dbmod.integrity(conn)
                report["tables"] = len(dbmod.table_names(conn))
            finally:
                conn.close()
    except (WrongKey, CryptoError, HeaderError) as exc:
        report["database"] = {"quick_check": f"error: {exc}"}

    if json_mode:
        console.print_json(json.dumps(report))
        return

    ok_header = report["header"].get("ok")
    console.print(f"header  : {'[green]ok[/green]' if ok_header else '[red]bad[/red]'}"
                  + ("" if ok_header else f" — {report['header'].get('error')}"))
    if "database" in report:
        verdict = report["database"].get("quick_check", "unknown")
        colour = "green" if verdict == "ok" else "red"
        console.print(f"database: [{colour}]{verdict}[/{colour}]")
        if "integrity_check" in report["database"]:
            full = report["database"]["integrity_check"]
            console.print(f"full    : [{colour}]{full}[/{colour}]")
        console.print(f"tables  : {report.get('tables', 0)}")


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        err_console.print("\n[yellow]cancelled[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
