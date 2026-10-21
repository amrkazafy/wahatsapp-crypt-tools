# wacrypt

[![tests](https://github.com/amrkazafy/whatsapp-crypt-tools/actions/workflows/test.yml/badge.svg)](https://github.com/amrkazafy/whatsapp-crypt-tools/actions/workflows/test.yml)
[![python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![license](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

Manage, inspect, migrate and search WhatsApp local backups
(`msgstore.db.crypt14` / `.crypt15`) — with **no `wa_crypt_tools` binaries**, no
upload, and no guessing.

**One file, one dependency.** The whole program is [`wacrypt.py`](wacrypt.py),
and the only thing it imports that Python does not already provide is
`cryptography` — because AES-256-GCM is the one thing stdlib will not do.
No package layout to install, no template engine, no keyring, no cache.

```console
$ wacrypt inspect msgstore.db.crypt15
msgstore.db.crypt15
  crypt type         crypt15
  WhatsApp version   2.26.40.73
  header jid suffix  22
  owner number       9990******* (high)
  why                self chat: 815 sent, 1 received
  chats              13,171
  messages           199,381
  earliest message   2019-07-24 18:40:46
  latest message     2026-10-20 17:30:51
  attachments        64,827 (14.67 GB)
  database size      236.60 MB
```

Everything runs locally. Your database, your key and your attachments are
never sent anywhere — this tool has no network code in it at all.

---

## Install

The whole thing is one file:

```bash
pip install cryptography
python wacrypt.py info msgstore.db.crypt15
```

Or clone it and get the `wacrypt` command on your PATH:

```bash
git clone https://github.com/amrkazafy/whatsapp-crypt-tools
cd whatsapp-crypt-tools
python3 -m venv .venv && .venv/bin/pip install .
.venv/bin/wacrypt --version      # wacrypt 0.2.0
```

Requires Python 3.9+. Dependency: `cryptography`. Nothing else — `typer`,
`rich`, `keyring` and `jinja2` were dropped in 0.2.0 to keep the single-file
promise.

## The key

WhatsApp derives a key from the 64-hex-digit string shown under
*Settings → Chats → End-to-end encrypted backup*, or stored in your
`Databases/key` file. wacrypt takes it from, in order:

1. `--key <hex or path>`
2. `WACRYPT_KEY=<hex>`
3. an interactive prompt (hidden)

That is the whole list. The tool never writes the key anywhere, so there is no
keychain entry to add and nothing to forget afterwards.

---

## Commands

| Command | What it does |
| --- | --- |
| `info` | Read the header. Needs no key, touches only the first 64 KB. |
| `inspect` | Owner number, chat/message counts, date range, footprint. |
| `decrypt` | Write a plain SQLite database (mode `0600`). |
| `encrypt` | Encrypt a plain database back into a crypt15 backup. |
| `search` | Find messages without ever materialising a decrypted file. |
| `export` | Write chats to HTML, JSON, CSV or plain text. |
| `diff` | Say what changed between two backups. |
| `migrate` | Change the number the backup belongs to. **Dry run by default.** |
| `integrity` | Check the file's checksum and the database's structure. |

Run `wacrypt <command> --help` for every option. Every `--json` flag turns the
output into a machine-readable report.

### Search

```bash
wacrypt search msgstore.db.crypt15 "invoice" --since 2025-01-01 --limit 20
wacrypt search msgstore.db.crypt15 'order \d+' --regex --context 40
wacrypt search msgstore.db.crypt15 "hello" --chat 99900011122 --json
```

Text is discovered from the schema, not from a hard-coded column list, so it
keeps working across schema versions. `message_media.media_caption`,
`message_vcard.vcard` and friends are searched too.

### Export

```bash
wacrypt export msgstore.db.crypt15 --out ./chats --format html
wacrypt export msgstore.db.crypt15 --out ./chats --format json --chats private
wacrypt export msgstore.db.crypt15 --out ./chats --format txt --limit 500
```

`html` produces a single self-contained file with client-side search over
every message (89 MB for 199 k messages). The markup is an inlined
`string.Template`; chat content never touches it. Messages ride in as JSON
under `<script type="application/json">`, and every `<` in that payload is
written as a JSON unicode escape, so no message can break out of the data
block and into the page.

### Migrate

Changing the number a backup belongs to is the operation with the most ways to
go wrong, so it is built to be inspectable first:

```bash
# 1. always a dry run — nothing is written
wacrypt migrate msgstore.db.crypt15 99900077733

# 2. only then
wacrypt migrate msgstore.db.crypt15 99900077733 --apply
```

```
migration plan  99900011122 → 99900077733 (header suffix 22 → 33)
  own JID rows       : 60
  tables scanned     : 300
  restore-critical   : 272 row(s)  always rewritten
  chat content       : 674 row(s)  left alone (pass --rewrite-text to include)

  applies  table             column        kind             rows
  yes      message_media     file_path     attachment path   147
  yes      message_media     media_name    attachment path   125
  no       message           text_data     chat content      603
  …
```

What it guarantees:

* **The original is never touched.** The migration runs on a copy of the
  decrypted database and writes a *new* `*_migrated.crypt15`. It refuses to
  overwrite the input file.
* **A prefix is never a match.** `99900011122` does not touch
  `999000111220` (someone else's account), and `99900011122` does not touch a
  shorter neighbour. Rows are selected with a broad anchor, then filtered and
  rewritten in Python with `(?<!\d)number(?!\d)`. SQLite's `REPLACE()` would
  corrupt the longer number even when the `WHERE` clause excluded it, so it is
  never used for this.
* **Chat history is yours.** Only what a restored backup actually depends on —
  the account's JID rows and the paths attachments are stored under — is
  rewritten by default. The 603 messages that merely quote the number are
  reported but left alone unless you pass `--rewrite-text`.
* **The header keeps everything but the suffix.** App version, feature flags,
  backup version and every unknown field survive; a no-op patch round-trips
  byte-identically.
* **The nonce is regenerated.** The output is sealed under a fresh AES-GCM IV,
  written back into the prefix where the reader takes it from. (Reusing the
  original's nonce over changed content is the classic GCM failure — see
  [0.2.0](CHANGELOG.md).)
* **The header suffix is derived, not assumed** — it is the last two digits of
  the new number, and it is verified by re-reading the file afterwards.
* **Collisions stop you.** If the target number already exists as a contact in
  this backup, the migration refuses to run unless you pass
  `--merge-collisions`.

### Diff

```bash
wacrypt diff old.crypt15 new.crypt15
# messages: 199,381 → 199,381 (+816 −816)   matched on key_id
# chats: 1 new, 1 removed, 0 with changes
```

Chats are matched on `key_id` when both sides have it, falling back to a
content fingerprint when they do not, so a renamed chat is reported as
*renamed* rather as one deletion plus one addition.

---

## How the owner number is found

WhatsApp does not store "this account is number X" in any obvious place. The
header's `jid_suffix` is only two digits, which is why tools that guess from
it will happily hand you ten equally plausible answers.

The signal that actually works is the **Message yourself** chat: it is the only
private chat where one side wrote hundreds of messages and the other replied
once.

```
self chat: 815 sent, 1 received      →  high confidence
private chat: 270 sent, 215 received →  a conversation, not you
```

The header suffix is recorded as a *reason* but is never enough on its own, so
a backup with no self chat reports `confidence: none` with a ranked list to
choose from rather than a confident wrong answer.

---

## Why the errors read the way they do

The most common failure in the previous version of this tool was

```
error in decrypting: incorrect header check
```

which tells you nothing: it appeared for a wrong key, for a corrupt file, and
for a file that was not a WhatsApp backup at all.

wacrypt checks in the order that lets it say which one it is:

1. **Structure** — the header parses? else `…is corrupt, truncated, or not a
   WhatsApp backup`.
2. **MD5 checksum**, over `varint + prefix + ciphertext + tag`, *before* any
   decryption — so a flipped byte is reported as corruption, not as a key
   problem. The prefix is covered too, so a tampered IV is caught here.
3. **Zlib header**, checked on the first decrypted block before any plaintext
   is handed over. The checksum has already passed by this point, so a payload
   that is not compressed data can only mean the **key is wrong**.
4. **GCM authentication tag**, verified at the end of the stream.

A wrong key and a corrupted file are genuinely indistinguishable at the cipher
layer. They are separated by checking the cheap, unambiguous things first.

---

## Nothing outlives the command that needed it

Every command that has to look inside the database decrypts into a temporary
directory and removes it on the way out — including on Ctrl-C and on error.
There is no cache to purge, no session directory to audit, and no decrypted
file for a later command to inherit.

`decrypt` is the one command that writes a database you keep, and it does so
with mode `0600`, through a `.partial` file so an interrupted run can never
leave a truncated database where a complete one is expected.

---

## The crypt15 format

```
[varint header_len][protobuf prefix][AES-256-GCM(zlib(msgstore.db))][tag][md5]
                                     └ 16 B IV in the prefix      └16B └16B
```

The key schedule is

```
privatekey = HMAC-SHA256(zeros32, root_key)
aes_key    = HMAC-SHA256(privatekey, b"backup encryption" + 0x01)
```

See [docs/FORMAT.md](docs/FORMAT.md) for the full field-by-field breakdown,
including the protobuf tags and how each was verified against a real file.

The parser is hand-written (~200 lines) rather than depending on `protobuf`,
because the header is a handful of fields and the dependency is not worth it.

---

## Tests

```bash
.venv/bin/python -m pytest -q
```

143 tests, all against a synthetic database built in a temporary directory —
no test reads or writes a real backup, and nothing is left behind. The
safety-critical cases have their own regression tests:

* `99900011122` must leave `999000111220` alone, in every column, including a
  row that contains *both*.
* A wrong key and a corrupt file must fail with different messages.
* A no-op header patch must be byte-identical.
* Planning must not write a single row.
* Two packings of the same database must not share a nonce, and the header
  must advertise whichever one was actually used.

Run on every push across Python 3.9–3.12 on Linux and macOS.

---

## Privacy

This tool contains no network code. It does not phone home, does not collect
telemetry, and does not upload your data. Backups, keys and exports stay on
your disk. The key is never written to disk by this program in any form.

---

## Limitations

* **crypt14 is best-effort.** Its field numbers are implemented from the
  published schema, but have never been exercised against a real crypt14
  file. Crypt15 is the path with a real backup behind it.
* **`chat.group_type` is never used as a filter.** On current schemas doing
  so hides real private chats, so owner detection does not touch it.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

---

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
