# wacrypt

[![tests](https://github.com/amrkazafy/whatsapp-crypt-tools/actions/workflows/test.yml/badge.svg)](https://github.com/amrkazafy/whatsapp-crypt-tools/actions/workflows/test.yml)
[![python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![license](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

Manage, inspect, migrate and search WhatsApp local backups
(`msgstore.db.crypt14` / `.crypt15`) — with **no `wa_crypt_tools` binaries**, no
upload, and no guessing.

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
  attachments        64,827 (14.67 GB)
  from cache         yes
```

Everything runs locally. Your database, your key and your attachments are
never sent anywhere — this tool has no network code in it at all.

---

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

Or straight from GitHub, without cloning:

```bash
pip install "git+https://github.com/amrkazafy/whatsapp-crypt-tools.git"
```

Requires Python 3.9+. Dependencies: `cryptography`, `typer`, `rich`,
`keyring`, `jinja2`.

```bash
wacrypt --version   # wacrypt 0.1.0
```

## The key

WhatsApp derives a key from the 64-hex-digit string shown under
*Settings → Chats → End-to-end encrypted backup*, or stored in your
`Databases/key` file. wacrypt will take it from, in order:

1. `--key <hex or path>`
2. `WACRYPT_KEY=<hex>`
3. the macOS Keychain / system keyring — see `wacrypt vault set`
4. an interactive prompt (hidden)

```bash
# store it once, stop pasting it everywhere
WACRYPT_KEY="$(cat 'pass wh.txt')" wacrypt vault add

wacrypt vault status
#   key in keychain : yes (97a7bc…7d65)
#   cached backups  : 2
```

(The six and four characters shown are the **key's** own hex, not a phone
number — enough to tell two keys apart, useless for opening anything.)

---

## Commands

| Command | What it does |
| --- | --- |
| `info` | Read the header. Needs no key, touches only the first 64 KB. |
| `inspect` | Owner number, chat/message counts, date range, footprint. |
| `decrypt` | Write a plain SQLite database (mode `0600`, into the vault). |
| `encrypt` | Encrypt a plain database back into a crypt15 backup. |
| `search` | Find messages without ever materialising a decrypted file. |
| `export` | Write chats to HTML, JSON, CSV or plain text. |
| `diff` | Say what changed between two backups. |
| `migrate` | Change the number the backup belongs to. **Dry run by default.** |
| `integrity` | Check the file's checksum and the database's structure. |
| `vault` | The keychain key and the encrypted decryption cache. |

Run `wacrypt <command> --help` for every option.

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
every message (89 MB for 199 k messages). The payload is JSON-encoded and
every `<` in it is written as a JSON unicode escape, so no message can break
out of the data block and into the page.

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
  overwrite the input file, and it never mutates the cached database either —
  or every later command would inherit the change.
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
* **The header keeps everything but the suffix.** The IV, app version,
  feature flags, backup version and every unknown field survive; a no-op patch
  round-trips byte-identically.
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
*renamed* rather than as one deletion plus one addition.

---

## How the owner number is found

WhatsApp does not store "this account is number X" in any obvious place. The
header's `jid_suffix` is only two digits, which is why tools that guess from
it will happily hand you ten equally plausible answers.

The signal that actually works is the **Message yourself** chat: it is the only
private chat where one side wrote hundreds of messages and the other replied
once.

```
self chat: 815 sent, 1 received   →  high confidence
private chat: 270 sent, 215 received  →  a conversation, not you
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

## Decrypted databases are not left lying around

`decrypt` writes to `0600`, but `search`, `inspect` and `export` never need a
plaintext file at all — they open the decrypted database straight out of an
**AES-256-GCM encrypted cache** whose key lives only in the keychain. The
plaintext copy exists for exactly as long as one command runs.

```bash
wacrypt vault status     # what is cached, and how big
wacrypt vault purge      # remove every cached database
wacrypt vault purge --all
```

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

175 tests, all against a synthetic database built in a temporary directory —
no test reads or writes a real backup, touches the real keychain, or leaves
anything behind. The safety-critical cases have their own regression tests:

* `99900011122` must leave `999000111220` alone, in every column, including a
  row that contains *both*.
* A wrong key and a corrupt file must fail with different messages.
* A no-op header patch must be byte-identical.
* Planning must not write a single row.

---

## Privacy

This tool contains no network code. It does not phone home, does not collect
telemetry, and does not upload your data. Backups, keys and exports stay on
your disk.

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
