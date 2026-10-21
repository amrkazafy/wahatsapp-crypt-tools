# Changelog

All notable changes to `wacrypt` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-10-21

First release. A ground-up rewrite of `wa_crypt_manager` as a package, with
the crypto implemented in-tree — no `wa_crypt_tools` binaries, and no
network code anywhere in it.

### Added

**Commands**

| Command | What it does |
| --- | --- |
| `info` | Read the header. Needs no key, touches only the first 64 KB. |
| `inspect` | Owner number, chat/message counts, date range, footprint. |
| `decrypt` | Write a plain SQLite database (mode `0600`). |
| `encrypt` | Encrypt a plain database back into a crypt15 backup. |
| `search` | Find messages without materialising a decrypted file. |
| `export` | Write chats to HTML, JSON, CSV or plain text. |
| `diff` | Say what changed between two backups. |
| `migrate` | Change the number a backup belongs to. Dry run by default. |
| `integrity` | Check the file's checksum and the database's structure. |
| `vault` | The keychain key and the encrypted decryption cache. |

**Crypt15 support, natively**

* AES-256-GCM streamed in 1 MiB blocks in both directions, so a 236 MB
  database never has to be held in memory.
* A hand-written protobuf parser (~200 lines) for the header's four nested
  messages, rather than taking a dependency on `protobuf`.
* Unknown header fields are preserved on rewrite, so a backup written by a
  newer WhatsApp than this code knows about round-trips instead of losing
  metadata.

**Readable failure**

Verification runs *structure → MD5 checksum → zlib header → GCM tag*.
Checking the checksum before decrypting, and the zlib magic before yielding
any plaintext, is what turns v1's unconditional

```
error in decrypting: incorrect header check
```

into a sentence that says which thing actually went wrong: a flipped byte is
corruption, and a payload that is not compressed data — after the checksum
has already passed — can only mean the key is wrong.

**A migration that cannot corrupt a neighbour**

* Dry run by default; `--apply` writes a new file, never the input.
* Numbers are matched on digit boundaries in Python, because SQLite's
  `REPLACE()` corrupts a longer neighbour number (`999000111220`) even when
  the `WHERE` clause excludes it.
* Rows are split into *restore-critical* (the account's JID rows and
  attachment paths, always rewritten) and *chat content* (messages, vCards,
  links — only with `--rewrite-text`). Migrating does not quietly edit
  history.
* Collisions with an existing contact stop the run unless `--merge-collisions`
  is passed.
* The header's `jid_suffix` is retargeted; every other field survives, and a
  no-op patch round-trips byte-identically.

**A cache that does not leak**

The decrypted database is materialised into a per-command temporary
directory and removed in a `finally` block. The cache at rest is
AES-256-GCM with a keychain-held key. `wacrypt vault status` reports
`plaintext on disk` so a leftover from an older build shows up.

**Owner detection that admits uncertainty**

Only the *Message yourself* chat counts as evidence. The header's two-digit
suffix is recorded as a reason attached to a candidate and is never
sufficient on its own, so a backup with no self chat reports
`confidence: none` with a ranked list rather than a confident wrong answer.

### Testing

179 tests, all against a synthetic database built in a temporary directory —
no test reads a real backup, touches the real keychain, or leaves anything
behind. Run on every push across Python 3.9–3.12 on Linux and macOS.

### Known limitations

* **crypt14 is best-effort.** The field numbers are implemented from the
  published schema but have never been exercised against a real crypt14
  file. Crypt15 is the tested path.
* **`chat.group_type` is never used as a filter.** Doing so hides real
  private chats on current schemas.

[0.1.0]: https://github.com/amrkazafy/whatsapp-crypt-tools/releases/tag/v0.1.0
