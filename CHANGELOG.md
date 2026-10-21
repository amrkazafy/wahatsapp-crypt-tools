# Changelog

All notable changes to `wacrypt` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-10-21

The program is now a single file with a single dependency. Along the way, one
real cryptographic defect — a reused AES-GCM nonce — was found and fixed.

### Changed

**One file**

`wacrypt.py` *is* the program; the `src/wacrypt/` package is gone. Clone the
repository, install `cryptography`, and run it:

```bash
pip install cryptography
python wacrypt.py info msgstore.db.crypt15
```

Installing the project still gives you a `wacrypt` command, but that is now a
console script pointing at `wacrypt:main` in the single module.

**One dependency**

`cryptography` is the only thing imported that Python does not already
provide. Everything else moved in-tree:

| Was | Now |
| --- | --- |
| `typer` | `argparse` |
| `rich` | plain output, with ANSI colour only on a TTY |
| `jinja2` | the export markup inlined as a `string.Template` |
| `keyring` | gone — see Removed |

`string.Template` was chosen over a Jinja one precisely because it cannot
evaluate anything: the four placeholders in the export markup are converted
once at build time, and chat content is not interpolated into the markup at
all. It rides in as JSON and is drawn client-side.

**A fresh nonce on every re-encryption**

`pack_from_file()` used to inherit the IV from the header it was handed
(`iv or header.iv or urandom`). Re-encrypting a *migrated* database — which
is not byte-identical to the original — under the same key and the same nonce
is the classic AES-GCM failure: anyone holding both files can XOR the two
ciphertexts together, and with enough known plaintext recover the GHASH key
and forge tags on either one. Backups WhatsApp writes always carry a fresh
nonce, so there was nothing to gain by reusing one.

A nonce is now generated per packing and written into the prefix with the new
`patch_iv()`, which rewrites that one field in place and copies everything
else — known and unknown — through verbatim, on the same contract as
`patch_jid_suffix()`. The prefix is where the reader takes the IV from, so
the header can no longer disagree with the ciphertext it describes.

`encrypt` correspondingly defaults to `--new-iv`; `--reuse-iv` is now an
explicit opt-in, correct only when the plaintext really is unchanged.

**Output**

Every command gained `--json`. Tables wrap to the terminal width instead of
parsing like a paragraph, colour is used only when stdout is a TTY (and never
when `NO_COLOR` is set), and a wrong key or a corrupt file fails with a
sentence rather than a traceback.

### Removed

**`vault`, and with it every trace of stored state**

The `vault` subcommand, the keychain entry, and the encrypted decryption
cache are gone. There are now nine commands:

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

The cache existed to avoid re-decrypting a database between commands. What it
bought in seconds cost a plaintext-adjacent file to reason about, a keychain
entry to manage, and a `--cache/--no-cache` flag on every command. Every
command now decrypts into a temporary directory that is removed when the
command ends, so the answer to "what decrypted data does this tool leave
behind?" is *none*, and the question no longer needs a flag.

**Key sources are down to three**

`--key` → `$WACRYPT_KEY` → a hidden prompt. The key is never written to disk
in any form, so there is nothing to purge and nothing to forget.

### Security

* **A GCM nonce is no longer reused across two different plaintexts.** This
  is the defect fixed under Changed; it affected `migrate --apply` and
  `encrypt --like`, both of which re-encrypted changed content under the
  original's IV.
* Decrypted databases are removed in a `finally` block that also runs on
  `Ctrl-C` and on error, so an interrupted command cannot leave one behind.
* `decrypt` still writes mode `0600`, through a `.partial` file that is
  renamed only once the copy is complete.

### Testing

143 tests (was 179: the keyring and cache suites went with the features they
covered, and eight were added for the nonce fix). Everything still runs
against a synthetic database in a temporary directory, and on every push
across Python 3.9–3.12 on Linux and macOS.

New coverage worth naming:

* Two packings of the same database under the same header must not produce
  the same nonce.
* The header must advertise whichever nonce was actually used, and an
  explicitly pinned nonce (`--reuse-iv`) must still round-trip.
* `patch_iv()` must move nothing else: the prefix keeps its length, and app
  version, features, backup version, key types and unknown fields survive.

### Upgrading from 0.1.0

Nothing you have on disk changes meaning. Backups written by 0.1.0 open
exactly as before — they were valid GCM files then and are now.

* `wacrypt vault …` no longer exists. If you stored a key there, it is still
  in your keychain; wacrypt simply no longer reads it, so pass it with
  `--key` or export `WACRYPT_KEY`.
* `--cache` / `--no-cache` are gone; there is nothing to cache.
* `encrypt --like X` now generates a fresh nonce by default. Add `--reuse-iv`
  if you specifically want a byte-identical reproduction.

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

[0.2.0]: https://github.com/amrkazafy/whatsapp-crypt-tools/releases/tag/v0.2.0
[0.1.0]: https://github.com/amrkazafy/whatsapp-crypt-tools/releases/tag/v0.1.0
