# The crypt14 / crypt15 backup format

How a WhatsApp local `msgstore.db.crypt15` is laid out, and exactly which
parts wacrypt has verified byte for byte.

Everything here is documented from [`wacrypt.py`](../wacrypt.py), where it is
implemented: the protobuf reader and the header classes sit in the
`BackupPrefix` / `parse_prefix` section, and the cipher in `pack_from_file` /
`unpack_to_file`.

---

## 1. File layout

```
┌──────────────────────────────────────────────────────────────────────────┐
│ varint   length of the protobuf prefix                                  │
├──────────────────────────────────────────────────────────────────────────┤
│ prefix   BackupPrefix (protobuf, nested) — includes the 16-byte IV       │
├──────────────────────────────────────────────────────────────────────────┤
│ cipher   AES-256-GCM( zlib(msgstore.db) )                               │
├──────────────────────────────────────────────────────────────────────────┤
│ tag      16 bytes  GCM authentication tag                               │
├──────────────────────────────────────────────────────────────────────────┤
│ md5      16 bytes  md5(varint ‖ prefix ‖ ciphertext ‖ tag)              │
└──────────────────────────────────────────────────────────────────────────┘
```

Notes that matter:

* The **IV lives in the prefix**, not next to the ciphertext.
* The **checksum covers the prefix too**, so tampering with the header is
  caught by the MD5 rather than by a confusing tag failure. This is why
  wacrypt verifies the checksum *before* decrypting.
* `cipher_size = file_size − cipher_offset − 32`, where `cipher_offset =
  len(varint) + header_len`.
* Legacy `crypt12` / early `crypt14` files begin with the magic `WAM` and are
  rejected by name rather than parsed.

A real WhatsApp 2.26 crypt15 file: `header_len = 135`, `cipher_offset = 137`,
file ≈ 98 MB, ciphertext ≈ 98 MB (SQLite compresses well, then GCM adds
nothing but the tag).

---

## 2. The key schedule

The 64 hex digits (the "backup key") are the **root key**. Two HMAC-SHA256
steps produce the key actually given to AES:

```
privatekey = HMAC-SHA256( key = 32 zero bytes, msg = root_key )
aes_key    = HMAC-SHA256( key = privatekey,     msg = b"backup encryption" || 0x01 )
```

Both steps are single-shot HMAC over the full message. The label is exactly
17 bytes: `backup encryption`, followed by one counter byte.

Consequences worth knowing:

* The root key must be 32 bytes; anything else is rejected before use.
* The derived key is 32 bytes and is **not** the key the user typed. Passing
  the root key where the derived one belongs does not fail loudly at the AES
  layer — it produces plausible-looking garbage that dies later at the zlib
  header. That is precisely why `derive_backup_key` is named what it is and
  why every entry point takes the root key and derives once.
* `encryption_loop(root, label, n)` stacks the derivation `n/32` times. The
  backup path uses `n = 32`, i.e. a single iteration.

Verified: deriving the key from a real backup key reproduces the expected
value exactly.

---

## 3. The protobuf prefix

The prefix is `BackupPrefix`, decoded by a hand-written parser (~200 lines:
varint, the four wire types, nested length-delimited messages). No `protobuf`
dependency — the header is four nested messages and the runtime would dwarf
the code.

### `BackupPrefix`

| field | number | wire | meaning |
| --- | --- | --- | --- |
| `key_type` (deprecated) | 1 | varint | see key types below |
| `wa_provided_key_data` | 2 | LEN | `C14_cipher` — the crypt14 path |
| `e2ee_key_data` | 3 | LEN | `C15_IV` — the crypt15 path |
| `backup_metadata` | 4 | LEN | `BackupExpiry` (see below) |
| `passkey_metadata` | 5 | LEN | passkey derivation material |
| `key_type` | 6 | varint | the authoritative key type |

The two `key_type` fields are the same value written twice; the one at field 6
is what wacrypt reports, and both are recorded when present.

### `C15_IV` (inside field 3)

| field | number | wire | meaning |
| --- | --- | --- | --- |
| `encryption_iv` | 1 | LEN | 16 bytes — the AES-GCM nonce |

### `BackupExpiry` (inside field 4)

| field | number | meaning |
| --- | --- | --- |
| 1 | | `app_version` — e.g. `2.26.40.73` |
| 2 | | `device_model` |
| 3 | | `jid_suffix` — last two digits of the account number |
| 4 | | `backup_version` |
| 5 … 37 | | **the migration "feature table"** — one flag per schema migration, set when complete |
| 38 | | `backup_export_file_size` |
| 39 | | `cleaned_db` |
| 42 | | `identifier_type` |
| 43 | | `lid_suffix` |
| 44 | | `display_suffix` |

Fields 5–37 are the part people mistake for garbage: they are a bitmap of
which schema migrations this backup has already been through. A real file
carries **33** of them, all complete.

Fields outside the known set are preserved as `unknown_fields` and written
back unchanged — a backup from a newer WhatsApp than this code knows about
round-trips instead of losing metadata.

### Key types

| value | name | notes |
| --- | --- | --- |
| 0 | `WA_PROVIDED` | WhatsApp holds the key — crypt12 / crypt14 |
| 1 | `E2EE_DEPRECATED` | end-to-end, before the kind was named |
| 2 | `E2EE_PASSWORD` | derived from a user password |
| 3 | `E2EE_ENCRYPTION_KEY` | the 64 hex key — today's crypt15 |
| 4 | `E2EE_PASSKEY` | derived from a passkey |

The two kinds are reported together, e.g.
`E2EE_DEPRECATED / new=E2EE_ENCRYPTION_KEY`.

---

## 4. Encryption

| | |
| --- | --- |
| Cipher | AES-256-GCM |
| Nonce | the 16-byte IV from the prefix |
| Key | `aes_key` from §2 |
| Plaintext | `zlib(msgstore.db)` |
| Tag | 16 bytes, appended to the ciphertext |
| Checksum | `md5(varint ‖ prefix ‖ ciphertext ‖ tag)`, 16 bytes, last in the file |

Compression happens **before** encryption, which is why the encrypted payload
is smaller than the decrypted database. wacrypt streams both directions in
1 MiB blocks: decrypting and inflating never materialises the ~2.4×
expansion in memory.

`sniff_payload()` identifies what came out — `zlib`, `sqlite`, `zip` or
`unknown` — so a file that was not compressed with zlib is named as such
instead of failing inside `zlib.decompress`.

---

## 5. Verification order, and why

This order is the whole reason the errors are readable:

1. **Structure.** `read_header` → if the varint or the protobuf will not
   parse: *"…is corrupt, truncated, or not a WhatsApp backup"*, with the
   underlying parse error attached.
2. **MD5 checksum**, computed over `varint ‖ prefix ‖ ciphertext ‖ tag`
   before any decryption. A flipped byte → *"the file is corrupt (not a key
   problem — the bytes on disk changed)"*. Because the prefix is inside the
   digest, a tampered IV is caught here too.
3. **Zlib header**, checked on the first decrypted block, *before any
   plaintext is yielded*. By this point the checksum has passed, so the file
   is authentic; a payload that is not a zlib stream can therefore only mean
   *"this is the wrong key"*.
4. **GCM tag**, verified when the stream finalises. A mismatch raises
   `WrongKey`.

Steps 2 and 3 are what separate the two failures the previous version of this
tool collapsed into `zlib.error: incorrect header check`. At the cipher layer
a wrong key and a corrupted file are genuinely indistinguishable — you can
only separate them by checking the cheap, unambiguous things first.

---

## 6. `jid_suffix`

The header carries only the **last two digits** of the account's phone number.
Two digits is not an identification: on a large backup it matches dozens of
contacts, which is why a tool that guesses the owner from it will present
several equally plausible candidates.

wacrypt records `jid_suffix` as a *reason* attached to a candidate and never
treats it as sufficient on its own. The actual signal is the **Message
yourself** chat — see the README.

When `migrate --apply` rewrites the header, the new suffix is the last two
digits of the target number, and the patch only touches field 3 of
`BackupExpiry`. Every other field, and every unknown field, is carried through
untouched; a patch that changes nothing round-trips byte-identically.

---

## 7. What is verified, and how

| Claim | Status |
| --- | --- |
| File layout, offsets, trailer sizes | ✅ measured against a real crypt15 file |
| Key schedule produces the expected 32 bytes | ✅ derived and compared |
| Checksum = `md5(varint‖prefix‖ciphertext‖tag)` | ✅ recomputed and matched the stored digest |
| Header field numbers (1–6, 1–44) | ✅ parse, and round-trip through `build_prefix` |
| Real header is 135 bytes / cipher at offset 137 | ✅ observed |
| The 33 migration flags in fields 5–37 | ✅ observed, all complete |
| Round-trip: decrypt → re-encrypt → decrypt | ✅ byte-identical output |
| `jid_suffix` patch preserves every other field | ✅ asserted by test |
| **crypt14 (`wa_provided_key_data`)** | ⚠️ field numbers implemented from the published schema, **not** exercised against a real crypt14 file |

The crypt14 path is written but untested against a real file — there was not
one available. `read_header` will parse such a file, but the derived
`cipher_offset` logic for crypt14 has not been measured end to end. Treat
crypt14 support as best-effort until it has been run against a real backup.

---

## 8. Reference implementation

* `core/header.py` — varints, protobuf decoding, `read_header`, `build_prefix`,
  `patch_jid_suffix`
* `core/crypto.py` — `derive_backup_key`, `_verify_checksum`, `iter_decrypted`,
  `iter_plaintext`, `unpack_to_file`, `pack_from_file`
* `tests/test_header.py`, `tests/test_crypto.py` — the assertions behind
  every ✅ above

Handy for checking any file against this document:

```bash
wacrypt info msgstore.db.crypt15     # header only, no key needed
wacrypt integrity msgstore.db.crypt15
```
