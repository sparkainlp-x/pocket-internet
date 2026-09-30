# Pocket Internet

Pocket Internet is a small, file-based demo for communities that carry compact public-information bundles between devices that may be disconnected, then merge the resulting local libraries later. It uses only Python's standard library. Devices exchange files manually; the program never opens a network connection or polls for updates.

The example material is synthetic. The demo is useful for exploring **offline file transport and simulated merge**, not for establishing whether a message is safe, authentic, or true.

## Quick start

Run from this directory with Python 3.10 or newer:

```sh
python3 pocket_internet.py validate examples/bundles/harbor-base.json
python3 pocket_internet.py import examples/bundles/harbor-base.json --store /tmp/node-a.json
python3 pocket_internet.py list /tmp/node-a.json
```

Merge the two included sample node libraries into a new local file:

```sh
python3 pocket_internet.py merge examples/nodes/node-a.json examples/nodes/node-b.json --output /tmp/merged.json
python3 pocket_internet.py list /tmp/merged.json
```

`list` reports each content revision's time status. For deterministic inspection, add `--as-of '2026-09-30T12:00:00Z'` to `validate`, `import`, or `list`. Status is computed from the bundle's issued and expiry timestamps: expired content is marked `EXPIRED` (or `SUPERSEDED; EXPIRED`) and is never marked current. A future-issued bundle is marked `UPCOMING`.

## Commands

```text
python3 pocket_internet.py validate BUNDLE [--as-of ISO_TIME]
python3 pocket_internet.py import BUNDLE --store LIBRARY [--as-of ISO_TIME]
python3 pocket_internet.py merge LIBRARY_A LIBRARY_B --output LIBRARY
python3 pocket_internet.py list LIBRARY [--as-of ISO_TIME]
```

Import creates a new library if the store path does not exist. Writes use a temporary file followed by an atomic replace. A merge keeps all distinct observations and unique content objects. Identical observations are skipped, and identical title/text pairs share one content object even when they appear under separate item identities. The original identity and bundle metadata remain in each observation.

An item identity is `(source_label, item_id)`; `revision` is a positive integer that publishers should increase monotonically for that identity. The tool allows old revisions to arrive out of order, as offline exchange requires. If the same identity and revision has different content, both alternatives are retained and reported as `CONFLICT`; neither is silently selected as current. A CLI operation that finds a conflict returns exit code `2` after writing the merged/imported library. Invalid JSON, schema, timestamps, or digests return exit code `1` and are rejected.

## Bundle format

A bundle is UTF-8 JSON with schema `pocket-internet/bundle`, version `1`, a non-empty source label, category and language tag, timezone-qualified ISO-8601 `issued_at` and `expires_at`, and one or more items. Each item has a stable `item_id`, positive integer `revision`, text `title`, and text `text`. Item IDs must be unique within one bundle.

The top-level `digest` is SHA-256 of the UTF-8 encoding of the JSON object with `digest` omitted, serialized with sorted keys, compact separators, and non-ASCII characters preserved. This detects accidental alterations when the digest is not also recomputed. It is **not** a digital signature: anyone can edit a bundle and calculate a new digest. The library separately computes SHA-256 content keys over each item's title and text so identical text is stored once.

## Trust and safety boundaries

- This is file transport and simulated merge only. It does **not** implement Bluetooth, radio, mesh networking, automatic synchronization, encryption, digital signatures, or origin authentication.
- A source label is plain text, not proof of who created a bundle. A matching SHA-256 digest does not prove authorship or integrity against a deliberate editor who can recompute it.
- Content is not guaranteed to be accurate, safe, current, or complete. Use sources your community already trusts, independently check important information, and check the source label and timestamps before acting.
- Expiry is a display and merge-status aid, not a cryptographic guarantee or an automatic deletion policy. Expired items remain in the library for review and are explicitly not presented as current.
- The examples contain fictional public-information notices. Do not put personal or sensitive data in bundles.

## Examples and tests

- `examples/bundles/` contains synthetic valid, expired, updated, and conflicting bundles.
- `examples/nodes/` contains two prebuilt stores representing separate offline nodes before exchange.
- Run checks with the Python standard library only:

```sh
python3 -m py_compile pocket_internet.py tests/test_pocket_internet.py
python3 -m unittest discover -s tests -v
```
