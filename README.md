# Pocket Internet

[![tests](https://github.com/sparkainlp-x/pocket-internet/actions/workflows/tests.yml/badge.svg)](https://github.com/sparkainlp-x/pocket-internet/actions/workflows/tests.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Status: research prototype](https://img.shields.io/badge/status-research%20prototype-orange.svg)](#install)
[![Evidence: SYNTHETIC](https://img.shields.io/badge/evidence-SYNTHETIC-blue.svg)](#install)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23187284.svg)](https://doi.org/10.5281/zenodo.23187284)

Pocket Internet is a small, file-based demo for communities that carry compact public-information bundles between devices that may be disconnected, then merge the resulting local libraries later. It uses only Python's standard library. Devices exchange files manually; the program never opens a network connection or polls for updates.

The example material is synthetic. The demo is useful for exploring **offline file transport and simulated merge**, not for establishing whether a message is safe, authentic, or true.

## Install

Requires Python 3.10 or newer and nothing else. Run the single script from this directory, or install it from a clone to get a `pocket-internet` command (which can replace `python3 pocket_internet.py` below):

```sh
python3 -m pip install .
pocket-internet --version
```

## Quick start

From this directory:

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

To see a revision conflict, import the alternative revision into the merged library (this exits with code 2):

```sh
python3 pocket_internet.py import examples/bundles/conflicting-revision.json --store /tmp/merged.json --as-of '2026-09-30T12:00:00Z'
```

`list` reports each content revision's time status. The sample bundles expire in October 2026, so for deterministic inspection add `--as-of '2026-09-30T12:00:00Z'` to `validate`, `import`, or `list`. Status is computed from the bundle's issued and expiry timestamps: expired content is marked `EXPIRED` (or `SUPERSEDED; EXPIRED`) and is never marked current. A future-issued bundle is marked `UPCOMING`.

The statuses in full:

- A time window is active from `issued_at` (inclusive) until `expires_at` (exclusive). When the same content was observed in several bundles, it counts as active if any of its windows is active now; otherwise `UPCOMING` if any window is still to come; otherwise `EXPIRED`.
- `CURRENT`: the highest issued revision for its identity, with an active window.
- `SUPERSEDED` (with `; EXPIRED` or `; UPCOMING` when no window is active): a higher revision of the same identity has already been issued as of the chosen time. A higher revision that is still upcoming does not yet supersede the revision in effect, and a higher revision that has already expired still supersedes it (then nothing for that identity is current).
- `CONFLICT; ACTIVE WINDOW`, `CONFLICT; UPCOMING`, or `CONFLICT; EXPIRED`: several different contents share one identity and revision.

## Commands

```text
python3 pocket_internet.py validate BUNDLE [--as-of ISO_TIME]
python3 pocket_internet.py import BUNDLE --store LIBRARY [--as-of ISO_TIME]
python3 pocket_internet.py merge LIBRARY_A LIBRARY_B --output LIBRARY
python3 pocket_internet.py list LIBRARY [--as-of ISO_TIME]
python3 pocket_internet.py --version
```

Import creates a new library if the store path does not exist; `merge --output` replaces an existing file. Writes use a temporary file in the same directory followed by an atomic replace, so readers see either the old or the new library, never a partial one. On POSIX systems the written library is readable only by its owner. Writes are not locked: do not run two imports into the same store at the same time, or one update can be lost. Store paths are the paths you give on the command line; item IDs and other bundle fields are never used to build file names. A merge keeps all distinct observations and unique content objects. Identical observations are skipped, and identical title/text pairs share one content object even when they appear under separate item identities. The original identity and bundle metadata remain in each observation.

An item identity is `(source_label, item_id)`; `revision` is a positive integer that publishers should increase monotonically for that identity. The tool allows old revisions to arrive out of order, as offline exchange requires. If the same identity and revision has different content, both alternatives are retained and reported as `CONFLICT`; neither is silently selected as current. Merging is order-independent: `merge A B` and `merge B A` produce byte-identical files, grouping does not matter, and merging a library with itself or with an earlier merge result adds nothing. Library files are written with sorted keys and a fixed observation order.

Exit codes: `0` for success; `2` when `import`, `merge`, or `list` finds a conflict (`import` and `merge` write the library first); `1` for every error, including invalid JSON, schema, timestamps, or digests, unreadable files, and command-line usage errors, so that `2` always means "conflict". Rejected input is never written.

## Bundle format

A bundle is UTF-8 JSON with schema `pocket-internet/bundle`, version `1`, a non-empty source label, category and language tag, timezone-qualified ISO-8601 `issued_at` and `expires_at`, and one or more items. Each item has a stable `item_id`, positive integer `revision`, text `title`, and text `text`. Item IDs must be unique within one bundle.

Validation is strict and behaves the same on Python 3.10–3.13:

- Timestamps must have the form `2026-09-30T12:00:00Z` or `2026-09-30T08:00:00-04:00` (whole seconds, `Z` or a numeric offset), and `expires_at` must be later than `issued_at`. Times with different offsets are compared as instants.
- Revisions are integers from 1 to 2^53 − 1. Labels (source, category, item ID, language) are at most 120 characters with no surrounding whitespace; titles at most 500 characters; texts at most 1,000,000 characters.
- Control characters are rejected everywhere except tab, line feed, and carriage return inside `text`. This also keeps terminal escape sequences from other devices out of `list` output.
- Unknown or missing keys, duplicate JSON keys, `NaN`/`Infinity`, invalid UTF-8, and files over 64 MiB are rejected. A leading UTF-8 byte-order mark is ignored.

Library files are checked for internal consistency when read: each content entry's key must be the SHA-256 of its title and text, every observation must refer to stored content, content that no observation refers to is rejected, and duplicate observations are rejected. The original bundles are not stored, so an observation's `bundle_sha256` and metadata cannot be re-checked against them.

The top-level `digest` is SHA-256 of the UTF-8 encoding of the JSON object with `digest` omitted, serialized with sorted keys, compact separators, and non-ASCII characters preserved. This detects accidental alterations when the digest is not also recomputed. It is **not** a digital signature or a keyed MAC (no key is involved, and the digest is compared with a plain equality check): anyone can edit a bundle and calculate a new digest. The library separately computes SHA-256 content keys over each item's title and text so identical text is stored once.

## Trust and safety boundaries

- This is file transport and simulated merge only. It does **not** implement Bluetooth, radio, mesh networking, automatic synchronization, encryption, digital signatures, or origin authentication.
- A source label is plain text, not proof of who created a bundle. A matching SHA-256 digest does not prove authorship or integrity against a deliberate editor who can recompute it.
- Content is not guaranteed to be accurate, safe, current, or complete. Use sources your community already trusts, independently check important information, and check the source label and timestamps before acting.
- Expiry is a display and merge-status aid, not a cryptographic guarantee or an automatic deletion policy. Expired items remain in the library for review and are explicitly not presented as current.
- The examples contain fictional public-information notices. Do not put personal or sensitive data in bundles.

## Examples and tests

- `examples/bundles/` contains synthetic valid, expired, updated, and conflicting bundles.
- `examples/nodes/` contains two prebuilt stores representing separate offline nodes before exchange: `node-a.json` is `harbor-base.json` plus `expired-notice.json`, and `node-b.json` is `harbor-update.json` (a test rebuilds both byte-for-byte).
- Run checks with the Python standard library only:

```sh
python3 -m py_compile pocket_internet.py tests/test_pocket_internet.py
python3 -m unittest discover -s tests -v
```

`tests/test_pocket_internet.py` holds the original tests. `tests/test_review_additions.py` adds tests for the digest's canonical form (and that a recomputed digest is accepted, i.e. it is not authentication), the timestamp profile, status rules, merge order-independence and idempotence on randomized libraries, strict JSON and library validation, atomic writes, exit codes, and checks that the module imports no networking code and runs with networking disabled. CI runs `ruff check .`, requires at least 90% branch coverage (`coverage[toml]`), runs the example commands, and smoke-tests `pip install .`.

## Related work / when to use something else

- **Authenticity:** sign bundles with [minisign](https://jedisct1.github.io/minisign/), signify, or OpenPGP and verify signatures before importing, if recipients must know who published a bundle and that it was not altered. This tool does not do that.
- **Offline-first messaging with identities:** [Briar](https://briarproject.org/) (Bluetooth/Wi-Fi/Tor, signed and encrypted) and [Secure Scuttlebutt](https://scuttlebutt.nz/) (signed append-only feeds that sync when peers meet).
- **Offline content libraries:** [Kiwix](https://kiwix.org/) serves large offline copies of Wikipedia and other reference content.
- **File synchronization and history:** [Syncthing](https://syncthing.net/) for syncing folders between devices, and Git (including `git bundle` files carried on removable media) for full version history.
- **Merge semantics:** CRDT libraries such as [Automerge](https://automerge.org/) for concurrent edits to shared documents.

Pocket Internet is a small, dependency-free, readable demonstration of carrying public notices on files and merging them with explicit expiry, supersession, and conflict reporting.

## Citation

See [CITATION.cff](CITATION.cff). Archived on Zenodo: concept DOI [10.5281/zenodo.23187284](https://doi.org/10.5281/zenodo.23187284) (all versions); v1.0.0: [10.5281/zenodo.23187285](https://doi.org/10.5281/zenodo.23187285).

## License

This software is available under the GNU Affero General Public License v3.0 only (AGPL-3.0-only); see [LICENSE](LICENSE).

Organizations that want to use it in proprietary products or services without AGPL obligations can contact the author about a commercial license via https://sparkainlpx.xyz.
