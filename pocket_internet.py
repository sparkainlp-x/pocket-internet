#!/usr/bin/env python3
# Copyright (C) 2026 Jean-François Brisson / Spark AI NLP. SPDX-License-Identifier: AGPL-3.0-only
"""File-based demo for validating and merging small public-information bundles.

Local files only: nothing here opens a network connection. The bundle digest is an
unkeyed SHA-256 checksum for spotting accidental changes; it is not a signature or MAC
and anyone who edits a bundle can recompute it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import unicodedata
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

__version__ = "1.0.0"

BUNDLE_SCHEMA = "pocket-internet/bundle"
LIBRARY_SCHEMA = "pocket-internet/library"
VERSION = 1
LANGUAGE_RE = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")
# One timestamp profile on every supported Python version: RFC 3339 date-time with
# whole seconds and Z or a numeric offset. (datetime.fromisoformat accepts many more
# forms on Python 3.11+ than on 3.10, so it is not used as the format check.)
TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2})$")
# Largest revision accepted: the largest integer every common JSON implementation
# represents exactly.
MAX_REVISION = 2**53 - 1
# Upper bound on the size of any bundle or library file read.
MAX_JSON_BYTES = 64 * 1024 * 1024
EXIT_OK, EXIT_ERROR, EXIT_CONFLICT = 0, 1, 2
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BUNDLE_KEYS = {
    "schema", "version", "source_label", "category", "language", "issued_at", "expires_at", "items", "digest",
}
ITEM_KEYS = {"item_id", "revision", "title", "text"}
OBSERVATION_KEYS = (
    "source_label", "category", "language", "issued_at", "expires_at", "item_id", "revision",
    "content_sha256", "bundle_sha256",
)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def content_sha256(title: str, text: str) -> str:
    return sha256_json({"title": title, "text": text})


def _reject_constant(name: str) -> NoReturn:
    raise ValueError(f"invalid JSON number: {name}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def read_json(path: str | Path) -> Any:
    """Read strict UTF-8 JSON (an optional BOM is ignored).

    Duplicate keys, NaN/Infinity, invalid UTF-8, over-deep nesting and files over
    MAX_JSON_BYTES raise ValueError; I/O problems raise OSError.
    """
    with open(path, "rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError(f"{path}: file is larger than {MAX_JSON_BYTES} bytes")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: not valid UTF-8 (byte offset {exc.start})") from None
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from None
    except RecursionError:
        raise ValueError(f"{path}: JSON is nested too deeply") from None


def require_object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be a JSON object")
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], where: str) -> None:
    missing, extra = expected - value.keys(), value.keys() - expected
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if extra:
            details.append("unexpected " + ", ".join(sorted(extra)))
        raise ValueError(f"{where}: " + "; ".join(details))


_MULTILINE_ALLOWED = frozenset("\t\n\r")


def require_text(value: Any, where: str, *, limit: int = 1_000_000, multiline: bool = False) -> str:
    """Non-blank text without control characters (tab/LF/CR allowed when multiline).

    Control characters are rejected so that text received from another device cannot
    carry terminal escape sequences into ``list`` output.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where} must be a non-empty string")
    if len(value) > limit:
        raise ValueError(f"{where} exceeds {limit} characters")
    for character in value:
        if unicodedata.category(character) == "Cc" and not (multiline and character in _MULTILINE_ALLOWED):
            raise ValueError(f"{where} contains a control character (U+{ord(character):04X})")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{where} contains an unpaired surrogate") from None
    return value


def parse_instant(value: Any, where: str = "timestamp") -> datetime:
    """Parse YYYY-MM-DDTHH:MM:SS followed by Z or +HH:MM/-HH:MM; return aware UTC."""
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise ValueError(
            f"{where} must look like 2026-09-30T12:00:00Z or 2026-09-30T08:00:00-04:00; got {value!r}"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"{where} is not a valid date and time: {value!r}") from exc


def _require_aware(now: datetime | None) -> datetime:
    if now is None:
        return utc_now()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("the reference time must be a timezone-aware datetime")
    return now


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_label(value: Any, where: str) -> str:
    text = require_text(value, where, limit=120)
    if text != text.strip():
        raise ValueError(f"{where} must not start or end with whitespace")
    return text


def _validate_revision(value: Any, where: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_REVISION:
        raise ValueError(f"{where} must be an integer from 1 to {MAX_REVISION}")
    return value


def _validate_language(value: Any) -> str:
    language = _validate_label(value, "language")
    if not LANGUAGE_RE.fullmatch(language):
        raise ValueError("language must be a simple BCP 47-style tag such as 'en' or 'fr-CA'")
    return language


def temporal_status(issued_at: str, expires_at: str, now: datetime | None = None) -> str:
    """UPCOMING before issued_at, EXPIRED from expires_at onward, otherwise CURRENT."""
    now = _require_aware(now)
    issued, expires = parse_instant(issued_at, "issued_at"), parse_instant(expires_at, "expires_at")
    if now < issued:
        return "UPCOMING"
    if now >= expires:
        return "EXPIRED"
    return "CURRENT"


def validate_bundle(bundle: Any, now: datetime | None = None) -> str:
    bundle = require_object(bundle, "bundle")
    require_exact_keys(bundle, BUNDLE_KEYS, "bundle")
    if bundle["schema"] != BUNDLE_SCHEMA:
        raise ValueError(f"unsupported bundle schema: {bundle['schema']!r}")
    if type(bundle["version"]) is not int or bundle["version"] != VERSION:
        raise ValueError(f"unsupported bundle version: {bundle['version']!r}")
    _validate_label(bundle["source_label"], "source_label")
    _validate_label(bundle["category"], "category")
    _validate_language(bundle["language"])
    issued = parse_instant(bundle["issued_at"], "issued_at")
    expires = parse_instant(bundle["expires_at"], "expires_at")
    if expires <= issued:
        raise ValueError("expires_at must be later than issued_at")
    items = bundle["items"]
    if not isinstance(items, list) or not items:
        raise ValueError("items must be a non-empty array")
    seen_ids: set[str] = set()
    for index, item_value in enumerate(items):
        item = require_object(item_value, f"items[{index}]")
        require_exact_keys(item, ITEM_KEYS, f"items[{index}]")
        item_id = _validate_label(item["item_id"], f"items[{index}].item_id")
        if item_id in seen_ids:
            raise ValueError(f"item_id {item_id!r} appears more than once in this bundle")
        seen_ids.add(item_id)
        _validate_revision(item["revision"], f"items[{index}].revision")
        require_text(item["title"], f"items[{index}].title", limit=500)
        require_text(item["text"], f"items[{index}].text", multiline=True)
    digest = bundle["digest"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ValueError("digest must be a lowercase 64-character SHA-256 hex string")
    unsigned = {key: value for key, value in bundle.items() if key != "digest"}
    expected = sha256_json(unsigned)
    # Plain comparison on purpose: this unkeyed checksum involves no secret, so a
    # constant-time (hmac.compare_digest) comparison would add nothing.
    if digest != expected:
        raise ValueError(f"bundle digest mismatch: expected {expected}, got {digest}")
    return temporal_status(bundle["issued_at"], bundle["expires_at"], now)


def make_bundle(
    *, source_label: str, category: str, language: str, issued_at: str, expires_at: str, items: list[dict[str, Any]]
) -> dict[str, Any]:
    """Build a bundle and compute its digest; primarily useful for fixtures and examples."""
    payload = {"schema": BUNDLE_SCHEMA, "version": VERSION, "source_label": source_label,
               "category": category, "language": language, "issued_at": issued_at,
               "expires_at": expires_at, "items": items}
    return {**payload, "digest": sha256_json(payload)}


def empty_library() -> dict[str, Any]:
    return {"schema": LIBRARY_SCHEMA, "version": VERSION, "content": {}, "observations": []}


def _validate_observation(observation: Any, index: int, content: dict[str, Any]) -> None:
    where = f"observations[{index}]"
    observation = require_object(observation, where)
    require_exact_keys(observation, set(OBSERVATION_KEYS), where)
    _validate_label(observation["source_label"], f"{where}.source_label")
    _validate_label(observation["category"], f"{where}.category")
    _validate_label(observation["language"], f"{where}.language")
    _validate_language(observation["language"])
    _validate_label(observation["item_id"], f"{where}.item_id")
    _validate_revision(observation["revision"], f"{where}.revision")
    issued = parse_instant(observation["issued_at"], f"{where}.issued_at")
    expires = parse_instant(observation["expires_at"], f"{where}.expires_at")
    if expires <= issued:
        raise ValueError(f"{where}.expires_at must be later than issued_at")
    for field in ("content_sha256", "bundle_sha256"):
        if not isinstance(observation[field], str) or not SHA256_RE.fullmatch(observation[field]):
            raise ValueError(f"{where}.{field} must be a lowercase SHA-256 digest")
    if observation["content_sha256"] not in content:
        raise ValueError(f"{where} refers to missing content {observation['content_sha256']}")


def validate_library(library: Any) -> dict[str, Any]:
    library = require_object(library, "library")
    require_exact_keys(library, {"schema", "version", "content", "observations"}, "library")
    if library["schema"] != LIBRARY_SCHEMA or type(library["version"]) is not int or library["version"] != VERSION:
        raise ValueError("unsupported library schema or version")
    content = require_object(library["content"], "library.content")
    for digest, blob_value in content.items():
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError(f"invalid content digest key: {digest!r}")
        blob = require_object(blob_value, f"content[{digest}]")
        require_exact_keys(blob, {"title", "text"}, f"content[{digest}]")
        title = require_text(blob["title"], f"content[{digest}].title", limit=500)
        text = require_text(blob["text"], f"content[{digest}].text", multiline=True)
        if content_sha256(title, text) != digest:
            raise ValueError(f"content digest mismatch for {digest}")
    observations = library["observations"]
    if not isinstance(observations, list):
        raise ValueError("library.observations must be an array")
    seen: set[tuple[Any, ...]] = set()
    for index, observation in enumerate(observations):
        _validate_observation(observation, index, content)
        key = tuple(observation[field] for field in OBSERVATION_KEYS)
        if key in seen:
            raise ValueError(f"duplicate observation at index {index}")
        seen.add(key)
    referenced = {observation["content_sha256"] for observation in observations}
    orphaned = sorted(set(content) - referenced)
    if orphaned:
        raise ValueError(f"library.content has entries no observation refers to: {', '.join(orphaned)}")
    return library


def observation_key(observation: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(observation[field] for field in OBSERVATION_KEYS)


def _observation_sort_key(observation: dict[str, Any]) -> tuple[Any, ...]:
    """Total order: readable fields first, times by instant, then every field as a tie-break."""
    return (
        observation["source_label"].casefold(),
        observation["item_id"],
        observation["revision"],
        observation["content_sha256"],
        parse_instant(observation["issued_at"]),
        parse_instant(observation["expires_at"]),
        observation_key(observation),
    )


def _sort_observations(observations: list[dict[str, Any]]) -> None:
    observations.sort(key=_observation_sort_key)


def import_bundle(library: dict[str, Any], bundle: Any, now: datetime | None = None) -> tuple[int, int, str]:
    """Add a validated bundle's items to ``library`` in place; return (added, skipped, status)."""
    validate_library(library)
    status = validate_bundle(bundle, now)
    known = {observation_key(obs) for obs in library["observations"]}
    added = skipped = 0
    for item in bundle["items"]:
        digest = content_sha256(item["title"], item["text"])
        blob = {"title": item["title"], "text": item["text"]}
        existing_blob = library["content"].get(digest)
        if existing_blob is not None and existing_blob != blob:
            raise ValueError(f"SHA-256 content collision for {digest}")
        library["content"][digest] = blob
        observation = {
            "source_label": bundle["source_label"], "category": bundle["category"],
            "language": bundle["language"], "issued_at": bundle["issued_at"],
            "expires_at": bundle["expires_at"], "item_id": item["item_id"],
            "revision": item["revision"], "content_sha256": digest,
            "bundle_sha256": bundle["digest"],
        }
        key = observation_key(observation)
        if key in known:
            skipped += 1
        else:
            library["observations"].append(observation)
            known.add(key)
            added += 1
    _sort_observations(library["observations"])
    validate_library(library)
    return added, skipped, status


def merge_libraries(left: Any, right: Any) -> tuple[dict[str, Any], int]:
    """Union two libraries. The result does not depend on argument order, merging a
    library with itself or with an earlier merge result adds nothing, and grouping
    does not matter: merge(merge(a, b), c) == merge(a, merge(b, c))."""
    left, right = validate_library(left), validate_library(right)
    merged = empty_library()
    for library in (left, right):
        for digest, blob in library["content"].items():
            existing = merged["content"].get(digest)
            if existing is not None and existing != blob:
                raise ValueError(f"SHA-256 content collision for {digest}")
            merged["content"][digest] = dict(blob)
    seen: set[tuple[Any, ...]] = set()
    duplicates = 0
    for observation in left["observations"] + right["observations"]:
        key = observation_key(observation)
        if key in seen:
            duplicates += 1
        else:
            merged["observations"].append(dict(observation))
            seen.add(key)
    _sort_observations(merged["observations"])
    merged["content"] = dict(sorted(merged["content"].items()))
    validate_library(merged)
    return merged, duplicates


def conflicts(library: dict[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, int], set[str]] = defaultdict(set)
    for obs in library["observations"]:
        grouped[(obs["source_label"], obs["item_id"], obs["revision"])].add(obs["content_sha256"])
    return [
        {"source_label": source, "item_id": item_id, "revision": revision, "digests": sorted(digests)}
        for (source, item_id, revision), digests in sorted(grouped.items()) if len(digests) > 1
    ]


def _window_summary(states: list[str]) -> str:
    """ACTIVE WINDOW if any window is open now, else UPCOMING if any is still to come, else EXPIRED."""
    if "CURRENT" in states:
        return "ACTIVE WINDOW"
    if "UPCOMING" in states:
        return "UPCOMING"
    return "EXPIRED"


def _variant_status(states: list[str], *, superseded: bool, conflict: bool) -> str:
    window = _window_summary(states)
    if conflict:
        return f"CONFLICT; {window}"
    if superseded:
        return "SUPERSEDED" + ("" if window == "ACTIVE WINDOW" else f"; {window}")
    return "CURRENT" if window == "ACTIVE WINDOW" else window


def listing_rows(library: dict[str, Any], now: datetime | None = None) -> list[dict[str, Any]]:
    """One row per (identity, revision, content) with its status at ``now``.

    A revision is superseded once a higher revision of the same identity has been
    issued (at least one of its observations has issued_at <= now). A higher revision
    that is still UPCOMING does not yet supersede the one in effect.
    """
    validate_library(library)
    now = _require_aware(now)
    started_revisions: dict[tuple[str, str], set[int]] = defaultdict(set)
    variants: dict[tuple[str, str, int, str], list[dict[str, Any]]] = defaultdict(list)
    revision_digests: dict[tuple[str, str, int], set[str]] = defaultdict(set)
    for obs in library["observations"]:
        identity = (obs["source_label"], obs["item_id"])
        revision = (obs["source_label"], obs["item_id"], obs["revision"])
        if parse_instant(obs["issued_at"]) <= now:
            started_revisions[identity].add(obs["revision"])
        revision_digests[revision].add(obs["content_sha256"])
        variants[(*revision, obs["content_sha256"])].append(obs)
    rows: list[dict[str, Any]] = []
    for key, observations in variants.items():
        source, item_id, revision, digest = key
        started = started_revisions.get((source, item_id))
        superseded = bool(started) and revision < max(started)
        conflict = len(revision_digests[(source, item_id, revision)]) > 1
        ordered = sorted(observations, key=_observation_sort_key_by_time)
        states = [temporal_status(o["issued_at"], o["expires_at"], now) for o in ordered]
        rows.append({
            "source_label": source, "item_id": item_id, "revision": revision,
            "content_sha256": digest,
            "status": _variant_status(states, superseded=superseded, conflict=conflict),
            "category": ordered[-1]["category"], "language": ordered[-1]["language"],
            "observations": len(observations),
            "windows": _dedupe_windows(ordered, states),
        })
    return sorted(rows, key=lambda row: (row["source_label"].casefold(), row["source_label"], row["item_id"],
                                         row["revision"], row["content_sha256"]))


def _observation_sort_key_by_time(observation: dict[str, Any]) -> tuple[Any, ...]:
    return (parse_instant(observation["issued_at"]), parse_instant(observation["expires_at"]),
            observation_key(observation))


def _dedupe_windows(ordered: list[dict[str, Any]], states: list[str]) -> list[tuple[str, str, str]]:
    windows: list[tuple[str, str, str]] = []
    for obs, state in zip(ordered, states, strict=True):
        window = (obs["issued_at"], obs["expires_at"], state)
        if window not in windows:
            windows.append(window)
    return windows


def render_library(library: dict[str, Any]) -> str:
    """Deterministic JSON text for a library: sorted keys, 2-space indent, final newline."""
    return json.dumps(library, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def write_library(path: str | Path, library: dict[str, Any]) -> None:
    """Validate, then write via a temporary file in the same directory and os.replace.

    Readers see either the old or the new file, never a partial one. This does not
    serialize concurrent writers: two imports into one store at the same time can
    lose one of the updates.
    """
    validate_library(library)
    text = render_library(library)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=target.parent,
                                         prefix=f".{target.name}.", suffix=".tmp", delete=False) as stream:
            temp_name = stream.name
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, target)
        temp_name = None
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def load_library(path: str | Path, *, allow_missing: bool = False) -> dict[str, Any]:
    path = Path(path)
    if allow_missing and not path.exists():
        return empty_library()
    return validate_library(read_json(path))


def _as_of(value: str | None) -> datetime:
    return utc_now() if value is None else parse_instant(value, "--as-of")


def _print_conflicts(library: dict[str, Any]) -> int:
    found = conflicts(library)
    for conflict in found:
        print(f"CONFLICT {conflict['source_label']}/{conflict['item_id']}@{conflict['revision']}: "
              f"{len(conflict['digests'])} distinct content digests retained; no revision was chosen.")
    return len(found)


def command_validate(args: argparse.Namespace) -> int:
    bundle = read_json(args.bundle)
    status = validate_bundle(bundle, _as_of(args.as_of))
    print(f"VALID {args.bundle}: {len(bundle['items'])} item(s); bundle status: {status}.")
    if status == "EXPIRED":
        print("Expired bundle: retained for review, not current information.")
    return EXIT_OK


def command_import(args: argparse.Namespace) -> int:
    bundle = read_json(args.bundle)
    library = load_library(args.store, allow_missing=True)
    added, skipped, status = import_bundle(library, bundle, _as_of(args.as_of))
    write_library(args.store, library)
    print(f"Imported {args.bundle} into {args.store}: {added} new observation(s), {skipped} duplicate(s); "
          f"bundle status: {status}.")
    if status == "EXPIRED":
        print("Expired bundle: stored for review, not current information.")
    return EXIT_CONFLICT if _print_conflicts(library) else EXIT_OK


def command_merge(args: argparse.Namespace) -> int:
    left, right = load_library(args.store_a), load_library(args.store_b)
    merged, duplicates = merge_libraries(left, right)
    write_library(args.output, merged)
    print(f"Merged {args.store_a} + {args.store_b} -> {args.output}: "
          f"{len(merged['observations'])} observation(s), {len(merged['content'])} unique content object(s), "
          f"{duplicates} duplicate observation(s) skipped.")
    return EXIT_CONFLICT if _print_conflicts(merged) else EXIT_OK


def command_list(args: argparse.Namespace) -> int:
    library = load_library(args.store)
    rows = listing_rows(library, _as_of(args.as_of))
    if not rows:
        print("Library is empty.")
        return 0
    for row in rows:
        periods = ", ".join(
            f"{issued}..{expires} [{'ACTIVE WINDOW' if state == 'CURRENT' else state}]"
            for issued, expires, state in row["windows"]
        )
        blob = library["content"][row["content_sha256"]]
        print(f"[{row['status']}] {row['source_label']}/{row['item_id']}@{row['revision']} "
              f"({row['category']}/{row['language']}; {row['observations']} bundle observation(s); {periods}) "
              f"— {blob['title']}")
        for line in blob["text"].splitlines() or [""]:
            print(f"  {line}")
    count = _print_conflicts(library)
    return EXIT_CONFLICT if count else EXIT_OK


class _Parser(argparse.ArgumentParser):
    """Usage errors exit 1 so that exit code 2 always means "conflict found"."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="pocket-internet",
                     description="Validate and merge Pocket Internet JSON bundles using local files only.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    validate_parser = commands.add_parser("validate", help="validate a bundle and report its time status")
    validate_parser.add_argument("bundle")
    validate_parser.add_argument("--as-of", help="override current time (ISO-8601 with timezone)")
    validate_parser.set_defaults(handler=command_validate)
    import_parser = commands.add_parser("import", help="import a bundle into a local JSON library")
    import_parser.add_argument("bundle")
    import_parser.add_argument("--store", required=True)
    import_parser.add_argument("--as-of", help="override current time (ISO-8601 with timezone)")
    import_parser.set_defaults(handler=command_import)
    merge_parser = commands.add_parser("merge", help="union two local libraries into an output library")
    merge_parser.add_argument("store_a")
    merge_parser.add_argument("store_b")
    merge_parser.add_argument("--output", required=True)
    merge_parser.set_defaults(handler=command_merge)
    list_parser = commands.add_parser("list", help="show stored content, time status, and conflicts")
    list_parser.add_argument("store")
    list_parser.add_argument("--as-of", help="override current time (ISO-8601 with timezone)")
    list_parser.set_defaults(handler=command_list)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Never fail half-way through printing because the console cannot encode a title.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
    try:
        return args.handler(args)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
