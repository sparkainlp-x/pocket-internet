#!/usr/bin/env python3
"""File-based demo for validating and merging small public-information bundles."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BUNDLE_SCHEMA = "pocket-internet/bundle"
LIBRARY_SCHEMA = "pocket-internet/library"
VERSION = 1
LANGUAGE_RE = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BUNDLE_KEYS = {"schema", "version", "source_label", "category", "language", "issued_at", "expires_at", "items", "digest"}
ITEM_KEYS = {"item_id", "revision", "title", "text"}
OBSERVATION_KEYS = ("source_label", "category", "language", "issued_at", "expires_at", "item_id", "revision", "content_sha256", "bundle_sha256")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def content_sha256(title: str, text: str) -> str:
    return sha256_json({"title": title, "text": text})


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def read_json(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=_reject_duplicate_keys)


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


def require_text(value: Any, where: str, *, limit: int = 1_000_000) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where} must be a non-empty string")
    if "\x00" in value or len(value) > limit:
        raise ValueError(f"{where} contains a NUL or exceeds {limit} characters")
    return value


def parse_instant(value: Any, where: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where} must be an ISO-8601 timestamp with a timezone")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise ValueError(f"{where} is not a valid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{where} must include a timezone (for example, Z or +00:00)")
    return parsed.astimezone(timezone.utc)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def instant_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_label(value: Any, where: str) -> str:
    text = require_text(value, where, limit=120)
    if text != text.strip():
        raise ValueError(f"{where} must not start or end with whitespace")
    return text


def _validate_language(value: Any) -> str:
    language = _validate_label(value, "language")
    if not LANGUAGE_RE.fullmatch(language):
        raise ValueError("language must be a simple BCP 47-style tag such as 'en' or 'fr-CA'")
    return language


def temporal_status(issued_at: str, expires_at: str, now: datetime | None = None) -> str:
    now = now or utc_now()
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
        if type(item["revision"]) is not int or item["revision"] < 1:
            raise ValueError(f"items[{index}].revision must be a positive integer")
        require_text(item["title"], f"items[{index}].title", limit=500)
        require_text(item["text"], f"items[{index}].text")
    digest = bundle["digest"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ValueError("digest must be a lowercase 64-character SHA-256 hex string")
    unsigned = {key: value for key, value in bundle.items() if key != "digest"}
    expected = sha256_json(unsigned)
    if not hmac.compare_digest(digest, expected):
        raise ValueError(f"bundle digest mismatch: expected {expected}, got {digest}")
    now = now or utc_now()
    if now < issued:
        return "UPCOMING"
    if now >= expires:
        return "EXPIRED"
    return "CURRENT"


def make_bundle(*, source_label: str, category: str, language: str, issued_at: str, expires_at: str, items: list[dict[str, Any]]) -> dict[str, Any]:
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
    _validate_language(observation["language"])
    _validate_label(observation["item_id"], f"{where}.item_id")
    if type(observation["revision"]) is not int or observation["revision"] < 1:
        raise ValueError(f"{where}.revision must be a positive integer")
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
        text = require_text(blob["text"], f"content[{digest}].text")
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
    return library


def observation_key(observation: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(observation[field] for field in OBSERVATION_KEYS)


def _sort_observations(observations: list[dict[str, Any]]) -> None:
    observations.sort(key=lambda o: (o["source_label"].casefold(), o["item_id"], o["revision"], o["content_sha256"], o["issued_at"], o["expires_at"], o["bundle_sha256"]))


def import_bundle(library: dict[str, Any], bundle: Any, now: datetime | None = None) -> tuple[int, int, str]:
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
    left, right = validate_library(left), validate_library(right)
    merged = empty_library()
    for library in (left, right):
        for digest, blob in library["content"].items():
            existing = merged["content"].get(digest)
            if existing is not None and existing != blob:
                raise ValueError(f"SHA-256 content collision for {digest}")
            merged["content"][digest] = blob
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


def _variant_status(observations: list[dict[str, Any]], *, latest: bool, conflict: bool, now: datetime) -> str:
    states = [temporal_status(o["issued_at"], o["expires_at"], now) for o in observations]
    suffix = "EXPIRED" if all(state == "EXPIRED" for state in states) else "UPCOMING" if all(state == "UPCOMING" for state in states) else "ACTIVE WINDOW"
    if conflict:
        return f"CONFLICT; {suffix}"
    if not latest:
        return "SUPERSEDED" + ("; EXPIRED" if suffix == "EXPIRED" else "; UPCOMING" if suffix == "UPCOMING" else "")
    return "CURRENT" if suffix == "ACTIVE WINDOW" else suffix


def listing_rows(library: dict[str, Any], now: datetime | None = None) -> list[dict[str, Any]]:
    validate_library(library)
    now = now or utc_now()
    identity_revisions: dict[tuple[str, str], set[int]] = defaultdict(set)
    variants: dict[tuple[str, str, int, str], list[dict[str, Any]]] = defaultdict(list)
    revision_digests: dict[tuple[str, str, int], set[str]] = defaultdict(set)
    for obs in library["observations"]:
        identity = (obs["source_label"], obs["item_id"])
        revision = (obs["source_label"], obs["item_id"], obs["revision"])
        identity_revisions[identity].add(obs["revision"])
        revision_digests[revision].add(obs["content_sha256"])
        variants[(*revision, obs["content_sha256"])].append(obs)
    rows: list[dict[str, Any]] = []
    for key, observations in variants.items():
        source, item_id, revision, digest = key
        latest = revision == max(identity_revisions[(source, item_id)])
        conflict = len(revision_digests[(source, item_id, revision)]) > 1
        ordered = sorted(observations, key=lambda o: (o["issued_at"], o["expires_at"], o["bundle_sha256"]))
        rows.append({
            "source_label": source, "item_id": item_id, "revision": revision,
            "content_sha256": digest,
            "status": _variant_status(observations, latest=latest, conflict=conflict, now=now),
            "category": ordered[-1]["category"], "language": ordered[-1]["language"],
            "observations": len(observations),
            "windows": sorted({(obs["issued_at"], obs["expires_at"], temporal_status(obs["issued_at"], obs["expires_at"], now)) for obs in observations}),
        })
    return sorted(rows, key=lambda row: (row["source_label"].casefold(), row["item_id"], row["revision"], row["content_sha256"]))


def write_library(path: str | Path, library: dict[str, Any]) -> None:
    validate_library(library)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent, prefix=f".{target.name}.", suffix=".tmp", delete=False) as stream:
            temp_name = stream.name
            json.dump(library, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, target)
    except Exception:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
        raise


def load_library(path: str | Path, *, allow_missing: bool = False) -> dict[str, Any]:
    path = Path(path)
    if allow_missing and not path.exists():
        return empty_library()
    return validate_library(read_json(path))


def _as_of(value: str | None) -> datetime:
    return parse_instant(value, "--as-of") if value else utc_now()


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
    return 0


def command_import(args: argparse.Namespace) -> int:
    bundle = read_json(args.bundle)
    library = load_library(args.store, allow_missing=True)
    added, skipped, status = import_bundle(library, bundle, _as_of(args.as_of))
    write_library(args.store, library)
    print(f"Imported {args.bundle} into {args.store}: {added} new observation(s), {skipped} duplicate(s); bundle status: {status}.")
    if status == "EXPIRED":
        print("Expired bundle: stored for review, not current information.")
    return 2 if _print_conflicts(library) else 0


def command_merge(args: argparse.Namespace) -> int:
    left, right = load_library(args.store_a), load_library(args.store_b)
    merged, duplicates = merge_libraries(left, right)
    write_library(args.output, merged)
    print(f"Merged {args.store_a} + {args.store_b} -> {args.output}: "
          f"{len(merged['observations'])} observation(s), {len(merged['content'])} unique content object(s), "
          f"{duplicates} duplicate observation(s) skipped.")
    return 2 if _print_conflicts(merged) else 0


def command_list(args: argparse.Namespace) -> int:
    library = load_library(args.store)
    rows = listing_rows(library, _as_of(args.as_of))
    if not rows:
        print("Library is empty.")
        return 0
    for row in rows:
        periods = ", ".join(f"{issued}..{expires} [{('ACTIVE WINDOW' if state == 'CURRENT' else state)}]" for issued, expires, state in row["windows"])
        blob = library["content"][row["content_sha256"]]
        print(f"[{row['status']}] {row['source_label']}/{row['item_id']}@{row['revision']} "
              f"({row['category']}/{row['language']}; {row['observations']} bundle observation(s); {periods}) — {blob['title']}")
        for line in blob["text"].splitlines() or [""]:
            print(f"  {line}")
    count = _print_conflicts(library)
    return 2 if count else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate and merge Pocket Internet JSON bundles using local files only.")
    commands = parser.add_subparsers(dest="command", required=True)
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
    try:
        return args.handler(args)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
