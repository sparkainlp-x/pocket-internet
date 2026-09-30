# Copyright (C) 2026 Jean-François Brisson / Spark AI NLP. SPDX-License-Identifier: AGPL-3.0-only
"""Tests added during the code review (the original tests are unchanged)."""

from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import io
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import pocket_internet as pi  # noqa: E402

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
AS_OF = "2026-09-30T12:00:00Z"
EXAMPLES = PROJECT_DIR / "examples"


def make(item_id="notice", revision=1, title="Clinic hours", text="Open 09:00-17:00", *,
         issued="2026-09-29T09:00:00Z", expires="2026-10-15T00:00:00Z", source="Community Desk",
         category="health", language="en"):
    return pi.make_bundle(source_label=source, category=category, language=language, issued_at=issued,
                          expires_at=expires,
                          items=[{"item_id": item_id, "revision": revision, "title": title, "text": text}])


def resign(value):
    value = copy.deepcopy(value)
    value.pop("digest", None)
    value["digest"] = pi.sha256_json(value)
    return value


def library_of(*bundles, now=NOW):
    library = pi.empty_library()
    for bundle in bundles:
        pi.import_bundle(library, bundle, now)
    return library


def statuses(library, now=NOW):
    return {(row["item_id"], row["revision"]): row["status"] for row in pi.listing_rows(library, now)}


class DigestTests(unittest.TestCase):
    def test_digest_matches_the_documented_canonical_form(self):
        raw = json.loads((EXAMPLES / "bundles" / "harbor-base.json").read_text(encoding="utf-8"))
        digest = raw.pop("digest")
        canonical = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), digest)

    def test_digest_is_not_authentication(self):
        edited = copy.deepcopy(make())
        edited["items"][0]["text"] = "Deliberately edited"
        edited["source_label"] = "Someone Else"
        # Anyone can recompute the digest; the edited bundle then validates.
        self.assertEqual(pi.validate_bundle(resign(edited), NOW), "CURRENT")

    def test_digest_must_be_lowercase_hex(self):
        bundle = make()
        bundle["digest"] = bundle["digest"].upper()
        with self.assertRaisesRegex(ValueError, "lowercase 64-character"):
            pi.validate_bundle(bundle, NOW)


class TimeTests(unittest.TestCase):
    def test_timestamp_profile_is_the_same_on_every_python_version(self):
        accepted = {
            "2026-09-30T12:00:00Z": NOW,
            "2026-09-30T08:00:00-04:00": NOW,
            "2026-09-30T14:00:00+02:00": NOW,
        }
        for text, expected in accepted.items():
            with self.subTest(text=text):
                self.assertEqual(pi.parse_instant(text), expected)
        for text in ("2026-09-30T12:00Z", "2026-09-30 12:00:00Z", "20260930T120000Z", "2026-09-30T12:00:00.5Z",
                     "2026-09-30T12:00:00", "2026-09-30T12:00:00z", "2026-09-30T12:00:00+0000",
                     "2026-02-30T12:00:00Z", "2026-09-30T12:00:00+24:00", "\u0662026-09-30T12:00:00Z", 1, None):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    pi.parse_instant(text)

    def test_reference_time_must_be_aware(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            pi.validate_bundle(make(), datetime(2026, 9, 30))
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            pi.listing_rows(pi.empty_library(), datetime(2026, 9, 30))

    def test_window_boundaries(self):
        bundle = make(issued="2026-09-30T12:00:00Z", expires="2026-09-30T13:00:00Z")
        self.assertEqual(pi.validate_bundle(bundle, NOW - timedelta(seconds=1)), "UPCOMING")
        self.assertEqual(pi.validate_bundle(bundle, NOW), "CURRENT")
        self.assertEqual(pi.validate_bundle(bundle, NOW + timedelta(minutes=59, seconds=59)), "CURRENT")
        self.assertEqual(pi.validate_bundle(bundle, NOW + timedelta(hours=1)), "EXPIRED")

    def test_expiry_must_follow_issue(self):
        with self.assertRaisesRegex(ValueError, "later than issued_at"):
            pi.validate_bundle(make(issued="2026-09-30T12:00:00Z", expires="2026-09-30T08:00:00-04:00"), NOW)

    def test_offsets_are_compared_as_instants(self):
        early_by_instant = make(category="old", issued="2026-09-30T10:00:00+02:00")  # 08:00Z
        late_by_instant = make(category="new", issued="2026-09-30T09:00:00Z")
        row = pi.listing_rows(library_of(late_by_instant, early_by_instant), NOW)[0]
        self.assertEqual(row["category"], "new")
        self.assertEqual([window[0] for window in row["windows"]],
                         ["2026-09-30T10:00:00+02:00", "2026-09-30T09:00:00Z"])


class StatusTests(unittest.TestCase):
    def test_expired_and_upcoming_windows_are_not_current(self):
        library = library_of(make(issued="2026-09-01T00:00:00Z", expires="2026-09-10T00:00:00Z"),
                             make(issued="2026-10-05T00:00:00Z", expires="2026-10-20T00:00:00Z"))
        self.assertEqual(statuses(library), {("notice", 1): "UPCOMING"})

    def test_upcoming_higher_revision_does_not_supersede_yet(self):
        library = library_of(make(revision=1), make(revision=2, text="New", issued="2026-10-05T00:00:00Z"))
        self.assertEqual(statuses(library), {("notice", 1): "CURRENT", ("notice", 2): "UPCOMING"})
        later = NOW.replace(month=10, day=6)
        self.assertEqual(statuses(library, later), {("notice", 1): "SUPERSEDED", ("notice", 2): "CURRENT"})

    def test_expired_higher_revision_still_supersedes(self):
        library = library_of(make(revision=1, issued="2026-09-01T00:00:00Z"),
                             make(revision=2, text="New", issued="2026-09-02T00:00:00Z",
                                  expires="2026-09-10T00:00:00Z"))
        self.assertEqual(statuses(library), {("notice", 1): "SUPERSEDED", ("notice", 2): "EXPIRED"})

    def test_superseded_labels_carry_the_window_state(self):
        library = library_of(make(revision=1, issued="2026-09-01T00:00:00Z", expires="2026-09-02T00:00:00Z"),
                             make(revision=2, text="New"))
        self.assertEqual(statuses(library)[("notice", 1)], "SUPERSEDED; EXPIRED")

    def test_conflict_labels(self):
        upcoming = "2026-10-01T00:00:00Z"
        library = library_of(make(text="A", issued=upcoming), make(text="B", issued=upcoming))
        self.assertEqual({row["status"] for row in pi.listing_rows(library, NOW)}, {"CONFLICT; UPCOMING"})
        self.assertEqual(pi.conflicts(library)[0]["revision"], 1)

    def test_same_item_id_under_different_sources_is_a_different_identity(self):
        library = library_of(make(source="Desk A", text="A"), make(source="Desk B", text="B"))
        self.assertEqual(pi.conflicts(library), [])


class MergeTests(unittest.TestCase):
    def random_library(self, rng):
        library = pi.empty_library()
        for _ in range(rng.randint(0, 6)):
            day = rng.randint(1, 28)
            bundle = make(item_id=rng.choice(["a", "b"]), revision=rng.randint(1, 3), text=rng.choice(["x", "y", "z"]),
                          source=rng.choice(["Desk", "desk", "Other"]), category=rng.choice(["c1", "c2"]),
                          issued=f"2026-09-{day:02d}T00:00:00Z", expires=f"2026-10-{day:02d}T00:00:00Z")
            pi.import_bundle(library, bundle, NOW)
        return library

    def test_merge_is_commutative_associative_and_idempotent(self):
        rng = random.Random(7)
        render = pi.render_library
        for _ in range(60):
            a, b, c = (self.random_library(rng) for _ in range(3))
            ab, _ = pi.merge_libraries(a, b)
            ba, _ = pi.merge_libraries(b, a)
            self.assertEqual(render(ab), render(ba))
            left, _ = pi.merge_libraries(ab, c)
            bc, _ = pi.merge_libraries(b, c)
            right, _ = pi.merge_libraries(a, bc)
            self.assertEqual(render(left), render(right))
            again, duplicates = pi.merge_libraries(ab, ab)
            self.assertEqual(render(again), render(ab))
            self.assertEqual(duplicates, len(ab["observations"]))
            with_empty, _ = pi.merge_libraries(a, pi.empty_library())
            self.assertEqual(render(with_empty), render(pi.merge_libraries(a, a)[0]))

    def test_order_is_total_even_for_hand_edited_libraries(self):
        library = library_of(make())
        twin = dict(library["observations"][0], category="other-category")
        one = copy.deepcopy(library)
        one["observations"] = [library["observations"][0], twin]
        two = copy.deepcopy(library)
        two["observations"] = [twin, library["observations"][0]]
        self.assertEqual(pi.render_library(pi.merge_libraries(one, pi.empty_library())[0]),
                         pi.render_library(pi.merge_libraries(two, pi.empty_library())[0]))

    def test_merge_does_not_share_mutable_state_with_inputs(self):
        left = library_of(make())
        merged, _ = pi.merge_libraries(left, pi.empty_library())
        next(iter(merged["content"].values()))["text"] = "changed"
        pi.validate_library(left)

    def test_example_nodes_merge(self):
        merged, duplicates = pi.merge_libraries(pi.load_library(EXAMPLES / "nodes" / "node-a.json"),
                                                pi.load_library(EXAMPLES / "nodes" / "node-b.json"))
        self.assertEqual(duplicates, 0)
        self.assertEqual(statuses(merged), {("library-hours", 1): "CURRENT", ("road-closure", 1): "EXPIRED",
                                            ("water-point", 1): "SUPERSEDED", ("water-point", 2): "CURRENT"})


class ValidationTests(unittest.TestCase):
    def test_control_characters_are_rejected_but_text_may_have_lines_and_tabs(self):
        pi.validate_bundle(make(text="Line one\n\tLine two\r\nLine three"), NOW)
        for kwargs in ({"text": "Alert \x1b[2J"}, {"title": "Title\nsecond"}, {"source": "Desk\x07"},
                       {"item_id": "id\x85"}, {"category": "c\x00"}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(ValueError, "control character"):
                    pi.validate_bundle(make(**kwargs), NOW)

    def test_unpaired_surrogates_are_rejected(self):
        bundle = make()
        bundle["items"][0]["text"] = "bad \ud800"
        with self.assertRaisesRegex(ValueError, "surrogate"):
            pi.validate_bundle(bundle, NOW)

    def test_revision_bounds(self):
        pi.validate_bundle(make(revision=pi.MAX_REVISION), NOW)
        for revision in (0, -1, pi.MAX_REVISION + 1, True, 1.0, "1"):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(ValueError, "revision"):
                    pi.validate_bundle(resign(make(revision=revision)), NOW)

    def test_labels_must_not_have_surrounding_whitespace_or_be_blank(self):
        for kwargs in ({"source": " Desk"}, {"category": "   "}, {"item_id": "x" * 121}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    pi.validate_bundle(make(**kwargs), NOW)

    def test_items_must_be_a_non_empty_array_of_objects(self):
        for items in ([], {}, ["x"]):
            bundle = make()
            bundle["items"] = items
            with self.subTest(items=items):
                with self.assertRaises(ValueError):
                    pi.validate_bundle(resign(bundle), NOW)
        with self.assertRaisesRegex(ValueError, "must be a JSON object"):
            pi.validate_bundle([], NOW)

    def test_library_validation(self):
        good = library_of(make())
        cases = {
            "orphan content": lambda lib: lib["content"].update(
                {pi.content_sha256("T", "orphan"): {"title": "T", "text": "orphan"}}),
            "missing content": lambda lib: lib["content"].clear(),
            "duplicate observation": lambda lib: lib["observations"].append(dict(lib["observations"][0])),
            "bad schema": lambda lib: lib.update(schema="other"),
            "bad content key": lambda lib: lib["content"].update({"ABC": {"title": "T", "text": "x"}}),
            "observations not a list": lambda lib: lib.update(observations={}),
            "bad bundle digest": lambda lib: lib["observations"][0].update(bundle_sha256="x"),
            "bad observation language": lambda lib: lib["observations"][0].update(language="english language"),
            "bad observation window": lambda lib: lib["observations"][0].update(expires_at="2026-01-01T00:00:00Z"),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                library = copy.deepcopy(good)
                mutate(library)
                with self.assertRaises(ValueError):
                    pi.validate_library(library)


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, data: bytes):
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_strict_json_reading(self):
        cases = {
            "nan.json": b'{"version": NaN}',
            "latin1.json": b'{"x": "\xe9"}',
            "broken.json": b'{"x": ',
            "deep.json": b"[" * 100000 + b"]" * 100000,
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    pi.read_json(self.write(name, data))
        bom = self.write("bom.json", b"\xef\xbb\xbf" + json.dumps(make()).encode("utf-8"))
        self.assertEqual(pi.validate_bundle(pi.read_json(bom), NOW), "CURRENT")
        with mock.patch.object(pi, "MAX_JSON_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "larger than 10 bytes"):
                pi.read_json(self.write("big.json", b'{"a": "0123456789"}'))

    def test_write_is_atomic_and_cleans_up_on_failure(self):
        target = self.root / "nested" / "store.json"
        library = library_of(make())
        pi.write_library(target, library)
        before = target.read_bytes()
        self.assertEqual(before.decode("utf-8"), pi.render_library(library))
        self.assertNotIn(b"\r\n", before)
        bigger = library_of(make(), make(item_id="other"))
        with mock.patch.object(pi.os, "replace", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                pi.write_library(target, bigger)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual([p.name for p in target.parent.iterdir()], ["store.json"])

    def test_invalid_library_is_never_written(self):
        target = self.root / "store.json"
        broken = library_of(make())
        broken["content"].clear()
        with self.assertRaises(ValueError):
            pi.write_library(target, broken)
        self.assertFalse(target.exists())

    def test_example_nodes_are_reproduced_from_the_example_bundles(self):
        def bundle(name):
            return pi.read_json(EXAMPLES / "bundles" / f"{name}.json")

        store_a, store_b = self.root / "a.json", self.root / "b.json"
        pi.write_library(store_a, library_of(bundle("harbor-base"), bundle("expired-notice")))
        pi.write_library(store_b, library_of(bundle("harbor-update")))
        self.assertEqual(store_a.read_bytes(), (EXAMPLES / "nodes" / "node-a.json").read_bytes())
        self.assertEqual(store_b.read_bytes(), (EXAMPLES / "nodes" / "node-b.json").read_bytes())


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = pi.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def bundle_path(self, name):
        return str(EXAMPLES / "bundles" / f"{name}.json")

    def test_exit_codes(self):
        store = str(self.root / "store.json")
        self.assertEqual(self.run_main("validate", self.bundle_path("harbor-base"), "--as-of", AS_OF)[0], 0)
        code, out, _ = self.run_main("validate", self.bundle_path("expired-notice"), "--as-of", AS_OF)
        self.assertEqual(code, 0)
        self.assertIn("status: EXPIRED", out)
        self.assertEqual(self.run_main("import", self.bundle_path("harbor-update"), "--store", store,
                                       "--as-of", AS_OF)[0], 0)
        code, out, _ = self.run_main("import", self.bundle_path("conflicting-revision"), "--store", store,
                                     "--as-of", AS_OF)
        self.assertEqual(code, 2)
        self.assertIn("CONFLICT Harbor Mutual Aid/water-point@2", out)
        self.assertEqual(len(pi.load_library(store)["observations"]), 3)  # written despite the conflict
        code, out, _ = self.run_main("list", store, "--as-of", AS_OF)
        self.assertEqual(code, 2)
        self.assertIn("[CONFLICT; ACTIVE WINDOW]", out)
        merged = str(self.root / "merged.json")
        self.assertEqual(self.run_main("merge", store, str(EXAMPLES / "nodes" / "node-a.json"),
                                       "--output", merged)[0], 2)
        empty = self.root / "empty.json"
        pi.write_library(empty, pi.empty_library())
        self.assertEqual(self.run_main("list", str(empty))[1], "Library is empty.\n")

    def test_errors_exit_1_and_usage_errors_do_not_look_like_conflicts(self):
        bad = self.root / "bad.json"
        bad.write_text("{}", encoding="utf-8")
        for argv in (("validate", str(bad)), ("validate", str(self.root / "missing.json")),
                     ("validate", self.bundle_path("harbor-base"), "--as-of", "2026-09-30"),
                     ("validate", self.bundle_path("harbor-base"), "--as-of", ""),
                     ("list", str(bad)), ("merge", str(bad), str(bad), "--output", str(self.root / "o.json")),
                     ("import", self.bundle_path("harbor-base"), "--store", self.bundle_path("harbor-base"))):
            with self.subTest(argv=argv):
                code, _, err = self.run_main(*argv)
                self.assertEqual(code, 1)
                self.assertIn("ERROR: ", err)
        for argv in ((), ("import", self.bundle_path("harbor-base")), ("frobnicate",)):
            with self.subTest(argv=argv):
                self.assertEqual(self.run_main(*argv)[0], 1)
        self.assertFalse((self.root / "o.json").exists())

    def test_version_matches_citation_and_packaging(self):
        code, out, _ = self.run_main("--version")
        self.assertEqual((code, out.strip()), (0, f"pocket-internet {pi.__version__}"))
        citation = (PROJECT_DIR / "CITATION.cff").read_text(encoding="utf-8")
        self.assertEqual(re.search(r"^version: (\S+)$", citation, re.M).group(1), pi.__version__)
        self.assertIn('version = { attr = "pocket_internet.__version__" }',
                      (PROJECT_DIR / "pyproject.toml").read_text(encoding="utf-8"))

    def test_non_utf8_console_does_not_break_listing(self):
        env = dict(os.environ, PYTHONIOENCODING="ascii")
        result = subprocess.run([sys.executable, "pocket_internet.py", "list", "examples/nodes/node-b.json",
                                 "--as-of", AS_OF], cwd=PROJECT_DIR, env=env, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"\\u2013", result.stdout)  # the en dash is escaped, not a crash


class OfflineTests(unittest.TestCase):
    def test_module_imports_only_offline_standard_library_modules(self):
        tree = ast.parse((PROJECT_DIR / "pocket_internet.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        allowed = {"__future__", "argparse", "collections", "datetime", "hashlib", "json", "os", "pathlib", "re",
                   "sys", "tempfile", "typing", "unicodedata"}
        self.assertLessEqual(imported, allowed)

    def test_cli_runs_with_networking_disabled(self):
        probe = (
            "import socket, sys\n"
            "def refuse(*a, **k): raise RuntimeError('network access attempted')\n"
            "socket.socket = refuse; socket.create_connection = refuse; socket.getaddrinfo = refuse\n"
            "sys.argv = ['pocket_internet.py'] + sys.argv[1:]\n"
            "import runpy; runpy.run_path('pocket_internet.py', run_name='__main__')\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, "-c", probe, "merge", "examples/nodes/node-a.json",
                                     "examples/nodes/node-b.json", "--output", str(Path(tmp) / "m.json")],
                                    cwd=PROJECT_DIR, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
