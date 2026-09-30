import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import pocket_internet as pi

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
ISSUED = "2026-09-29T09:00:00Z"
EXPIRES = "2026-10-15T00:00:00Z"


def bundle(item_id="notice", revision=1, title="Clinic hours", text="Open 09:00–17:00", *, issued=ISSUED, expires=EXPIRES, source="Community Desk"):
    return pi.make_bundle(
        source_label=source,
        category="health",
        language="en",
        issued_at=issued,
        expires_at=expires,
        items=[{"item_id": item_id, "revision": revision, "title": title, "text": text}],
    )


def resign(value):
    value = copy.deepcopy(value)
    value.pop("digest", None)
    value["digest"] = pi.sha256_json(value)
    return value


class PocketInternetTests(unittest.TestCase):
    def test_hash_validation_and_tampering(self):
        valid = bundle()
        self.assertEqual(pi.validate_bundle(valid, NOW), "CURRENT")
        altered = copy.deepcopy(valid)
        altered["items"][0]["text"] = "Open 24 hours"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            pi.validate_bundle(altered, NOW)
        altered["digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            pi.validate_bundle(altered, NOW)

    def test_duplicate_import_is_idempotent_and_content_is_deduplicated(self):
        library = pi.empty_library()
        one = bundle()
        self.assertEqual(pi.import_bundle(library, one, NOW)[:2], (1, 0))
        self.assertEqual(pi.import_bundle(library, one, NOW)[:2], (0, 1))
        other_identity = bundle(item_id="another-id")
        self.assertEqual(pi.import_bundle(library, other_identity, NOW)[:2], (1, 0))
        self.assertEqual(len(library["observations"]), 2)
        self.assertEqual(len(library["content"]), 1)

    def test_expiry_is_explicit_and_never_current(self):
        expired = bundle(issued="2026-09-01T00:00:00Z", expires="2026-09-10T00:00:00Z")
        self.assertEqual(pi.validate_bundle(expired, NOW), "EXPIRED")
        library = pi.empty_library()
        pi.import_bundle(library, expired, NOW)
        statuses = {row["status"] for row in pi.listing_rows(library, NOW)}
        self.assertEqual(statuses, {"EXPIRED"})
        self.assertNotIn("CURRENT", statuses)

    def test_expired_observation_stays_labeled_after_same_content_is_reissued(self):
        library = pi.empty_library()
        pi.import_bundle(library, bundle(issued="2026-09-01T00:00:00Z", expires="2026-09-10T00:00:00Z"), NOW)
        pi.import_bundle(library, bundle(issued="2026-09-29T00:00:00Z", expires="2026-10-10T00:00:00Z"), NOW)
        row = pi.listing_rows(library, NOW)[0]
        self.assertEqual(row["status"], "CURRENT")
        self.assertEqual({window[2] for window in row["windows"]}, {"EXPIRED", "CURRENT"})

    def test_same_revision_conflict_is_preserved_and_reported(self):
        library = pi.empty_library()
        pi.import_bundle(library, bundle(text="Evacuation point: north hall"), NOW)
        pi.import_bundle(library, bundle(text="Evacuation point: school gym"), NOW)
        self.assertEqual(len(pi.conflicts(library)), 1)
        self.assertEqual(len(library["content"]), 2)
        rows = pi.listing_rows(library, NOW)
        self.assertEqual({row["status"] for row in rows}, {"CONFLICT; ACTIVE WINDOW"})

    def test_merge_unions_revisions_deduplicates_and_keeps_conflicts(self):
        left, right = pi.empty_library(), pi.empty_library()
        pi.import_bundle(left, bundle(revision=1, text="Old public hours"), NOW)
        pi.import_bundle(right, bundle(revision=2, text="Updated public hours"), NOW)
        merged, duplicates = pi.merge_libraries(left, right)
        self.assertEqual(duplicates, 0)
        self.assertEqual(len(merged["observations"]), 2)
        self.assertEqual(len(merged["content"]), 2)
        row_statuses = {row["revision"]: row["status"] for row in pi.listing_rows(merged, NOW)}
        self.assertEqual(row_statuses, {1: "SUPERSEDED", 2: "CURRENT"})

        conflicting = pi.empty_library()
        pi.import_bundle(conflicting, bundle(text="A competing revision"), NOW)
        joined, _ = pi.merge_libraries(left, conflicting)
        self.assertEqual(len(pi.conflicts(joined)), 1)
        self.assertTrue(any(row["status"].startswith("CONFLICT") for row in pi.listing_rows(joined, NOW)))

    def test_invalid_schema_version_language_time_and_revision(self):
        cases = []
        bad_schema = bundle()
        bad_schema["schema"] = "other"
        cases.append(bad_schema)
        bad_version = bundle()
        bad_version["version"] = True
        cases.append(resign(bad_version))
        bad_language = bundle()
        bad_language["language"] = "not a language tag"
        cases.append(resign(bad_language))
        no_timezone = bundle()
        no_timezone["issued_at"] = "2026-09-29T09:00:00"
        cases.append(resign(no_timezone))
        bad_revision = bundle()
        bad_revision["items"][0]["revision"] = 0
        cases.append(resign(bad_revision))
        duplicate_id = bundle()
        duplicate_id["items"].append(copy.deepcopy(duplicate_id["items"][0]))
        cases.append(resign(duplicate_id))
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    pi.validate_bundle(case, NOW)

    def test_unexpected_fields_and_duplicate_json_keys_rejected(self):
        extra = bundle()
        extra["unrecognized"] = "ambiguous"
        with self.assertRaisesRegex(ValueError, "unexpected"):
            pi.validate_bundle(extra, NOW)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "duplicate.json"
            path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                pi.read_json(path)

    def test_library_content_tampering_rejected(self):
        library = pi.empty_library()
        pi.import_bundle(library, bundle(), NOW)
        digest = next(iter(library["content"]))
        library["content"][digest]["text"] = "substituted"
        with self.assertRaisesRegex(ValueError, "content digest mismatch"):
            pi.validate_library(library)


if __name__ == "__main__":
    unittest.main()
