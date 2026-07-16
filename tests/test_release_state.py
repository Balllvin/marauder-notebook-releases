from __future__ import annotations

import unittest

from scripts import release_state


TAG = "notebook-v1.2.3-42"
TITLE = "Marauder Notebook 1.2.3 (42)"
BODY = "Independently signed universal macOS application.\n"
TARGET = "a" * 40
EXPECTED_ASSETS = [
    "Marauder-Notebook-1.2.3-42-universal.zip",
    "Marauder-Notebook-1.2.3-42-universal.zip.sha256",
    "appcast.xml",
    "notebook-release.json",
    "update-feed.json",
]


def draft(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": 17,
        "tag_name": TAG,
        "target_commitish": TARGET,
        "name": TITLE,
        "body": BODY,
        "draft": True,
        "prerelease": False,
    }
    payload.update(overrides)
    return payload


def asset(name: str, identifier: int) -> dict[str, object]:
    return {"id": identifier, "name": name, "state": "uploaded", "size": 10}


class ReleaseStateTests(unittest.TestCase):
    def test_selects_create_or_exact_recoverable_draft(self) -> None:
        self.assertEqual(
            release_state.select_draft([], tag=TAG, title=TITLE, body=BODY),
            {"mode": "create"},
        )
        self.assertEqual(
            release_state.select_draft([draft()], tag=TAG, title=TITLE, body=BODY),
            {"mode": "recover", "release_id": "17", "target_commitish": TARGET},
        )

    def test_rejects_duplicate_published_or_mismatched_draft_identity(self) -> None:
        cases = (
            [draft(), draft(id=18)],
            [draft(draft=False)],
            [draft(prerelease=True)],
            [draft(name="Other")],
            [draft(body="Other")],
            [draft(target_commitish="main")],
        )
        for releases in cases:
            with self.subTest(releases=releases):
                with self.assertRaises(release_state.ReleaseStateError):
                    release_state.select_draft(releases, tag=TAG, title=TITLE, body=BODY)

    def test_partial_asset_plan_uploads_only_missing_exact_assets(self) -> None:
        existing = [asset(EXPECTED_ASSETS[0], 1), asset(EXPECTED_ASSETS[2], 3)]
        plan = release_state.plan_assets(existing, EXPECTED_ASSETS)
        self.assertEqual(plan["present"], {EXPECTED_ASSETS[0]: "1", EXPECTED_ASSETS[2]: "3"})
        self.assertEqual(
            plan["missing"],
            [EXPECTED_ASSETS[1], EXPECTED_ASSETS[3], EXPECTED_ASSETS[4]],
        )

    def test_rejects_unexpected_duplicate_incomplete_or_empty_asset(self) -> None:
        cases = (
            [asset("unexpected", 1)],
            [asset(EXPECTED_ASSETS[0], 1), asset(EXPECTED_ASSETS[0], 2)],
            [{**asset(EXPECTED_ASSETS[0], 1), "state": "new"}],
            [{**asset(EXPECTED_ASSETS[0], 1), "size": 0}],
        )
        for assets in cases:
            with self.subTest(assets=assets):
                with self.assertRaises(release_state.ReleaseStateError):
                    release_state.plan_assets(assets, EXPECTED_ASSETS)

    def test_cleanup_requires_exact_owned_draft_and_no_publish_attempt(self) -> None:
        self.assertTrue(
            release_state.cleanup_allowed(
                draft(),
                owned_release_id="17",
                tag=TAG,
                publish_attempted=False,
            )
        )
        for current, owned, attempted in (
            (draft(), "17", True),
            (draft(id=18), "17", False),
            (draft(tag_name="other"), "17", False),
            (draft(draft=False), "17", False),
        ):
            with self.subTest(current=current, owned=owned, attempted=attempted):
                self.assertFalse(
                    release_state.cleanup_allowed(
                        current,
                        owned_release_id=owned,
                        tag=TAG,
                        publish_attempted=attempted,
                    )
                )

    def test_published_validation_handles_lost_publish_response(self) -> None:
        published = draft(draft=False)
        release_state.validate_published(published, release_id="17", tag=TAG)
        with self.assertRaises(release_state.ReleaseStateError):
            release_state.validate_published(draft(), release_id="17", tag=TAG)

    def test_audits_every_published_release_in_monotonic_order(self) -> None:
        releases = [
            draft(id=4, tag_name="notebook-v1.3.0-50", draft=False, immutable=True),
            draft(id=2, tag_name="notebook-v1.2.3-42", draft=False, immutable=True),
            draft(id=8, tag_name="notebook-v1.4.0-51"),
        ]
        self.assertEqual(
            release_state.audit_published(releases),
            {"tags": ["notebook-v1.2.3-42", "notebook-v1.3.0-50"]},
        )

    def test_published_audit_rejects_mutable_duplicate_or_nonmonotonic_history(self) -> None:
        cases = (
            [draft(draft=False, immutable=False)],
            [draft(draft=False, immutable=True), draft(id=18, draft=False, immutable=True)],
            [draft(draft=False, immutable=True, prerelease=True)],
            [draft(draft=False, immutable=True, tag_name="other-v1")],
            [
                draft(id=1, draft=False, immutable=True, tag_name="notebook-v1.2.3-50"),
                draft(id=2, draft=False, immutable=True, tag_name="notebook-v1.3.0-49"),
            ],
        )
        for releases in cases:
            with self.subTest(releases=releases):
                with self.assertRaises(release_state.ReleaseStateError):
                    release_state.audit_published(releases)


if __name__ == "__main__":
    unittest.main()
