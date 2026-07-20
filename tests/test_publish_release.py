from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from scripts.publish_release import (
    PublishConfig,
    PublishError,
    PublishState,
    PUBLICATION_LOCK_BRANCH,
    ReleasePublisher,
    _config,
)
from scripts.publisher_gateway import GatewayError


PUBLISHER_COMMIT = "a" * 40
SOURCE_COMMIT = "b" * 40
INTAKE_COMMIT = "c" * 40
TAG = "notebook-v1.2.3-42"
ARCHIVE = "Marauder-Notebook-1.2.3-42-universal.zip"
BRANCH = f"publication/1.2.3-42-{SOURCE_COMMIT}"
EXPECTED = sorted(
    (
        ARCHIVE,
        f"{ARCHIVE}.sha256",
        "appcast.xml",
        "notebook-release.json",
        "update-feed.json",
    )
)


def release_body() -> str:
    return (
        "Marauder Notebook 1.2.3 (42)\n\n"
        "Independently signed universal macOS application. No Apple account is required; "
        "macOS may ask for one Open Anyway confirmation on first launch.\n"
        f"Source: Balllvin/marauder@{SOURCE_COMMIT}\n"
    )


def release_payload(*, draft: bool = True) -> dict[str, object]:
    return {
        "id": 17,
        "tag_name": TAG,
        "target_commitish": PUBLISHER_COMMIT,
        "name": "Marauder Notebook 1.2.3 (42)",
        "body": release_body(),
        "draft": draft,
        "prerelease": False,
    }


class FakeGateway:
    def __init__(self, *, recovered: bool = False) -> None:
        self.release = release_payload() if recovered else None
        self.assets: dict[str, tuple[str, bytes]] = {}
        self.next_asset_id = 100
        self.tag_target: str | None = PUBLISHER_COMMIT if recovered else None
        self.deleted: list[str] = []
        self.uploaded: list[str] = []
        self.publish_error: Exception | None = None
        self.publish_changes_server = True
        self.verify_results = [True]
        self.waits: list[int] = []
        self.verified_assets: list[str] = []
        self.delete_error: Exception | None = None
        self.intake_targets: dict[str, str | None] = {
            BRANCH: INTAKE_COMMIT,
            PUBLICATION_LOCK_BRANCH: INTAKE_COMMIT,
        }
        self.intake_snapshot_sequence: list[dict[str, str | None]] = []

    def head(self) -> str:
        return PUBLISHER_COMMIT

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        return ancestor == PUBLISHER_COMMIT and descendant == PUBLISHER_COMMIT

    def intake_snapshot(
        self, repository: str, branches: tuple[str, ...]
    ) -> dict[str, str | None]:
        if self.intake_snapshot_sequence:
            return self.intake_snapshot_sequence.pop(0)
        return {branch: self.intake_targets.get(branch) for branch in branches}

    def current_tag_target(self, repository: str, tag: str) -> str | None:
        return self.tag_target

    def list_releases(self, repository: str) -> list[object]:
        return [] if self.release is None else [dict(self.release)]

    def create_draft(self, repository: str, payload: dict[str, object]) -> object:
        self.release = {"id": 17, **payload}
        self.tag_target = PUBLISHER_COMMIT
        return dict(self.release)

    def get_release(self, repository: str, release_id: str) -> object:
        if self.release is None:
            raise GatewayError("missing release")
        return dict(self.release)

    def delete_release(self, repository: str, release_id: str) -> None:
        if self.delete_error is not None:
            raise self.delete_error
        self.deleted.append(release_id)
        self.release = None

    def list_assets(self, repository: str, release_id: str) -> list[object]:
        return [
            {
                "id": int(identifier),
                "name": name,
                "state": "uploaded",
                "size": len(content),
            }
            for name, (identifier, content) in self.assets.items()
        ]

    def download_asset(self, repository: str, asset_id: str, output: Path) -> None:
        for _name, (identifier, content) in self.assets.items():
            if identifier == asset_id:
                output.write_bytes(content)
                return
        raise GatewayError("missing asset")

    def upload_asset(self, repository: str, tag: str, path: Path) -> None:
        self.next_asset_id += 1
        self.assets[path.name] = (str(self.next_asset_id), path.read_bytes())
        self.uploaded.append(path.name)

    def publish(self, repository: str, tag: str) -> Exception | None:
        if self.publish_changes_server:
            assert self.release is not None
            self.release["draft"] = False
        return self.publish_error

    def verify_release(self, repository: str, tag: str) -> bool:
        return self.verify_results.pop(0)

    def verify_asset(self, repository: str, tag: str, path: Path) -> None:
        self.verified_assets.append(path.name)

    def wait(self, seconds: int) -> None:
        self.waits.append(seconds)


class PublishReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        root = Path(self.temporary_directory.name)
        self.intake = root / "intake"
        self.intake.mkdir()
        for name in EXPECTED:
            content = json.dumps({"version": "1.2.3", "build_number": "42"}).encode() if name == "notebook-release.json" else f"content:{name}".encode()
            (self.intake / name).write_bytes(content)
        self.config = PublishConfig(
            repository="Balllvin/marauder-notebook-releases",
            intake_repository="Balllvin/marauder-notebook-release-intake",
            publisher_commit=PUBLISHER_COMMIT,
            release_version="1.2.3",
            build_number="42",
            release_tag=TAG,
            archive_name=ARCHIVE,
            source_commit=SOURCE_COMMIT,
            intake_branch=BRANCH,
            intake_commit=INTAKE_COMMIT,
            publication_lock_commit=INTAKE_COMMIT,
            intake=self.intake,
            work=root / "work",
            distribution_mode="independent",
        )

    def publisher(self, gateway: FakeGateway) -> ReleasePublisher:
        return ReleasePublisher(gateway, self.config)

    def config_arguments(self, publication_lock_commit: str) -> Namespace:
        return Namespace(
            repository=self.config.repository,
            intake_repository=self.config.intake_repository,
            publisher_commit=self.config.publisher_commit,
            release_version=self.config.release_version,
            build_number=self.config.build_number,
            release_tag=self.config.release_tag,
            archive_name=self.config.archive_name,
            source_commit=self.config.source_commit,
            intake_branch=self.config.intake_branch,
            intake_commit=self.config.intake_commit,
            publication_lock_commit=publication_lock_commit,
            intake=self.config.intake,
            work=self.config.work,
            distribution_mode=self.config.distribution_mode,
        )

    def test_new_draft_uploads_exact_assets_and_reaches_attested_state(self) -> None:
        gateway = FakeGateway()
        publisher = self.publisher(gateway)
        self.assertEqual(publisher.run(), PublishState.ATTESTED)
        self.assertEqual(gateway.uploaded, EXPECTED)
        self.assertEqual(gateway.verified_assets, EXPECTED)
        self.assertEqual(gateway.deleted, [])
        self.assertIsNone(publisher.owned_release_id)

    def test_config_requires_the_lock_to_identify_the_intake(self) -> None:
        with self.assertRaisesRegex(PublishError, "does not identify"):
            _config(self.config_arguments("none"))
        with self.assertRaisesRegex(PublishError, "does not identify"):
            _config(self.config_arguments("d" * 40))

    def test_lock_change_before_work_fails_without_creating_a_draft(self) -> None:
        gateway = FakeGateway()
        gateway.intake_targets[PUBLICATION_LOCK_BRANCH] = "d" * 40
        with self.assertRaisesRegex(PublishError, "publication lock changed"):
            self.publisher(gateway).run()
        self.assertIsNone(gateway.release)

    def test_lock_change_before_publish_removes_the_owned_draft(self) -> None:
        gateway = FakeGateway()
        gateway.intake_snapshot_sequence = [
            {BRANCH: INTAKE_COMMIT, PUBLICATION_LOCK_BRANCH: INTAKE_COMMIT},
            {BRANCH: INTAKE_COMMIT, PUBLICATION_LOCK_BRANCH: "d" * 40},
        ]
        publisher = self.publisher(gateway)
        with self.assertRaisesRegex(PublishError, "publication lock changed"):
            publisher.run()
        self.assertEqual(gateway.deleted, ["17"])
        self.assertEqual(publisher.state, PublishState.ASSETS_VERIFIED)

    def test_snapshot_rejects_a_changed_intake_and_lock_together(self) -> None:
        gateway = FakeGateway()
        gateway.intake_targets[BRANCH] = "d" * 40
        gateway.intake_targets[PUBLICATION_LOCK_BRANCH] = "d" * 40
        with self.assertRaisesRegex(PublishError, "intake ref changed"):
            self.publisher(gateway).run()
        self.assertIsNone(gateway.release)

    def test_recovered_partial_draft_uploads_only_missing_and_is_never_deleted(self) -> None:
        gateway = FakeGateway(recovered=True)
        gateway.assets[EXPECTED[0]] = ("1", (self.intake / EXPECTED[0]).read_bytes())
        gateway.publish_changes_server = False
        gateway.publish_error = GatewayError("publish rejected")
        publisher = self.publisher(gateway)
        with self.assertRaisesRegex(GatewayError, "publish rejected"):
            publisher.run()
        self.assertEqual(gateway.uploaded, EXPECTED[1:])
        self.assertEqual(gateway.deleted, [])
        self.assertEqual(publisher.state, PublishState.PUBLISH_ATTEMPTED)

    def test_owned_new_draft_is_deleted_when_asset_verification_fails(self) -> None:
        gateway = FakeGateway()
        gateway.assets[EXPECTED[0]] = ("1", b"different")
        publisher = self.publisher(gateway)
        with self.assertRaisesRegex(PublishError, "existing draft asset differs"):
            publisher.run()
        self.assertEqual(gateway.deleted, ["17"])
        self.assertEqual(publisher.state, PublishState.DRAFT_READY)

    def test_lost_publish_response_is_reconciled_from_published_server_state(self) -> None:
        gateway = FakeGateway()
        gateway.publish_error = GatewayError("response lost")
        self.assertEqual(self.publisher(gateway).run(), PublishState.ATTESTED)

    def test_failed_publish_attempt_is_not_cleaned_up(self) -> None:
        gateway = FakeGateway()
        gateway.publish_changes_server = False
        gateway.publish_error = GatewayError("publish failed")
        publisher = self.publisher(gateway)
        with self.assertRaisesRegex(GatewayError, "publish failed"):
            publisher.run()
        self.assertEqual(publisher.state, PublishState.PUBLISH_ATTEMPTED)
        self.assertEqual(gateway.deleted, [])

    def test_attestation_is_retried_without_republishing(self) -> None:
        gateway = FakeGateway()
        gateway.verify_results = [False, False, True]
        self.assertEqual(self.publisher(gateway).run(), PublishState.ATTESTED)
        self.assertEqual(gateway.waits, [5, 5])

    def test_recovered_mismatched_asset_fails_without_deleting_foreign_draft(self) -> None:
        gateway = FakeGateway(recovered=True)
        gateway.assets[EXPECTED[0]] = ("1", b"different")
        with self.assertRaisesRegex(PublishError, "existing draft asset differs"):
            self.publisher(gateway).run()
        self.assertEqual(gateway.deleted, [])

    def test_owned_draft_cleanup_failure_is_reported_not_silenced(self) -> None:
        gateway = FakeGateway()
        gateway.assets[EXPECTED[0]] = ("1", b"different")
        gateway.delete_error = GatewayError("cleanup rejected")
        with self.assertRaisesRegex(
            PublishError,
            "publication failed and owned draft cleanup failed: cleanup rejected",
        ):
            self.publisher(gateway).run()


if __name__ == "__main__":
    unittest.main()
