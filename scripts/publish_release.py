#!/usr/bin/env python3

from __future__ import annotations

import argparse
import filecmp
import json
import re
import sys
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Protocol

try:
    from . import release_state, verify_intake
    from .intake_selection import PUBLICATION_LOCK_BRANCH
    from .publisher_gateway import CommandGateway, GatewayError
except ImportError:
    import release_state
    import verify_intake
    from intake_selection import PUBLICATION_LOCK_BRANCH
    from publisher_gateway import CommandGateway, GatewayError


COMMIT = re.compile(r"[0-9a-f]{40}")
REPOSITORY = "Balllvin/marauder-notebook-releases"
INTAKE_REPOSITORY = "Balllvin/marauder-notebook-release-intake"


class PublishError(RuntimeError):
    pass


class PublishState(IntEnum):
    INITIAL = 0
    DRAFT_READY = 1
    ASSETS_VERIFIED = 2
    PUBLISH_ATTEMPTED = 3
    PUBLISHED = 4
    ATTESTED = 5


@dataclass(frozen=True)
class PublishConfig:
    repository: str
    intake_repository: str
    publisher_commit: str
    release_version: str
    build_number: str
    release_tag: str
    archive_name: str
    source_commit: str
    intake_branch: str
    intake_commit: str
    publication_lock_commit: str | None
    intake: Path
    work: Path
    distribution_mode: str


class Gateway(Protocol):
    def head(self) -> str: ...
    def is_ancestor(self, ancestor: str, descendant: str) -> bool: ...
    def intake_target(self, repository: str, branch: str) -> str | None: ...
    def current_tag_target(self, repository: str, tag: str) -> str | None: ...
    def list_releases(self, repository: str) -> list[object]: ...
    def create_draft(self, repository: str, payload: dict[str, object]) -> object: ...
    def get_release(self, repository: str, release_id: str) -> object: ...
    def delete_release(self, repository: str, release_id: str) -> None: ...
    def list_assets(self, repository: str, release_id: str) -> list[object]: ...
    def download_asset(self, repository: str, asset_id: str, output: Path) -> None: ...
    def upload_asset(self, repository: str, tag: str, path: Path) -> None: ...
    def publish(self, repository: str, tag: str) -> Exception | None: ...
    def verify_release(self, repository: str, tag: str) -> bool: ...
    def verify_asset(self, repository: str, tag: str, path: Path) -> None: ...
    def wait(self, seconds: int) -> None: ...


class ReleasePublisher:
    def __init__(self, gateway: Gateway, config: PublishConfig) -> None:
        self.gateway = gateway
        self.config = config
        self.state = PublishState.INITIAL
        self.owned_release_id: str | None = None

    def _approved_commit(self, commit: str) -> str:
        if COMMIT.fullmatch(commit) is None or not self.gateway.is_ancestor(
            commit, self.config.publisher_commit
        ):
            raise PublishError("release target is not approved publisher history")
        return commit

    def _assert_intake_unchanged(self) -> None:
        if self.gateway.intake_target(
            self.config.intake_repository, self.config.intake_branch
        ) != self.config.intake_commit:
            raise PublishError("intake ref changed during publication")
        if self.gateway.intake_target(
            self.config.intake_repository, PUBLICATION_LOCK_BRANCH
        ) != self.config.publication_lock_commit:
            raise PublishError("publication lock changed during publication")

    def _cleanup_owned_draft(self) -> None:
        if self.owned_release_id is None or self.state >= PublishState.PUBLISH_ATTEMPTED:
            return
        current = self.gateway.get_release(self.config.repository, self.owned_release_id)
        if not release_state.cleanup_allowed(
            current,
            owned_release_id=self.owned_release_id,
            tag=self.config.release_tag,
            publish_attempted=False,
        ):
            raise PublishError("owned draft no longer satisfies the cleanup boundary")
        self.gateway.delete_release(self.config.repository, self.owned_release_id)

    def run(self) -> PublishState:
        try:
            self._run()
        except Exception as publication_error:
            try:
                self._cleanup_owned_draft()
            except Exception as cleanup_error:
                raise PublishError(
                    f"publication failed and owned draft cleanup failed: {cleanup_error}"
                ) from publication_error
            raise
        return self.state

    def _run(self) -> None:
        cfg = self.config
        if self.gateway.head() != cfg.publisher_commit:
            raise PublishError("publisher HEAD changed after protected-main verification")
        self._assert_intake_unchanged()
        cfg.work.mkdir(mode=0o700, parents=True, exist_ok=False)
        notes = cfg.work / "release-notes.md"
        note = (
            "Developer ID signed and notarized universal macOS application."
            if cfg.distribution_mode == "developer-id"
            else "Independently signed universal macOS application. No Apple account is required; macOS may ask for one Open Anyway confirmation on first launch."
        )
        notes.write_text(
            f"Marauder Notebook {cfg.release_version} ({cfg.build_number})\n\n{note}\n"
            f"Source: Balllvin/marauder@{cfg.source_commit}\n",
            encoding="utf-8",
        )
        title = f"Marauder Notebook {cfg.release_version} ({cfg.build_number})"
        expected = sorted((cfg.archive_name, f"{cfg.archive_name}.sha256", "appcast.xml", "notebook-release.json", "update-feed.json"))
        tag_target = self.gateway.current_tag_target(cfg.repository, cfg.release_tag)
        if tag_target is not None:
            tag_target = self._approved_commit(tag_target)

        plan = release_state.select_draft(
            self.gateway.list_releases(cfg.repository),
            tag=cfg.release_tag,
            title=title,
            body=notes.read_text(encoding="utf-8"),
        )
        if plan["mode"] == "recover":
            release_id = str(plan["release_id"])
            release_target = self._approved_commit(str(plan["target_commitish"]))
            if tag_target is not None and release_target != tag_target:
                raise PublishError("recovered draft and tag target differ")
            tag_target = tag_target or release_target
        else:
            created = self.gateway.create_draft(
                cfg.repository,
                {
                    "tag_name": cfg.release_tag,
                    "target_commitish": tag_target or cfg.publisher_commit,
                    "name": title,
                    "body": notes.read_text(encoding="utf-8"),
                    "draft": True,
                    "prerelease": False,
                    "make_latest": "false",
                },
            )
            if (
                isinstance(created, dict)
                and isinstance(created.get("id"), int)
                and not isinstance(created.get("id"), bool)
                and created["id"] > 0
                and created.get("tag_name") == cfg.release_tag
                and created.get("draft") is True
                and created.get("prerelease") is False
            ):
                # Claim only the exact draft returned by this create call before
                # deeper validation so a malformed response cannot leak it.
                self.owned_release_id = str(created["id"])
            created_plan = release_state.validate_created_draft(
                created, tag=cfg.release_tag, title=title, body=notes.read_text(encoding="utf-8")
            )
            release_id = str(created_plan["release_id"])
            if self.owned_release_id != release_id:
                raise PublishError("created draft ownership could not be established")
            release_target = self._approved_commit(str(created_plan["target_commitish"]))
            current_target = self.gateway.current_tag_target(cfg.repository, cfg.release_tag)
            if current_target is not None and self._approved_commit(current_target) != release_target:
                raise PublishError("created draft and tag target differ")
            tag_target = current_target or release_target
        assert tag_target is not None
        self.state = PublishState.DRAFT_READY

        asset_plan = release_state.plan_assets(
            self.gateway.list_assets(cfg.repository, release_id), expected
        )
        for name, asset_id in asset_plan["present"].items():
            downloaded = cfg.work / f"existing-{name}"
            self.gateway.download_asset(cfg.repository, str(asset_id), downloaded)
            if not filecmp.cmp(cfg.intake / name, downloaded, shallow=False):
                raise PublishError(f"existing draft asset differs: {name}")
        for name in asset_plan["missing"]:
            self.gateway.upload_asset(cfg.repository, cfg.release_tag, cfg.intake / name)

        final_plan = release_state.plan_assets(
            self.gateway.list_assets(cfg.repository, release_id), expected
        )
        if final_plan["missing"]:
            raise PublishError("draft is still missing release assets")
        downloaded_root = cfg.work / "downloaded-release"
        downloaded_root.mkdir()
        for name in expected:
            downloaded = downloaded_root / name
            self.gateway.download_asset(
                cfg.repository, str(final_plan["present"][name]), downloaded
            )
            if not filecmp.cmp(cfg.intake / name, downloaded, shallow=False):
                raise PublishError(f"uploaded release asset differs: {name}")
        self.state = PublishState.ASSETS_VERIFIED

        releases_path = cfg.work / "final-releases.json"
        releases_path.write_text(
            json.dumps(self.gateway.list_releases(cfg.repository)), encoding="utf-8"
        )
        verify_intake.assert_newer(cfg.intake / "notebook-release.json", releases_path)
        self._assert_intake_unchanged()
        self.state = PublishState.PUBLISH_ATTEMPTED
        publish_error = self.gateway.publish(cfg.repository, cfg.release_tag)
        current_release = self.gateway.get_release(cfg.repository, release_id)
        try:
            release_state.validate_published(
                current_release, release_id=release_id, tag=cfg.release_tag
            )
        except release_state.ReleaseStateError:
            if publish_error is not None:
                raise publish_error
            raise PublishError("GitHub accepted publication but still reports a draft")
        if self._approved_commit(
            self.gateway.current_tag_target(cfg.repository, cfg.release_tag) or ""
        ) != tag_target:
            raise PublishError("published tag target changed")
        self.state = PublishState.PUBLISHED
        for attempt in range(12):
            if self.gateway.verify_release(cfg.repository, cfg.release_tag):
                break
            if attempt < 11:
                self.gateway.wait(5)
        else:
            raise PublishError("immutable release attestation was not produced")
        for name in expected:
            self.gateway.verify_asset(cfg.repository, cfg.release_tag, cfg.intake / name)
        self.owned_release_id = None
        self.state = PublishState.ATTESTED


def _config(arguments: argparse.Namespace) -> PublishConfig:
    values = (arguments.publisher_commit, arguments.source_commit, arguments.intake_commit)
    if any(COMMIT.fullmatch(value) is None for value in values):
        raise PublishError("publisher, source, and intake commits must be exact lowercase SHAs")
    if arguments.repository != REPOSITORY or arguments.intake_repository != INTAKE_REPOSITORY:
        raise PublishError("publisher repositories do not match the protected contract")
    publication_lock_commit = (
        None if arguments.publication_lock_commit == "none" else arguments.publication_lock_commit
    )
    if publication_lock_commit is not None and (
        COMMIT.fullmatch(publication_lock_commit) is None
        or publication_lock_commit != arguments.intake_commit
    ):
        raise PublishError("publication lock does not identify the selected intake")
    if arguments.distribution_mode not in ("independent", "developer-id"):
        raise PublishError("unsupported distribution mode")
    if (
        verify_intake.SEMANTIC_VERSION.fullmatch(arguments.release_version) is None
        or not arguments.build_number.isascii()
        or not arguments.build_number.isdigit()
        or arguments.build_number.startswith("0")
        or int(arguments.build_number) < 1
    ):
        raise PublishError("release version and build identity are invalid")
    expected_tag = f"notebook-v{arguments.release_version}-{arguments.build_number}"
    expected_archive = (
        f"Marauder-Notebook-{arguments.release_version}-{arguments.build_number}-universal.zip"
    )
    expected_branch = (
        f"publication/{arguments.release_version}-{arguments.build_number}-"
        f"{arguments.source_commit}"
    )
    if (
        arguments.release_tag != expected_tag
        or arguments.archive_name != expected_archive
        or arguments.intake_branch != expected_branch
    ):
        raise PublishError("release tag, archive, or intake branch identity does not match")
    return PublishConfig(
        repository=arguments.repository,
        intake_repository=arguments.intake_repository,
        publisher_commit=arguments.publisher_commit,
        release_version=arguments.release_version,
        build_number=arguments.build_number,
        release_tag=arguments.release_tag,
        archive_name=arguments.archive_name,
        source_commit=arguments.source_commit,
        intake_branch=arguments.intake_branch,
        intake_commit=arguments.intake_commit,
        publication_lock_commit=publication_lock_commit,
        intake=arguments.intake,
        work=arguments.work,
        distribution_mode=arguments.distribution_mode,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Publish one verified immutable Notebook release")
    for name in (
        "repository", "intake-repository", "publisher-commit", "release-version",
        "build-number", "release-tag", "archive-name", "source-commit", "intake-branch",
        "intake-commit", "publication-lock-commit", "distribution-mode",
    ):
        result.add_argument(f"--{name}", required=True)
    result.add_argument("--intake", required=True, type=Path)
    result.add_argument("--work", required=True, type=Path)
    return result


def main() -> int:
    try:
        arguments = parser().parse_args()
        gateway = CommandGateway()
        config = _config(arguments)
        ReleasePublisher(gateway, config).run()
    except (
        PublishError,
        GatewayError,
        release_state.ReleaseStateError,
        verify_intake.IntakeError,
        OSError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
