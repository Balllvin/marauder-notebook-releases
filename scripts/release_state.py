#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


COMMIT = re.compile(r"[0-9a-f]{40}")
RELEASE_TAG = re.compile(
    r"notebook-v(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)-([1-9][0-9]*)"
)


class ReleaseStateError(ValueError):
    pass


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseStateError(f"unable to read {path.name}: {error}") from error


def _flatten_pages(payload: object, label: str) -> list[object]:
    if not isinstance(payload, list):
        raise ReleaseStateError(f"{label} must be a JSON array")
    if payload and all(isinstance(page, list) for page in payload):
        return [item for page in payload for item in page]
    if any(isinstance(page, list) for page in payload):
        raise ReleaseStateError(f"{label} has inconsistent pagination")
    return payload


def _positive_identifier(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ReleaseStateError(f"{label} must be a positive integer")
    return value


def _validate_draft(
    release: object,
    *,
    tag: str,
    title: str,
    body: str,
) -> dict[str, object]:
    if not isinstance(release, dict):
        raise ReleaseStateError("the release is not an object")
    if release.get("draft") is not True or release.get("prerelease") is not False:
        raise ReleaseStateError("the recoverable release must be a non-prerelease draft")
    if release.get("tag_name") != tag or release.get("name") != title or release.get("body") != body:
        raise ReleaseStateError("the recoverable draft identity does not match")
    target = release.get("target_commitish")
    if not isinstance(target, str) or COMMIT.fullmatch(target) is None:
        raise ReleaseStateError("the recoverable draft target is not an exact publisher commit")
    return {
        "release_id": str(_positive_identifier(release.get("id"), "release id")),
        "target_commitish": target,
    }


def select_draft(
    releases: list[object],
    *,
    tag: str,
    title: str,
    body: str,
) -> dict[str, object]:
    matches = [
        release
        for release in releases
        if isinstance(release, dict) and release.get("tag_name") == tag
    ]
    if len(matches) > 1:
        raise ReleaseStateError("multiple releases claim the same tag")
    if not matches:
        return {"mode": "create"}
    validated = _validate_draft(matches[0], tag=tag, title=title, body=body)
    return {"mode": "recover", **validated}


def validate_created_draft(
    release: object,
    *,
    tag: str,
    title: str,
    body: str,
) -> dict[str, object]:
    return _validate_draft(release, tag=tag, title=title, body=body)


def _expected_names(path: Path) -> list[str]:
    try:
        names = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ReleaseStateError(f"unable to read {path.name}: {error}") from error
    if (
        not names
        or len(names) != len(set(names))
        or any(not name or Path(name).name != name for name in names)
    ):
        raise ReleaseStateError("the expected asset list is invalid")
    return names


def plan_assets(assets: list[object], expected_names: list[str]) -> dict[str, object]:
    expected = set(expected_names)
    present: dict[str, str] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ReleaseStateError("the asset list contains a non-object")
        name = asset.get("name")
        if not isinstance(name, str) or name not in expected:
            raise ReleaseStateError("the draft contains an unexpected asset")
        if name in present:
            raise ReleaseStateError("the draft contains a duplicate asset")
        if asset.get("state") != "uploaded":
            raise ReleaseStateError("a draft asset has not finished uploading")
        size = asset.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ReleaseStateError("a draft asset has an invalid size")
        present[name] = str(_positive_identifier(asset.get("id"), "asset id"))
    return {
        "present": present,
        "missing": [name for name in expected_names if name not in present],
    }


def cleanup_allowed(
    release: object,
    *,
    owned_release_id: str,
    tag: str,
    publish_attempted: bool,
) -> bool:
    if publish_attempted or not isinstance(release, dict):
        return False
    try:
        release_id = str(_positive_identifier(release.get("id"), "release id"))
    except ReleaseStateError:
        return False
    return (
        release_id == owned_release_id
        and release.get("tag_name") == tag
        and release.get("draft") is True
        and release.get("prerelease") is False
    )


def validate_published(release: object, *, release_id: str, tag: str) -> None:
    if not isinstance(release, dict):
        raise ReleaseStateError("the published release is not an object")
    if (
        str(_positive_identifier(release.get("id"), "release id")) != release_id
        or release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
    ):
        raise ReleaseStateError("GitHub does not report the exact release as published")


def audit_published(releases: list[object]) -> dict[str, object]:
    seen_ids: set[int] = set()
    seen_tags: set[str] = set()
    published: list[tuple[tuple[int, int, int], int, str]] = []
    for release in releases:
        if not isinstance(release, dict):
            raise ReleaseStateError("the release list contains a non-object")
        identifier = _positive_identifier(release.get("id"), "release id")
        if identifier in seen_ids:
            raise ReleaseStateError("the release list contains a duplicate id")
        seen_ids.add(identifier)
        tag = release.get("tag_name")
        if not isinstance(tag, str) or (match := RELEASE_TAG.fullmatch(tag)) is None:
            raise ReleaseStateError("the dedicated repository contains a non-Notebook release")
        if tag in seen_tags:
            raise ReleaseStateError("multiple releases claim the same tag")
        seen_tags.add(tag)
        draft = release.get("draft")
        prerelease = release.get("prerelease")
        if not isinstance(draft, bool) or not isinstance(prerelease, bool):
            raise ReleaseStateError("release publication flags must be booleans")
        if prerelease:
            raise ReleaseStateError("the dedicated repository cannot contain prereleases")
        if draft:
            continue
        if release.get("immutable") is not True:
            raise ReleaseStateError("every published release must be immutable")
        version = tuple(int(part) for part in match.groups()[:3])
        build = int(match.group(4))
        if version == (0, 0, 0):
            raise ReleaseStateError("published release version must be positive")
        published.append((version, build, tag))

    published.sort()
    for previous, current in zip(published, published[1:]):
        if current[0] <= previous[0] or current[1] <= previous[1]:
            raise ReleaseStateError("published versions and builds must be strictly increasing")
    return {"tags": [tag for _version, _build, tag in published]}


def _write_result(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Validate recoverable GitHub release state")
    subparsers = result.add_subparsers(dest="command", required=True)

    select = subparsers.add_parser("select-draft")
    select.add_argument("--releases", required=True, type=Path)
    select.add_argument("--tag", required=True)
    select.add_argument("--title", required=True)
    select.add_argument("--body", required=True, type=Path)
    select.add_argument("--result", required=True, type=Path)

    created = subparsers.add_parser("validate-created-draft")
    created.add_argument("--release", required=True, type=Path)
    created.add_argument("--tag", required=True)
    created.add_argument("--title", required=True)
    created.add_argument("--body", required=True, type=Path)
    created.add_argument("--result", required=True, type=Path)

    assets = subparsers.add_parser("plan-assets")
    assets.add_argument("--assets", required=True, type=Path)
    assets.add_argument("--expected", required=True, type=Path)
    assets.add_argument("--result", required=True, type=Path)

    cleanup = subparsers.add_parser("cleanup-allowed")
    cleanup.add_argument("--release", required=True, type=Path)
    cleanup.add_argument("--owned-release-id", required=True)
    cleanup.add_argument("--tag", required=True)
    cleanup.add_argument("--publish-attempted", required=True, choices=("true", "false"))

    published = subparsers.add_parser("validate-published")
    published.add_argument("--release", required=True, type=Path)
    published.add_argument("--release-id", required=True)
    published.add_argument("--tag", required=True)

    audit = subparsers.add_parser("audit-published")
    audit.add_argument("--releases", required=True, type=Path)
    audit.add_argument("--result", required=True, type=Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "select-draft":
            releases = _flatten_pages(_read_json(arguments.releases), "release list")
            body = arguments.body.read_text(encoding="utf-8")
            _write_result(
                arguments.result,
                select_draft(releases, tag=arguments.tag, title=arguments.title, body=body),
            )
        elif arguments.command == "validate-created-draft":
            body = arguments.body.read_text(encoding="utf-8")
            _write_result(
                arguments.result,
                validate_created_draft(
                    _read_json(arguments.release),
                    tag=arguments.tag,
                    title=arguments.title,
                    body=body,
                ),
            )
        elif arguments.command == "plan-assets":
            assets = _flatten_pages(_read_json(arguments.assets), "asset list")
            _write_result(arguments.result, plan_assets(assets, _expected_names(arguments.expected)))
        elif arguments.command == "cleanup-allowed":
            if not cleanup_allowed(
                _read_json(arguments.release),
                owned_release_id=arguments.owned_release_id,
                tag=arguments.tag,
                publish_attempted=arguments.publish_attempted == "true",
            ):
                return 1
        elif arguments.command == "validate-published":
            validate_published(
                _read_json(arguments.release),
                release_id=arguments.release_id,
                tag=arguments.tag,
            )
        else:
            releases = _flatten_pages(_read_json(arguments.releases), "release list")
            _write_result(arguments.result, audit_published(releases))
    except (ReleaseStateError, OSError, UnicodeDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
