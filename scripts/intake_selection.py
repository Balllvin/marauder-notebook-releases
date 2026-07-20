#!/usr/bin/env python3

from __future__ import annotations

import re
from dataclasses import dataclass

try:
    from . import verify_intake
except ImportError:
    import verify_intake


PUBLICATION_LOCK_BRANCH = "publication-lock/notebook"
PUBLICATION_LOCK_REF = f"refs/heads/{PUBLICATION_LOCK_BRANCH}"
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
BRANCH_PATTERN = re.compile(
    r"publication/"
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-"
    r"([1-9][0-9]*)-([0-9a-f]{40})"
)


class SelectionError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class IntakeCandidate:
    version: tuple[int, int, int]
    build: int
    branch: str
    commit: str
    tag: str

    def result(self) -> dict[str, str]:
        return {"branch": self.branch, "commit": self.commit}


def _publication_lock(refs: list[object]) -> tuple[str | None, list[object]]:
    commit: str | None = None
    publication_refs: list[object] = []
    for payload in refs:
        if not isinstance(payload, dict) or payload.get("ref") != PUBLICATION_LOCK_REF:
            publication_refs.append(payload)
            continue
        target = payload.get("object")
        if not isinstance(target, dict):
            raise SelectionError("publication lock has no target")
        target_commit = target.get("sha")
        if (
            target.get("type") != "commit"
            or not isinstance(target_commit, str)
            or COMMIT_PATTERN.fullmatch(target_commit) is None
        ):
            raise SelectionError("publication lock target is not a commit")
        if commit is not None and commit != target_commit:
            raise SelectionError("publication lock has conflicting targets")
        commit = target_commit
    return commit, publication_refs


def _publication_history(
    releases: list[object],
) -> tuple[set[str], tuple[int, int, int], int]:
    tags: set[str] = set()
    identities: list[tuple[tuple[int, int, int], int]] = []
    for release in releases:
        if not isinstance(release, dict):
            raise SelectionError("release list contains a non-object")
        if release.get("draft") is True:
            continue
        if release.get("prerelease") is True:
            raise SelectionError("the release repository cannot contain prereleases")
        tag = release.get("tag_name")
        if not isinstance(tag, str):
            raise SelectionError("the dedicated repository contains a non-Notebook release")
        match = verify_intake.RELEASE_TAG.fullmatch(tag)
        if match is None:
            raise SelectionError("the dedicated repository contains a non-Notebook release")
        tags.add(tag)
        identities.append(
            (tuple(int(part) for part in match.groups()[:3]), int(match.group(4)))
        )
    highest_version = max((identity[0] for identity in identities), default=(0, 0, 0))
    highest_build = max((identity[1] for identity in identities), default=0)
    return tags, highest_version, highest_build


def _candidate(payload: object) -> IntakeCandidate | None:
    if not isinstance(payload, dict):
        return None
    ref = payload.get("ref")
    target = payload.get("object")
    if not isinstance(ref, str) or not ref.startswith("refs/heads/") or not isinstance(target, dict):
        return None
    branch = ref.removeprefix("refs/heads/")
    match = BRANCH_PATTERN.fullmatch(branch)
    commit = target.get("sha")
    if (
        match is None
        or target.get("type") != "commit"
        or not isinstance(commit, str)
        or COMMIT_PATTERN.fullmatch(commit) is None
    ):
        return None
    version = tuple(int(part) for part in match.groups()[:3])
    if version == (0, 0, 0):
        return None
    build = int(match.group(4))
    return IntakeCandidate(
        version=version,
        build=build,
        branch=branch,
        commit=commit,
        tag=f"notebook-v{'.'.join(str(part) for part in version)}-{build}",
    )


def _locked_candidates(
    candidates: list[IntakeCandidate],
    lock_commit: str,
    published_tags: set[str],
    highest_version: tuple[int, int, int],
    highest_build: int,
) -> tuple[list[IntakeCandidate], int, bool]:
    matching = [candidate for candidate in candidates if candidate.commit == lock_commit]
    if len(matching) != 1:
        raise SelectionError("publication lock must identify exactly one versioned intake branch")
    locked = matching[0]
    if locked.tag in published_tags:
        return [], 0, True
    if locked.version <= highest_version or locked.build <= highest_build:
        raise SelectionError("locked publication intake is stale or non-monotonic")
    eligible_count = sum(
        candidate.tag not in published_tags
        and candidate.version > highest_version
        and candidate.build > highest_build
        for candidate in candidates
    )
    return [locked], max(eligible_count - 1, 0), False


def select_pending_intake(refs: list[object], releases: list[object]) -> dict[str, object]:
    lock_commit, publication_refs = _publication_lock(refs)
    published_tags, highest_version, highest_build = _publication_history(releases)

    candidates: list[IntakeCandidate] = []
    seen_branches: set[str] = set()
    ignored = 0
    for payload in publication_refs:
        candidate = _candidate(payload)
        if candidate is None:
            ignored += 1
            continue
        if candidate.branch in seen_branches:
            continue
        seen_branches.add(candidate.branch)
        candidates.append(candidate)

    if lock_commit is None:
        if candidates:
            raise SelectionError("publication intake exists without the required lock")
        return {
            "available": False,
            "candidates": [],
            "ignored_ref_count": ignored,
            "publication_lock_commit": "none",
        }
    selected, selection_ignored, already_published = _locked_candidates(
        candidates, lock_commit, published_tags, highest_version, highest_build
    )
    ignored += selection_ignored

    selected.sort()
    prepared = [candidate.result() for candidate in selected]
    lock_result = lock_commit or "none"
    if already_published or not prepared:
        return {
            "available": False,
            "candidates": [],
            "ignored_ref_count": ignored,
            "publication_lock_commit": lock_result,
        }
    return {
        "available": True,
        "branch": prepared[0]["branch"],
        "commit": prepared[0]["commit"],
        "candidates": prepared,
        "ignored_ref_count": ignored,
        "publication_lock_commit": lock_result,
    }
