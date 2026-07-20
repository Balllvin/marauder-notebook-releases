#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, BinaryIO

try:
    from . import intake_selection, verify_intake
except ImportError:
    import intake_selection
    import verify_intake


INTAKE_REPOSITORY = "Balllvin/marauder-notebook-release-intake"
PUBLICATION_LOCK_REF = intake_selection.PUBLICATION_LOCK_REF
COMMIT_PATTERN = intake_selection.COMMIT_PATTERN
BRANCH_PATTERN = intake_selection.BRANCH_PATTERN


class PreparationError(ValueError):
    pass


def _run_git(
    repository: Path,
    *arguments: str,
    capture: bool = True,
    stdout: BinaryIO | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            stdout=subprocess.PIPE if capture else stdout,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise PreparationError(f"unable to run git: {error}") from error
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise PreparationError(message or f"git {' '.join(arguments)} failed")
    return result


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreparationError(f"unable to read {path.name}: {error}") from error


def _flatten_pages(payload: object, label: str) -> list[object]:
    if not isinstance(payload, list):
        raise PreparationError(f"{label} must be a JSON array")
    if payload and all(isinstance(page, list) for page in payload):
        return [item for page in payload for item in page]
    if any(isinstance(page, list) for page in payload):
        raise PreparationError(f"{label} has inconsistent pagination")
    return payload


def _select_pending_intake(refs: list[object], releases: list[object]) -> dict[str, object]:
    try:
        return intake_selection.select_pending_intake(refs, releases)
    except intake_selection.SelectionError as error:
        raise PreparationError(str(error)) from error


def select_pending_intake(refs_path: Path, releases_path: Path) -> dict[str, object]:
    refs = _flatten_pages(_read_json(refs_path), "intake refs")
    releases = _flatten_pages(_read_json(releases_path), "release list")
    return _select_pending_intake(refs, releases)


def discover_pending_intake(repository_url: str, releases_path: Path) -> dict[str, object]:
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git", repository_url):
        raise PreparationError("intake repository URL must be a fixed public GitHub clone URL")
    try:
        result = subprocess.run(
            [
                "git",
                "ls-remote",
                "--heads",
                repository_url,
                "refs/heads/publication/*",
                PUBLICATION_LOCK_REF,
            ],
            check=False,
            capture_output=True,
        )
    except OSError as error:
        raise PreparationError(f"unable to discover public intake refs: {error}") from error
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise PreparationError(message or "unable to discover public intake refs")
    refs: list[object] = []
    malformed_ref_count = 0
    for line in result.stdout.splitlines():
        try:
            raw_commit, raw_ref = line.split(b"\t", 1)
            commit = raw_commit.decode("ascii")
            ref = raw_ref.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            malformed_ref_count += 1
            continue
        refs.append({"ref": ref, "object": {"type": "commit", "sha": commit}})
    releases = _flatten_pages(_read_json(releases_path), "release list")
    selection = _select_pending_intake(refs, releases)
    selection["ignored_ref_count"] = int(selection["ignored_ref_count"]) + malformed_ref_count
    return selection


def _require_empty_output(output: Path) -> None:
    if output.is_symlink():
        raise PreparationError("output directory cannot be a symbolic link")
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            raise PreparationError("output directory must be empty")
    else:
        output.mkdir(parents=True, mode=0o700)
    os.chmod(output, 0o700)


def _blob_size(repository: Path, commit: str, path: str) -> int:
    raw = _run_git(repository, "cat-file", "-s", f"{commit}:{path}").stdout
    try:
        return int(raw.decode("ascii").strip())
    except ValueError as error:
        raise PreparationError(f"unable to read blob size for {path}") from error


def _extract_blob(
    repository: Path,
    commit: str,
    git_path: str,
    destination: Path,
    maximum_bytes: int,
) -> None:
    size = _blob_size(repository, commit, git_path)
    if size < 0 or size > maximum_bytes:
        raise PreparationError(f"{git_path} exceeds its size limit")
    with destination.open("xb") as output_file:
        _run_git(
            repository,
            "show",
            f"{commit}:{git_path}",
            capture=False,
            stdout=output_file,
        )
    os.chmod(destination, 0o600)
    if destination.stat().st_size != size:
        raise PreparationError(f"extracted size does not match {git_path}")


def _tree_entries(repository: Path, commit: str, paths: list[str]) -> dict[str, tuple[str, str]]:
    payload = _run_git(repository, "ls-tree", "-z", commit, "--", *paths).stdout
    result: dict[str, tuple[str, str]] = {}
    for record in payload.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, _object_id = header.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError) as error:
            raise PreparationError("intake tree contains an invalid entry") from error
        if path in result:
            raise PreparationError("intake tree contains a duplicate path")
        result[path] = (mode, kind)
    return result


def prepare_intake(
    repository: Path,
    commit: str,
    branch: str,
    output: Path,
    *,
    openssl: str,
    trusted_main_ref: str = "origin/main",
) -> dict[str, str]:
    if COMMIT_PATTERN.fullmatch(commit) is None or BRANCH_PATTERN.fullmatch(branch) is None:
        raise PreparationError("publication commit or branch has an invalid identity")
    if not repository.is_dir():
        raise PreparationError("intake repository is missing")
    _require_empty_output(output)

    parent_line = _run_git(repository, "rev-list", "--parents", "-n", "1", commit).stdout.decode("ascii").split()
    if len(parent_line) != 2 or parent_line[0] != commit:
        raise PreparationError("intake commit must have exactly one parent")
    parent = parent_line[1]
    ancestor = subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", parent, trusted_main_ref],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if ancestor.returncode != 0:
        raise PreparationError("intake parent is not trusted main history")
    parent_intake = _run_git(repository, "ls-tree", "-r", "--name-only", "-z", parent, "--", "intake").stdout
    if parent_intake:
        raise PreparationError("trusted intake main must not contain release payloads")

    metadata_git_path = "intake/notebook-release.json"
    _extract_blob(repository, commit, metadata_git_path, output / "notebook-release.json", 32 * 1024)
    metadata = _read_json(output / "notebook-release.json")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("asset"), dict):
        raise PreparationError("release metadata has no asset object")
    archive_name = metadata["asset"].get("name")
    if not isinstance(archive_name, str) or re.fullmatch(
        r"Marauder-Notebook-(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-[1-9][0-9]*-universal\.zip",
        archive_name,
    ) is None:
        raise PreparationError("release metadata has an invalid archive name")
    expected_paths = [
        f"intake/{archive_name}",
        f"intake/{archive_name}.sha256",
        "intake/appcast.xml",
        metadata_git_path,
        "intake/update-feed.json",
    ]

    diff_payload = _run_git(repository, "diff-tree", "--no-commit-id", "--name-only", "-z", "-r", commit).stdout
    try:
        diff_paths = [path.decode("utf-8", errors="strict") for path in diff_payload.split(b"\0") if path]
    except UnicodeDecodeError as error:
        raise PreparationError("intake commit contains a non-UTF-8 path") from error
    if sorted(diff_paths) != sorted(expected_paths) or len(diff_paths) != len(expected_paths):
        raise PreparationError("intake commit must add exactly the five approved release paths")
    added_payload = _run_git(
        repository,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "--diff-filter=A",
        "-z",
        "-r",
        commit,
    ).stdout
    added_paths = [path.decode("utf-8", errors="strict") for path in added_payload.split(b"\0") if path]
    if sorted(added_paths) != sorted(expected_paths):
        raise PreparationError("all five intake paths must be newly added")
    entries = _tree_entries(repository, commit, expected_paths)
    if set(entries) != set(expected_paths) or any(entry != ("100644", "blob") for entry in entries.values()):
        raise PreparationError("intake paths must be ordinary non-executable blobs")

    limits = {
        archive_name: 512 * 1024 * 1024,
        f"{archive_name}.sha256": 1024,
        "appcast.xml": 1024 * 1024,
        "update-feed.json": 32 * 1024,
    }
    for name, maximum_bytes in limits.items():
        _extract_blob(repository, commit, f"intake/{name}", output / name, maximum_bytes)
    result = verify_intake.validate_intake(output, branch, openssl=openssl)
    result["intake_commit"] = commit
    return result


def prepare_pending_intake(
    repository: Path,
    selection_path: Path,
    output: Path,
    *,
    openssl: str,
    trusted_main_ref: str = "origin/main",
) -> dict[str, object]:
    selection = _read_json(selection_path)
    if not isinstance(selection, dict) or not isinstance(selection.get("available"), bool):
        raise PreparationError("intake selection has no boolean availability")
    candidates = selection.get("candidates")
    if not isinstance(candidates, list):
        raise PreparationError("intake selection has no candidate list")
    publication_lock_commit = selection.get("publication_lock_commit")
    if publication_lock_commit != "none" and (
        not isinstance(publication_lock_commit, str)
        or COMMIT_PATTERN.fullmatch(publication_lock_commit) is None
    ):
        raise PreparationError("intake selection has an invalid publication lock")
    if publication_lock_commit != "none" and any(
        not isinstance(candidate, dict)
        or candidate.get("commit") != publication_lock_commit
        for candidate in candidates
    ):
        raise PreparationError("locked intake selection contains a different candidate")
    if selection["available"] is False:
        if candidates:
            raise PreparationError("unavailable intake selection cannot contain candidates")
        return {
            "available": False,
            "invalid_candidate_count": 0,
            "invalid_candidates": [],
            "publication_lock_commit": publication_lock_commit,
        }
    if publication_lock_commit == "none":
        raise PreparationError("available intake selection requires a publication lock")
    if not candidates:
        raise PreparationError("available intake selection has no candidates")
    if output.exists() or output.is_symlink():
        raise PreparationError("verified intake output must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True)

    invalid: list[dict[str, str]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise PreparationError("intake candidate is not an object")
        branch = candidate.get("branch")
        commit = candidate.get("commit")
        if not isinstance(branch, str) or not isinstance(commit, str):
            raise PreparationError("intake candidate has an invalid identity")
        with tempfile.TemporaryDirectory(
            prefix="notebook-intake-candidate-", dir=output.parent
        ) as temporary:
            candidate_output = Path(temporary) / "verified"
            try:
                result: dict[str, object] = prepare_intake(
                    repository,
                    commit,
                    branch,
                    candidate_output,
                    openssl=openssl,
                    trusted_main_ref=trusted_main_ref,
                )
            except (PreparationError, verify_intake.IntakeError) as error:
                invalid.append({"branch": branch, "reason": str(error)[:512]})
                continue
            shutil.move(str(candidate_output), output)
            result["available"] = True
            result["invalid_candidate_count"] = len(invalid)
            result["invalid_candidates"] = invalid
            result["publication_lock_commit"] = publication_lock_commit
            return result
    raise PreparationError(
        f"all {len(invalid)} pending intake candidates failed verification"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Select and extract inert Notebook release intake data")
    subparsers = result.add_subparsers(dest="command", required=True)
    select = subparsers.add_parser("select")
    source = select.add_mutually_exclusive_group(required=True)
    source.add_argument("--refs", type=Path)
    source.add_argument("--repository-url")
    select.add_argument("--releases", required=True, type=Path)
    select.add_argument("--result", required=True, type=Path)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--repository", required=True, type=Path)
    prepare.add_argument("--commit", required=True)
    prepare.add_argument("--branch", required=True)
    prepare.add_argument("--output", required=True, type=Path)
    prepare.add_argument("--openssl", default="openssl")
    prepare.add_argument("--trusted-main-ref", default="origin/main")
    prepare.add_argument("--result", required=True, type=Path)
    pending = subparsers.add_parser("prepare-pending")
    pending.add_argument("--repository", required=True, type=Path)
    pending.add_argument("--selection", required=True, type=Path)
    pending.add_argument("--output", required=True, type=Path)
    pending.add_argument("--openssl", default="openssl")
    pending.add_argument("--trusted-main-ref", default="origin/main")
    pending.add_argument("--result", required=True, type=Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "select":
            if arguments.repository_url:
                result: dict[str, Any] = discover_pending_intake(
                    arguments.repository_url,
                    arguments.releases,
                )
            else:
                result = select_pending_intake(arguments.refs, arguments.releases)
        elif arguments.command == "prepare":
            result = prepare_intake(
                arguments.repository,
                arguments.commit,
                arguments.branch,
                arguments.output,
                openssl=arguments.openssl,
                trusted_main_ref=arguments.trusted_main_ref,
            )
        else:
            result = prepare_pending_intake(
                arguments.repository,
                arguments.selection,
                arguments.output,
                openssl=arguments.openssl,
                trusted_main_ref=arguments.trusted_main_ref,
            )
        arguments.result.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    except (PreparationError, verify_intake.IntakeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
