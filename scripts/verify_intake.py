#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


RELEASE_REPOSITORY = "Balllvin/marauder-notebook-releases"
SOURCE_REPOSITORY = "Balllvin/marauder"
PRODUCT_NAME = "Marauder Notebook"
PUBLIC_ED_KEY = "tWzGidYf3K08nkhu45CwWt/uJWERB+MT+UrpYjy4OXU="
RELEASE_ROOT = f"https://github.com/{RELEASE_REPOSITORY}/releases"
FEED_URL = f"{RELEASE_ROOT}/latest/download/appcast.xml"
DOWNLOAD_URL_PREFIX = f"{RELEASE_ROOT}/download"
METADATA_URL = f"{RELEASE_ROOT}/latest/download/notebook-release.json"
SPARKLE_NAMESPACE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
SEMANTIC_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
BUILD_NUMBER = re.compile(r"[1-9][0-9]*")
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}")
RELEASE_TAG = re.compile(r"notebook-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-([1-9][0-9]*)")
FEED_SIGNATURE_BLOCK = re.compile(
    rb"<!-- sparkle-signatures:\nedSignature: ([A-Za-z0-9+/]+={0,2})\nlength: ([1-9][0-9]*)\n-->\n\Z"
)
ED25519_SUBJECT_PUBLIC_KEY_PREFIX = bytes.fromhex("302a300506032b6570032100")


class IntakeError(ValueError):
    pass


def _without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IntakeError(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, maximum_bytes: int) -> dict[str, Any]:
    _require_regular_file(path, maximum_bytes)
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_without_duplicate_keys,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntakeError(f"unable to read {path.name}: {error}") from error
    if not isinstance(payload, dict):
        raise IntakeError(f"{path.name} must contain one JSON object")
    return payload


def _require_regular_file(path: Path, maximum_bytes: int | None = None) -> None:
    if path.is_symlink() or not path.is_file():
        raise IntakeError(f"{path.name} must be a regular file")
    if maximum_bytes is not None and path.stat().st_size > maximum_bytes:
        raise IntakeError(f"{path.name} exceeds its size limit")


def _require_exact_keys(payload: dict[str, Any], expected: set[str], label: str) -> None:
    if set(payload) != expected:
        raise IntakeError(f"{label} has unexpected or missing fields")


def _canonical_signature(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise IntakeError(f"{label} is missing")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise IntakeError(f"{label} is not canonical base64") from error
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise IntakeError(f"{label} must be one canonical Ed25519 signature")
    return decoded


def _canonical_public_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise IntakeError("the committed Sparkle public key is invalid") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise IntakeError("the committed Sparkle public key is invalid")
    return decoded


def _verify_ed25519(
    input_path: Path,
    signature: bytes,
    public_key: bytes,
    openssl: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="notebook-intake-signature-") as directory:
        root = Path(directory)
        key_path = root / "public.der"
        signature_path = root / "signature.bin"
        key_path.write_bytes(ED25519_SUBJECT_PUBLIC_KEY_PREFIX + public_key)
        signature_path.write_bytes(signature)
        try:
            result = subprocess.run(
                [
                    openssl,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-keyform",
                    "DER",
                    "-rawin",
                    "-in",
                    str(input_path),
                    "-sigfile",
                    str(signature_path),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as error:
            raise IntakeError(f"unable to run the Ed25519 verifier: {error}") from error
        if result.returncode != 0:
            raise IntakeError(f"Ed25519 signature verification failed for {input_path.name}")


def _release_identity(version: str, build_number: str) -> tuple[tuple[int, int, int], int]:
    match = SEMANTIC_VERSION.fullmatch(version)
    if match is None or all(int(part) == 0 for part in match.groups()):
        raise IntakeError("release version must be a positive semantic version")
    if BUILD_NUMBER.fullmatch(build_number) is None:
        raise IntakeError("build number must be a positive integer without leading zeros")
    return tuple(int(part) for part in match.groups()), int(build_number)


def _validate_trust_manifest(path: Path, public_key: str) -> None:
    payload = _read_json(path, 32 * 1024)
    expected = {
        "schema": 1,
        "enabled": True,
        "repository": RELEASE_REPOSITORY,
        "feed_url": FEED_URL,
        "download_url_prefix": DOWNLOAD_URL_PREFIX,
        "release_metadata_url": METADATA_URL,
        "public_ed_key": public_key,
    }
    if payload != expected:
        raise IntakeError("update-feed.json does not match the committed release trust boundary")


def _canonical_provenance_payload(metadata: dict[str, Any]) -> tuple[bytes, bytes]:
    unsigned_metadata = dict(metadata)
    provenance = unsigned_metadata.pop("provenance", None)
    if not isinstance(provenance, dict):
        raise IntakeError("release provenance must be one signed object")
    _require_exact_keys(provenance, {"algorithm", "sparkle_ed_signature"}, "release provenance")
    if provenance["algorithm"] != "ed25519":
        raise IntakeError("release provenance must use Ed25519")
    signature = _canonical_signature(
        provenance["sparkle_ed_signature"],
        "release provenance signature",
    )
    try:
        canonical = json.dumps(
            unsigned_metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as error:
        raise IntakeError(f"release metadata cannot be canonicalized: {error}") from error
    return canonical, signature


def _verify_provenance(
    metadata: dict[str, Any],
    public_key: bytes,
    openssl: str,
) -> None:
    canonical, signature = _canonical_provenance_payload(metadata)
    with tempfile.NamedTemporaryFile(prefix="notebook-release-provenance-", delete=False) as payload_file:
        payload_path = Path(payload_file.name)
        payload_file.write(canonical)
    try:
        _verify_ed25519(payload_path, signature, public_key, openssl)
    finally:
        payload_path.unlink(missing_ok=True)


def _validate_checksum(archive: Path, checksum: Path, expected_digest: object) -> str:
    _require_regular_file(checksum, 1024)
    if not isinstance(expected_digest, str) or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        raise IntakeError("release metadata has an invalid SHA-256 digest")
    digest = hashlib.sha256()
    with archive.open("rb") as archive_file:
        for chunk in iter(lambda: archive_file.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    expected_line = f"{actual}  {archive.name}\n"
    try:
        checksum_text = checksum.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise IntakeError(f"unable to read {checksum.name}: {error}") from error
    if checksum_text != expected_line:
        raise IntakeError("checksum file must contain the exact archive SHA-256 entry")
    if expected_digest != actual:
        raise IntakeError("release metadata SHA-256 does not match the archive")
    return actual


def _validate_appcast(
    path: Path,
    *,
    archive: Path,
    archive_url: str,
    archive_signature: str,
    version: str,
    build_number: str,
    public_key: bytes,
    openssl: str,
) -> None:
    _require_regular_file(path, 1024 * 1024)
    payload = path.read_bytes()
    if re.search(rb"<!\s*(DOCTYPE|ENTITY)", payload, re.IGNORECASE):
        raise IntakeError("appcast.xml cannot contain document type or entity declarations")
    signature_match = FEED_SIGNATURE_BLOCK.search(payload)
    if signature_match is None:
        raise IntakeError("appcast.xml has no valid signed-feed block")
    feed_signature = _canonical_signature(
        signature_match.group(1).decode("ascii"),
        "appcast feed signature",
    )
    signed_length = int(signature_match.group(2))
    if signed_length != signature_match.start():
        raise IntakeError("appcast signed length does not match its signed content")

    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise IntakeError(f"appcast.xml is not valid XML: {error}") from error
    enclosures = root.findall(".//enclosure")
    if len(enclosures) != 1:
        raise IntakeError("appcast.xml must contain exactly one release enclosure")
    enclosure = enclosures[0]
    containing_items = [
        item for item in root.findall(".//item") if enclosure in item.findall("enclosure")
    ]
    if len(containing_items) != 1:
        raise IntakeError("appcast enclosure must belong to exactly one update item")
    item = containing_items[0]

    def version_value(name: str) -> str | None:
        qualified_name = f"{{{SPARKLE_NAMESPACE}}}{name}"
        attribute_value = enclosure.get(qualified_name)
        elements = item.findall(qualified_name)
        if len(elements) > 1:
            raise IntakeError(f"appcast item has duplicate Sparkle {name} values")
        element_value = None
        if elements:
            element_value = (elements[0].text or "").strip() or None
        if attribute_value and element_value and attribute_value != element_value:
            raise IntakeError(f"appcast has conflicting Sparkle {name} values")
        return attribute_value or element_value

    if enclosure.get("url") != archive_url:
        raise IntakeError("appcast enclosure does not use the immutable archive URL")
    if enclosure.get("length") != str(archive.stat().st_size):
        raise IntakeError("appcast enclosure length does not match the archive")
    if version_value("shortVersionString") != version:
        raise IntakeError("appcast version does not match release metadata")
    if version_value("version") != build_number:
        raise IntakeError("appcast build number does not match release metadata")
    if enclosure.get(f"{{{SPARKLE_NAMESPACE}}}edSignature") != archive_signature:
        raise IntakeError("appcast archive signature does not match release metadata")

    with tempfile.NamedTemporaryFile(prefix="notebook-appcast-content-", delete=False) as signed_file:
        signed_path = Path(signed_file.name)
        signed_file.write(payload[:signed_length])
    try:
        _verify_ed25519(signed_path, feed_signature, public_key, openssl)
    finally:
        signed_path.unlink(missing_ok=True)


def validate_intake(
    intake: Path,
    branch: str,
    *,
    public_key: str = PUBLIC_ED_KEY,
    openssl: str = "openssl",
) -> dict[str, str]:
    if intake.is_symlink() or not intake.is_dir():
        raise IntakeError("intake must be a real directory")
    metadata_path = intake / "notebook-release.json"
    metadata = _read_json(metadata_path, 32 * 1024)
    _require_exact_keys(
        metadata,
        {"schema", "product", "version", "build_number", "tag", "architecture", "source", "asset", "checksum", "appcast", "provenance"},
        "notebook-release.json",
    )
    if metadata["schema"] != 1 or metadata["product"] != PRODUCT_NAME:
        raise IntakeError("release metadata has the wrong schema or product")
    raw_public_key = _canonical_public_key(public_key)
    _verify_provenance(metadata, raw_public_key, openssl)
    version = metadata["version"]
    build_number = metadata["build_number"]
    if not isinstance(version, str) or not isinstance(build_number, str):
        raise IntakeError("release version and build number must be strings")
    _release_identity(version, build_number)
    tag = f"notebook-v{version}-{build_number}"
    if metadata["tag"] != tag or metadata["architecture"] != "universal":
        raise IntakeError("release tag or architecture does not match the release identity")

    source = metadata["source"]
    if not isinstance(source, dict):
        raise IntakeError("release source must be one object")
    _require_exact_keys(
        source,
        {"repository", "commit", "previous_commit"},
        "release source",
    )
    source_commit = source["commit"]
    if source["repository"] != SOURCE_REPOSITORY or not isinstance(source_commit, str) or SOURCE_COMMIT.fullmatch(source_commit) is None:
        raise IntakeError("release source does not identify an exact Marauder commit")
    previous_source_commit = source["previous_commit"]
    if previous_source_commit is not None and (
        not isinstance(previous_source_commit, str)
        or SOURCE_COMMIT.fullmatch(previous_source_commit) is None
    ):
        raise IntakeError("release source has an invalid previous published commit")
    expected_branch = f"publication/{version}-{build_number}-{source_commit}"
    if branch != expected_branch:
        raise IntakeError("publication branch does not match the signed release identity")

    asset = metadata["asset"]
    checksum_metadata = metadata["checksum"]
    appcast_metadata = metadata["appcast"]
    if not isinstance(asset, dict) or not isinstance(checksum_metadata, dict) or not isinstance(appcast_metadata, dict):
        raise IntakeError("release asset metadata must use objects")
    _require_exact_keys(asset, {"name", "url", "length", "sha256", "sparkle_ed_signature"}, "release asset")
    _require_exact_keys(checksum_metadata, {"name", "url"}, "release checksum")
    _require_exact_keys(appcast_metadata, {"name", "url", "enclosure_url"}, "release appcast")

    archive_name = f"Marauder-Notebook-{version}-{build_number}-universal.zip"
    checksum_name = f"{archive_name}.sha256"
    expected_names = {archive_name, checksum_name, "appcast.xml", "notebook-release.json", "update-feed.json"}
    actual_names = {path.name for path in intake.iterdir()}
    if actual_names != expected_names or any(path.is_dir() for path in intake.iterdir()):
        raise IntakeError("intake must contain exactly the five approved release files")
    for path in intake.iterdir():
        if path.is_symlink() or not path.is_file():
            raise IntakeError("intake cannot contain directories, links, or special files")

    archive = intake / archive_name
    checksum = intake / checksum_name
    appcast = intake / "appcast.xml"
    _require_regular_file(archive, 2 * 1024 * 1024 * 1024)
    if asset["name"] != archive_name or checksum_metadata["name"] != checksum_name or appcast_metadata["name"] != "appcast.xml":
        raise IntakeError("release filenames do not match the release identity")
    if not isinstance(asset["length"], int) or isinstance(asset["length"], bool) or asset["length"] != archive.stat().st_size or asset["length"] <= 0:
        raise IntakeError("release metadata length does not match the archive")
    archive_url = f"{DOWNLOAD_URL_PREFIX}/{tag}/{archive_name}"
    checksum_url = f"{DOWNLOAD_URL_PREFIX}/{tag}/{checksum_name}"
    if asset["url"] != archive_url or checksum_metadata["url"] != checksum_url:
        raise IntakeError("release metadata does not use immutable asset URLs")
    if appcast_metadata != {"name": "appcast.xml", "url": FEED_URL, "enclosure_url": archive_url}:
        raise IntakeError("appcast metadata does not match the public update feed")

    archive_signature = asset["sparkle_ed_signature"]
    signature_bytes = _canonical_signature(archive_signature, "archive Sparkle signature")
    _validate_checksum(archive, checksum, asset["sha256"])
    _verify_ed25519(archive, signature_bytes, raw_public_key, openssl)
    _validate_appcast(
        appcast,
        archive=archive,
        archive_url=archive_url,
        archive_signature=archive_signature,
        version=version,
        build_number=build_number,
        public_key=raw_public_key,
        openssl=openssl,
    )
    _validate_trust_manifest(intake / "update-feed.json", public_key)
    return {
        "version": version,
        "build_number": build_number,
        "tag": tag,
        "archive": archive_name,
        "source_commit": source_commit,
        "previous_source_commit": previous_source_commit,
        "branch": expected_branch,
    }


def assert_newer(manifest_path: Path, releases_path: Path) -> None:
    manifest = _read_json(manifest_path, 32 * 1024)
    version = manifest.get("version")
    build_number = manifest.get("build_number")
    if not isinstance(version, str) or not isinstance(build_number, str):
        raise IntakeError("release metadata has no valid release identity")
    candidate_version, candidate_build = _release_identity(version, build_number)
    try:
        payload = json.loads(releases_path.read_text(encoding="utf-8"), object_pairs_hook=_without_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntakeError(f"unable to read GitHub releases: {error}") from error
    if not isinstance(payload, list):
        raise IntakeError("GitHub releases response must be an array")
    releases = [release for page in payload for release in page] if payload and all(isinstance(page, list) for page in payload) else payload
    if any(isinstance(release, list) for release in releases):
        raise IntakeError("GitHub releases response has inconsistent pagination")
    published: list[tuple[tuple[int, int, int], int]] = []
    for release in releases:
        if not isinstance(release, dict):
            raise IntakeError("GitHub releases response contains a non-object release")
        if release.get("draft") is True:
            continue
        if release.get("prerelease") is True:
            raise IntakeError("the release repository cannot contain prereleases")
        tag = release.get("tag_name")
        if not isinstance(tag, str):
            raise IntakeError("published release has no tag")
        match = RELEASE_TAG.fullmatch(tag)
        if match is None or all(int(part) == 0 for part in match.groups()[:3]):
            raise IntakeError("the dedicated repository contains a non-Notebook release")
        published.append((tuple(int(part) for part in match.groups()[:3]), int(match.group(4))))
    if published:
        highest_version = max(item[0] for item in published)
        highest_build = max(item[1] for item in published)
        if candidate_version <= highest_version:
            raise IntakeError("release version must be strictly newer than every published version")
        if candidate_build <= highest_build:
            raise IntakeError("build number must be strictly greater than every published build")


def _verified_source_identity(
    manifest_path: Path,
    *,
    public_key: str,
    openssl: str,
) -> tuple[str, str | None]:
    metadata = _read_json(manifest_path, 32 * 1024)
    _require_exact_keys(
        metadata,
        {
            "schema",
            "product",
            "version",
            "build_number",
            "tag",
            "architecture",
            "source",
            "asset",
            "checksum",
            "appcast",
            "provenance",
        },
        "notebook-release.json",
    )
    if metadata["schema"] != 1 or metadata["product"] != PRODUCT_NAME:
        raise IntakeError("release metadata has the wrong schema or product")
    _verify_provenance(metadata, _canonical_public_key(public_key), openssl)
    source = metadata["source"]
    if not isinstance(source, dict):
        raise IntakeError("release source must be one object")
    _require_exact_keys(
        source,
        {"repository", "commit", "previous_commit"},
        "release source",
    )
    commit = source["commit"]
    previous_commit = source["previous_commit"]
    if (
        source["repository"] != SOURCE_REPOSITORY
        or not isinstance(commit, str)
        or SOURCE_COMMIT.fullmatch(commit) is None
    ):
        raise IntakeError("release source does not identify an exact Marauder commit")
    if previous_commit is not None and (
        not isinstance(previous_commit, str)
        or SOURCE_COMMIT.fullmatch(previous_commit) is None
    ):
        raise IntakeError("release source has an invalid previous published commit")
    return commit, previous_commit


def assert_source_link(
    manifest_path: Path,
    previous_manifest_path: Path | None,
    *,
    public_key: str = PUBLIC_ED_KEY,
    openssl: str = "openssl",
) -> None:
    _candidate_commit, candidate_previous_commit = _verified_source_identity(
        manifest_path,
        public_key=public_key,
        openssl=openssl,
    )
    if previous_manifest_path is None:
        if candidate_previous_commit is not None:
            raise IntakeError("the first release must not claim a previous published source")
        return
    previous_commit, _previous_previous_commit = _verified_source_identity(
        previous_manifest_path,
        public_key=public_key,
        openssl=openssl,
    )
    if candidate_previous_commit != previous_commit:
        raise IntakeError(
            "release source does not continue from the latest signed published source"
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Verify a signed Marauder Notebook release intake")
    subparsers = result.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--intake", required=True, type=Path)
    validate.add_argument("--branch", required=True)
    validate.add_argument("--result", required=True, type=Path)
    validate.add_argument("--openssl", default="openssl")
    newer = subparsers.add_parser("assert-newer")
    newer.add_argument("--manifest", required=True, type=Path)
    newer.add_argument("--releases", required=True, type=Path)
    source_link = subparsers.add_parser("assert-source-link")
    source_link.add_argument("--manifest", required=True, type=Path)
    source_link.add_argument("--previous-manifest", type=Path)
    source_link.add_argument("--openssl", default="openssl")
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "validate":
            result = validate_intake(
                arguments.intake,
                arguments.branch,
                openssl=arguments.openssl,
            )
            arguments.result.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        elif arguments.command == "assert-newer":
            assert_newer(arguments.manifest, arguments.releases)
        else:
            assert_source_link(
                arguments.manifest,
                arguments.previous_manifest,
                openssl=arguments.openssl,
            )
    except (IntakeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
