#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import plistlib
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any


BUNDLE_IDENTIFIER = "com.marauder.notebook"
EXECUTABLE_NAME = "Marauder Notebook"
MINIMUM_SYSTEM_VERSION = "15.0"
DEEP_LINK_SCHEME = "marauder-notebook"
FEED_URL = (
    "https://github.com/Balllvin/marauder-notebook-releases/"
    "releases/latest/download/appcast.xml"
)
PUBLIC_ED_KEY = "Pp68s3Yv758+APzr4aMwpJNcXbOdJqkrMjS/7+i0LY0="
TEAM_IDENTIFIER = re.compile(r"[A-Z0-9]{10}")
REQUIRED_ENTITLEMENTS: dict[str, object] = {
    "com.apple.security.app-sandbox": True,
    "com.apple.security.network.client": True,
    "com.apple.security.files.bookmarks.app-scope": True,
    "com.apple.security.files.user-selected.read-write": True,
    "com.apple.security.device.audio-input": True,
    "com.apple.security.temporary-exception.mach-lookup.global-name": [
        "com.marauder.notebook-spks",
        "com.marauder.notebook-spki",
    ],
}
APPLE_IDENTITY_ENTITLEMENTS = {
    "com.apple.application-identifier",
    "com.apple.developer.team-identifier",
    "keychain-access-groups",
}


class BundleVerificationError(ValueError):
    pass


def _matches_exactly(actual: object, expected: object) -> bool:
    return type(actual) is type(expected) and actual == expected


def _read_plist(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise BundleVerificationError(f"{path.name} must be a regular property list")
    try:
        payload = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise BundleVerificationError(f"unable to read {path.name}: {error}") from error
    if not isinstance(payload, dict):
        raise BundleVerificationError(f"{path.name} must contain one property-list dictionary")
    return payload


def verify_info_plist(
    info: dict[str, Any],
    *,
    release_version: str,
    build_number: str,
) -> None:
    expected = {
        "CFBundleIdentifier": BUNDLE_IDENTIFIER,
        "CFBundleExecutable": EXECUTABLE_NAME,
        "CFBundleShortVersionString": release_version,
        "CFBundleVersion": build_number,
        "LSMinimumSystemVersion": MINIMUM_SYSTEM_VERSION,
        "SUFeedURL": FEED_URL,
        "SUPublicEDKey": PUBLIC_ED_KEY,
        "SURequireSignedFeed": True,
        "SUVerifyUpdateBeforeExtraction": True,
        "SUEnableInstallerLauncherService": True,
    }
    for key, value in expected.items():
        if not _matches_exactly(info.get(key), value):
            raise BundleVerificationError(f"Info.plist has an unexpected {key}")
    if info.get("CFBundleURLTypes") != [
        {
            "CFBundleURLName": BUNDLE_IDENTIFIER,
            "CFBundleURLSchemes": [DEEP_LINK_SCHEME],
        }
    ]:
        raise BundleVerificationError("Info.plist has an unexpected deep-link declaration")


def verify_entitlements(entitlements: dict[str, Any], *, team_identifier: str) -> None:
    if TEAM_IDENTIFIER.fullmatch(team_identifier) is None:
        raise BundleVerificationError("the Developer ID team identifier is invalid")
    for key, value in REQUIRED_ENTITLEMENTS.items():
        if not _matches_exactly(entitlements.get(key), value):
            raise BundleVerificationError(f"the signed app has an unexpected {key} entitlement")

    unexpected = set(entitlements) - set(REQUIRED_ENTITLEMENTS) - APPLE_IDENTITY_ENTITLEMENTS
    if unexpected:
        raise BundleVerificationError(
            "the signed app has unexpected entitlements: " + ", ".join(sorted(unexpected))
        )

    application_identifier = entitlements.get("com.apple.application-identifier")
    if application_identifier is not None and application_identifier != f"{team_identifier}.{BUNDLE_IDENTIFIER}":
        raise BundleVerificationError("the application identifier does not match the Developer ID team")
    entitlement_team = entitlements.get("com.apple.developer.team-identifier")
    if entitlement_team is not None and entitlement_team != team_identifier:
        raise BundleVerificationError("the entitlement team does not match the signing certificate")
    keychain_groups = entitlements.get("keychain-access-groups")
    if keychain_groups is not None and keychain_groups != [
        f"{team_identifier}.{BUNDLE_IDENTIFIER}"
    ]:
        raise BundleVerificationError("the keychain access groups do not match the Notebook app")


def _file_description(path: Path) -> str:
    result = subprocess.run(
        ["/usr/bin/file", "-b", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(f"file inspection failed for {path.name}: {result.stderr.strip()}")
    return result.stdout.strip()


def _architectures(path: Path) -> set[str]:
    result = subprocess.run(
        ["/usr/bin/lipo", "-archs", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(f"architecture inspection failed for {path.name}: {result.stderr.strip()}")
    return set(result.stdout.split())


def verify_macho_architectures(
    app: Path,
    *,
    describe: Callable[[Path], str] = _file_description,
    architectures: Callable[[Path], set[str]] = _architectures,
) -> list[Path]:
    verified: list[Path] = []
    for candidate in sorted(app.rglob("*")):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        if "Mach-O" not in describe(candidate):
            continue
        slices = architectures(candidate)
        if not {"arm64", "x86_64"}.issubset(slices):
            relative = candidate.relative_to(app)
            raise BundleVerificationError(
                f"{relative} is not a universal arm64 and x86_64 Mach-O"
            )
        verified.append(candidate)
    if not verified:
        raise BundleVerificationError("the app bundle contains no Mach-O executables")
    return verified


def verify_declared_executable(
    executable: Path,
    *,
    describe: Callable[[Path], str] = _file_description,
    architectures: Callable[[Path], set[str]] = _architectures,
) -> None:
    if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise BundleVerificationError("the declared app executable is missing or not executable")
    if "Mach-O" not in describe(executable):
        raise BundleVerificationError("the declared app executable is not a Mach-O binary")
    if architectures(executable) != {"arm64", "x86_64"}:
        raise BundleVerificationError(
            "the declared app executable must contain exactly arm64 and x86_64 slices"
        )


def verify_app_bundle(
    app: Path,
    entitlements_path: Path,
    *,
    release_version: str,
    build_number: str,
    team_identifier: str,
) -> None:
    if app.is_symlink() or not app.is_dir() or app.name != f"{EXECUTABLE_NAME}.app":
        raise BundleVerificationError("the release must contain the Marauder Notebook app bundle")
    info = _read_plist(app / "Contents" / "Info.plist")
    entitlements = _read_plist(entitlements_path)
    verify_info_plist(info, release_version=release_version, build_number=build_number)
    verify_entitlements(entitlements, team_identifier=team_identifier)
    executable = app / "Contents" / "MacOS" / EXECUTABLE_NAME
    verify_declared_executable(executable)
    verify_macho_architectures(app)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Verify the immutable Marauder Notebook app identity")
    result.add_argument("--app", required=True, type=Path)
    result.add_argument("--entitlements", required=True, type=Path)
    result.add_argument("--release-version", required=True)
    result.add_argument("--build-number", required=True)
    result.add_argument("--team-identifier", required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        verify_app_bundle(
            arguments.app,
            arguments.entitlements,
            release_version=arguments.release_version,
            build_number=arguments.build_number,
            team_identifier=arguments.team_identifier,
        )
    except (BundleVerificationError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
