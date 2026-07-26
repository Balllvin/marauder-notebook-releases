#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import plistlib
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from .code_signing_contract import (
        ACCOUNT_FREE_MODE,
        ARCHITECTURES,
        BUNDLE_IDENTIFIER,
        DEVELOPER_ID_MODE,
        DISTRIBUTION_MODES,
        EXPECTED_CODE_IDENTIFIERS,
        INDEPENDENT_MODE,
        PINNED_INDEPENDENT_DESIGNATED_REQUIREMENT,
        PINNED_INDEPENDENT_ROOT_CERTIFICATE_SHA256,
        TEAM_IDENTIFIER,
        BundleVerificationError,
        verify_code_signatures,
        verify_sealed_bundle,
    )
    from .macho_contract import (
        ALLOWED_RPATHS,
        BUILD_HOST_PATH,
        EXECUTABLE_NAME,
        parse_dependencies,
        parse_rpaths,
        verify_declared_executable,
        verify_macho_architectures,
        verify_macho_deployment_targets,
        verify_macho_load_paths,
    )
except ImportError:
    from code_signing_contract import (
        ACCOUNT_FREE_MODE,
        ARCHITECTURES,
        BUNDLE_IDENTIFIER,
        DEVELOPER_ID_MODE,
        DISTRIBUTION_MODES,
        EXPECTED_CODE_IDENTIFIERS,
        INDEPENDENT_MODE,
        PINNED_INDEPENDENT_DESIGNATED_REQUIREMENT,
        PINNED_INDEPENDENT_ROOT_CERTIFICATE_SHA256,
        TEAM_IDENTIFIER,
        BundleVerificationError,
        verify_code_signatures,
        verify_sealed_bundle,
    )
    from macho_contract import (
        ALLOWED_RPATHS,
        BUILD_HOST_PATH,
        EXECUTABLE_NAME,
        parse_dependencies,
        parse_rpaths,
        verify_declared_executable,
        verify_macho_architectures,
        verify_macho_deployment_targets,
        verify_macho_load_paths,
    )


MINIMUM_SYSTEM_VERSION = "15.0"
DEEP_LINK_SCHEME = "marauder-notebook"
FEED_URL = (
    "https://github.com/Balllvin/marauder-notebook-releases/"
    "releases/latest/download/appcast.xml"
)
PUBLIC_ED_KEY = "tWzGidYf3K08nkhu45CwWt/uJWERB+MT+UrpYjy4OXU="
ICON_NAME = "AppIcon"
ICON_FILE_NAME = f"{ICON_NAME}.icns"
MAX_ICON_BYTES = 16 * 1024 * 1024
MAX_INFO_PLIST_BYTES = 1024 * 1024
ICON_SHA256 = "7f6b996cbc0fee7c93bfce2765d227d7ab4ba37905872b5345da0b37e30dda35"
MICROPHONE_USAGE = (
    "Marauder Notebook uses the microphone while you dictate or have an active voice "
    "conversation in chat, a source, or a document."
)
SPEECH_RECOGNITION_USAGE = (
    "Marauder Notebook converts your dictation into document text when you start dictation."
)
REQUIRED_ENTITLEMENTS: dict[str, object] = {
    "com.apple.security.app-sandbox": True,
    "com.apple.security.cs.disable-library-validation": True,
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
EXPECTED_NESTED_CODE_ENTITLEMENTS = {
    path: {} for path in EXPECTED_CODE_IDENTIFIERS if path != f"Contents/MacOS/{EXECUTABLE_NAME}"
}
AUTUPDATE_PATH = "Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate"
INDEPENDENT_AUTUPDATE_ENTITLEMENTS = {
    "com.apple.application-identifier": "org.sparkle-project.Sparkle.Autoupdate"
}


def _matches_exactly(actual: object, expected: object) -> bool:
    return type(actual) is type(expected) and actual == expected


def _read_plist(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise BundleVerificationError(f"{path.name} must be a regular property list")
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_INFO_PLIST_BYTES:
        raise BundleVerificationError(f"{path.name} has an invalid size")
    try:
        payload = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise BundleVerificationError(f"unable to read {path.name}: {error}") from error
    if not isinstance(payload, dict):
        raise BundleVerificationError(f"{path.name} must contain one property-list dictionary")
    return payload


def _read_signed_entitlements(
    path: Path, architecture: str, *, required: bool
) -> dict[str, Any]:
    result = subprocess.run(
        [
            "/usr/bin/codesign",
            "-d",
            "--architecture",
            architecture,
            "--entitlements=-",
            "--xml",
            str(path),
        ],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(f"unable to read signed entitlements for {path.name}")
    if not result.stdout:
        if required:
            raise BundleVerificationError("the signed app is missing its entitlements")
        return {}
    try:
        payload = plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as error:
        raise BundleVerificationError(
            f"the signed entitlements for {path.name} are malformed"
        ) from error
    if not isinstance(payload, dict):
        raise BundleVerificationError(
            f"the signed entitlements for {path.name} must be one dictionary"
        )
    return payload


def verify_info_plist(
    info: dict[str, Any], *, release_version: str, build_number: str
) -> None:
    expected: dict[str, object] = {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleDisplayName": EXECUTABLE_NAME,
        "CFBundleIdentifier": BUNDLE_IDENTIFIER,
        "CFBundleExecutable": EXECUTABLE_NAME,
        "CFBundleIconFile": ICON_NAME,
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": EXECUTABLE_NAME,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": release_version,
        "CFBundleURLTypes": [{"CFBundleURLName": BUNDLE_IDENTIFIER, "CFBundleURLSchemes": [DEEP_LINK_SCHEME]}],
        "CFBundleVersion": build_number,
        "LSApplicationCategoryType": "public.app-category.productivity",
        "LSMinimumSystemVersion": MINIMUM_SYSTEM_VERSION,
        "NSHighResolutionCapable": True,
        "NSMicrophoneUsageDescription": MICROPHONE_USAGE,
        "NSPrincipalClass": "NSApplication",
        "NSSpeechRecognitionUsageDescription": SPEECH_RECOGNITION_USAGE,
        "SUFeedURL": FEED_URL,
        "SUPublicEDKey": PUBLIC_ED_KEY,
        "SURequireSignedFeed": True,
        "SUVerifyUpdateBeforeExtraction": True,
        "SUEnableInstallerLauncherService": True,
        "SUEnableAutomaticChecks": True,
        "SUAutomaticallyUpdate": True,
        "SUAllowsAutomaticUpdates": True,
    }
    unexpected = set(info) - set(expected)
    missing = set(expected) - set(info)
    if unexpected or missing:
        details = []
        if unexpected:
            details.append("unexpected: " + ", ".join(sorted(unexpected)))
        if missing:
            details.append("missing: " + ", ".join(sorted(missing)))
        raise BundleVerificationError(
            "Info.plist keys do not match the producer contract (" + "; ".join(details) + ")"
        )
    for key, value in expected.items():
        if not _matches_exactly(info.get(key), value):
            raise BundleVerificationError(f"Info.plist has an unexpected {key}")


def verify_icon(app: Path) -> None:
    icon = app / "Contents" / "Resources" / ICON_FILE_NAME
    if icon.is_symlink() or not icon.is_file():
        raise BundleVerificationError("the app icon must be a regular AppIcon.icns file")
    size = icon.stat().st_size
    if size < 8 or size > MAX_ICON_BYTES:
        raise BundleVerificationError("the app icon has an invalid size")
    payload = icon.read_bytes()
    if payload[:4] != b"icns" or int.from_bytes(payload[4:8], "big") != size:
        raise BundleVerificationError("the app icon is not a complete ICNS file")
    if hashlib.sha256(payload).hexdigest() != ICON_SHA256:
        raise BundleVerificationError("the app icon does not match the trusted product icon")


def verify_entitlements(
    entitlements: dict[str, Any],
    *,
    distribution_mode: str,
    team_identifier: str | None = None,
) -> None:
    for key, value in REQUIRED_ENTITLEMENTS.items():
        if not _matches_exactly(entitlements.get(key), value):
            raise BundleVerificationError(f"the signed app has an unexpected {key} entitlement")
    unexpected = set(entitlements) - set(REQUIRED_ENTITLEMENTS) - APPLE_IDENTITY_ENTITLEMENTS
    if unexpected:
        raise BundleVerificationError(
            "the signed app has unexpected entitlements: " + ", ".join(sorted(unexpected))
        )
    identity_entitlements = set(entitlements) & APPLE_IDENTITY_ENTITLEMENTS
    if distribution_mode in (ACCOUNT_FREE_MODE, INDEPENDENT_MODE):
        if team_identifier is not None or identity_entitlements:
            raise BundleVerificationError(
                f"{distribution_mode} distribution cannot contain Apple team identity"
            )
        return
    if distribution_mode != DEVELOPER_ID_MODE:
        raise BundleVerificationError("the distribution mode is unsupported")
    if team_identifier is None or TEAM_IDENTIFIER.fullmatch(team_identifier) is None:
        raise BundleVerificationError("the Developer ID team identifier is invalid")
    application_identifier = entitlements.get("com.apple.application-identifier")
    if application_identifier is not None and application_identifier != f"{team_identifier}.{BUNDLE_IDENTIFIER}":
        raise BundleVerificationError("the application identifier does not match the Developer ID team")
    if entitlements.get("com.apple.developer.team-identifier") not in (None, team_identifier):
        raise BundleVerificationError("the entitlement team does not match the signing certificate")
    keychain_groups = entitlements.get("keychain-access-groups")
    if keychain_groups is not None and keychain_groups != [f"{team_identifier}.{BUNDLE_IDENTIFIER}"]:
        raise BundleVerificationError("the keychain access groups do not match the Notebook app")


def _read_optional_signed_entitlements(path: Path, architecture: str) -> dict[str, Any]:
    return _read_signed_entitlements(path, architecture, required=False)


def verify_nested_code_entitlements(
    app: Path,
    machos: list[Path],
    *,
    distribution_mode: str,
    entitlement_reader: Callable[[Path, str], dict[str, Any]] = _read_optional_signed_entitlements,
) -> None:
    main_executable = app / "Contents" / "MacOS" / EXECUTABLE_NAME
    for candidate in machos:
        if candidate == main_executable:
            continue
        relative = candidate.relative_to(app).as_posix()
        expected = EXPECTED_NESTED_CODE_ENTITLEMENTS.get(relative)
        if expected is None:
            raise BundleVerificationError(
                f"{relative} is outside the expected nested-code entitlement contract"
            )
        if distribution_mode == INDEPENDENT_MODE and relative == AUTUPDATE_PATH:
            expected = INDEPENDENT_AUTUPDATE_ENTITLEMENTS
        for architecture in ARCHITECTURES:
            if entitlement_reader(candidate, architecture) != expected:
                raise BundleVerificationError(
                    f"{relative} [{architecture}] has unexpected signed entitlements"
                )


def verify_app_bundle(
    app: Path,
    *,
    release_version: str,
    build_number: str,
    distribution_mode: str,
    expected_team_identifier: str | None = None,
) -> None:
    if app.is_symlink() or not app.is_dir() or app.name != f"{EXECUTABLE_NAME}.app":
        raise BundleVerificationError("the release must contain the Marauder Notebook app bundle")
    verify_info_plist(
        _read_plist(app / "Contents" / "Info.plist"),
        release_version=release_version,
        build_number=build_number,
    )
    verify_icon(app)
    executable = app / "Contents" / "MacOS" / EXECUTABLE_NAME
    verify_declared_executable(executable)
    machos = verify_macho_architectures(app)
    verify_macho_deployment_targets(app, machos)
    verify_macho_load_paths(machos)
    verify_sealed_bundle(app)
    for architecture in ARCHITECTURES:
        verify_entitlements(
            _read_signed_entitlements(executable, architecture, required=True),
            distribution_mode=distribution_mode,
            team_identifier=expected_team_identifier,
        )
    verify_nested_code_entitlements(
        app,
        machos,
        distribution_mode=distribution_mode,
    )
    verify_code_signatures(
        app,
        machos,
        distribution_mode=distribution_mode,
        expected_team_identifier=expected_team_identifier,
        expected_root_certificate_sha256=PINNED_INDEPENDENT_ROOT_CERTIFICATE_SHA256,
        expected_designated_requirement=PINNED_INDEPENDENT_DESIGNATED_REQUIREMENT,
        expected_code_identifiers=EXPECTED_CODE_IDENTIFIERS,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Verify the immutable Marauder Notebook app identity")
    result.add_argument("--app", required=True, type=Path)
    result.add_argument("--release-version", required=True)
    result.add_argument("--build-number", required=True)
    result.add_argument("--distribution-mode", choices=DISTRIBUTION_MODES, default=INDEPENDENT_MODE)
    result.add_argument("--expected-team-identifier")
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        verify_app_bundle(
            arguments.app,
            release_version=arguments.release_version,
            build_number=arguments.build_number,
            distribution_mode=arguments.distribution_mode,
            expected_team_identifier=arguments.expected_team_identifier,
        )
    except (BundleVerificationError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
