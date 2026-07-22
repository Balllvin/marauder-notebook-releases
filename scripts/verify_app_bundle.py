#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import os
import plistlib
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from .code_signing_contract import (
        ARCHITECTURES,
        BUNDLE_IDENTIFIER,
        DEVELOPER_ID_MODE,
        DISTRIBUTION_MODES,
        EXPECTED_CODE_IDENTIFIERS,
        INDEPENDENT_MODE,
        PINNED_INDEPENDENT_ROOT_CERTIFICATE_SHA256,
        PINNED_INDEPENDENT_DESIGNATED_REQUIREMENT,
        TEAM_IDENTIFIER,
        BundleVerificationError,
        verify_code_signatures,
        verify_sealed_bundle,
    )
except ImportError:
    from code_signing_contract import (
        ARCHITECTURES,
        BUNDLE_IDENTIFIER,
        DEVELOPER_ID_MODE,
        DISTRIBUTION_MODES,
        EXPECTED_CODE_IDENTIFIERS,
        INDEPENDENT_MODE,
        PINNED_INDEPENDENT_ROOT_CERTIFICATE_SHA256,
        PINNED_INDEPENDENT_DESIGNATED_REQUIREMENT,
        TEAM_IDENTIFIER,
        BundleVerificationError,
        verify_code_signatures,
        verify_sealed_bundle,
    )


EXECUTABLE_NAME = "Marauder Notebook"
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
    "Marauder Notebook uses the microphone only while you dictate into a document."
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
    path: {}
    for path in EXPECTED_CODE_IDENTIFIERS
    if path != f"Contents/MacOS/{EXECUTABLE_NAME}"
}
EXPECTED_NESTED_CODE_ENTITLEMENTS[
    "Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate"
] = {
    "com.apple.application-identifier": "org.sparkle-project.Sparkle.Autoupdate",
}
ALLOWED_RPATHS = {"/usr/lib/swift", "@executable_path/../Frameworks"}
ALLOWED_NON_SYSTEM_DEPENDENCY = "@rpath/Sparkle.framework/Versions/B/Sparkle"
BUILD_HOST_PATH = re.compile(
    r"(?:^|[^A-Za-z0-9_])(?:/Users/|/private/var/|/var/folders/|/opt/homebrew/)"
)
RPATH_OUTPUT = re.compile(r"^path (.+) \(offset [0-9]+\)$")
DEPENDENCY_OUTPUT = re.compile(
    r"^(.+) \(compatibility version [^,]+, current version [^)]+\)$"
)


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
    path: Path,
    architecture: str,
    *,
    required: bool,
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
    info: dict[str, Any],
    *,
    release_version: str,
    build_number: str,
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
        "CFBundleURLTypes": [
            {
                "CFBundleURLName": BUNDLE_IDENTIFIER,
                "CFBundleURLSchemes": [DEEP_LINK_SCHEME],
            }
        ],
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
            "Info.plist keys do not match the producer contract ("
            + "; ".join(details)
            + ")"
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
    header = payload[:8]
    if header[:4] != b"icns" or int.from_bytes(header[4:], "big") != size:
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
    if distribution_mode == INDEPENDENT_MODE:
        if team_identifier is not None:
            raise BundleVerificationError("independent distribution cannot declare an Apple team")
        if identity_entitlements:
            raise BundleVerificationError(
                "independent distribution cannot contain Apple team identity entitlements"
            )
        return

    if distribution_mode != DEVELOPER_ID_MODE:
        raise BundleVerificationError("the distribution mode is unsupported")
    if team_identifier is None or TEAM_IDENTIFIER.fullmatch(team_identifier) is None:
        raise BundleVerificationError("the Developer ID team identifier is invalid")

    application_identifier = entitlements.get("com.apple.application-identifier")
    if (
        application_identifier is not None
        and application_identifier != f"{team_identifier}.{BUNDLE_IDENTIFIER}"
    ):
        raise BundleVerificationError(
            "the application identifier does not match the Developer ID team"
        )
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
        raise BundleVerificationError(
            f"file inspection failed for {path.name}: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def _architectures(path: Path) -> set[str]:
    result = subprocess.run(
        ["/usr/bin/lipo", "-archs", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(
            f"architecture inspection failed for {path.name}: {result.stderr.strip()}"
        )
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
        if slices != {"arm64", "x86_64"}:
            relative = candidate.relative_to(app)
            raise BundleVerificationError(
                f"{relative} must contain exactly arm64 and x86_64 slices"
            )
        verified.append(candidate)
    if not verified:
        raise BundleVerificationError("the app bundle contains no Mach-O executables")
    return verified


def _rpaths(path: Path, architecture: str) -> set[str]:
    result = subprocess.run(
        ["/usr/bin/otool", "-arch", architecture, "-l", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(
            f"load-command inspection failed for {path.name}: {result.stderr.strip()}"
        )
    return parse_rpaths(result.stdout)


def _embedded_build_paths(path: Path, architecture: str) -> tuple[str, ...]:
    result = subprocess.run(
        ["/usr/bin/strings", "-arch", architecture, str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(
            f"string inspection failed for {path.name}: {result.stderr.strip()}"
        )
    return tuple(line for line in result.stdout.splitlines() if BUILD_HOST_PATH.search(line))


def _dependencies(path: Path, architecture: str) -> set[str]:
    result = subprocess.run(
        ["/usr/bin/otool", "-arch", architecture, "-L", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(
            f"dependency inspection failed for {path.name}: {result.stderr.strip()}"
        )
    return parse_dependencies(result.stdout)


def parse_rpaths(payload: str) -> set[str]:
    paths: set[str] = set()
    awaiting_path = False
    for line in payload.splitlines():
        value = line.strip()
        if value == "cmd LC_RPATH":
            if awaiting_path:
                raise BundleVerificationError("load commands contain an incomplete LC_RPATH")
            awaiting_path = True
            continue
        if awaiting_path and value.startswith("path "):
            match = RPATH_OUTPUT.fullmatch(value)
            if match is None:
                raise BundleVerificationError("load commands contain a malformed LC_RPATH")
            paths.add(match.group(1))
            awaiting_path = False
    if awaiting_path:
        raise BundleVerificationError("load commands contain an incomplete LC_RPATH")
    return paths


def parse_dependencies(payload: str) -> set[str]:
    dependencies: set[str] = set()
    for line in payload.splitlines()[1:]:
        value = line.strip()
        if not value:
            continue
        match = DEPENDENCY_OUTPUT.fullmatch(value)
        if match is None:
            raise BundleVerificationError("dependency list contains a malformed install name")
        dependencies.add(match.group(1))
    return dependencies


def _version_tuple(value: str) -> tuple[int, ...]:
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", value) is None:
        raise BundleVerificationError("Mach-O deployment target is malformed")
    return tuple(int(part) for part in value.split("."))


def parse_deployment_target(payload: str) -> tuple[str, tuple[int, ...]]:
    build_matches = re.findall(
        r"cmd LC_BUILD_VERSION\s+cmdsize [0-9]+\s+platform ([0-9]+)\s+minos ([0-9.]+)",
        payload,
    )
    legacy_matches = re.findall(
        r"cmd LC_VERSION_MIN_MACOSX\s+cmdsize [0-9]+\s+version ([0-9.]+)",
        payload,
    )
    if len(build_matches) + len(legacy_matches) != 1:
        raise BundleVerificationError(
            "Mach-O must declare exactly one macOS deployment target"
        )
    if build_matches:
        platform, minimum = build_matches[0]
        if platform != "1":
            raise BundleVerificationError("Mach-O deployment platform must be macOS")
        return "macos", _version_tuple(minimum)
    return "macos", _version_tuple(legacy_matches[0])


def _deployment_target(path: Path, architecture: str) -> tuple[str, tuple[int, ...]]:
    result = subprocess.run(
        ["/usr/bin/otool", "-arch", architecture, "-l", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(
            f"deployment-target inspection failed for {path.name}: {result.stderr.strip()}"
        )
    return parse_deployment_target(result.stdout)


def verify_macho_deployment_targets(
    app: Path,
    machos: list[Path],
    *,
    reader: Callable[[Path, str], tuple[str, tuple[int, ...]]] = _deployment_target,
) -> None:
    main = app / "Contents" / "MacOS" / EXECUTABLE_NAME
    expected = (15, 0)
    for candidate in machos:
        for architecture in ARCHITECTURES:
            platform, minimum = reader(candidate, architecture)
            if platform != "macos" or (candidate == main and minimum != expected) or (
                candidate != main and minimum > expected
            ):
                relative = candidate.relative_to(app)
                raise BundleVerificationError(
                    f"{relative} [{architecture}] has an incompatible macOS deployment target"
                )


def verify_macho_load_paths(
    machos: list[Path],
    *,
    rpath_reader: Callable[[Path, str], set[str]] = _rpaths,
    build_path_reader: Callable[[Path, str], tuple[str, ...]] = _embedded_build_paths,
    dependency_reader: Callable[[Path, str], set[str]] = _dependencies,
) -> None:
    for candidate in machos:
        for architecture in ARCHITECTURES:
            unexpected = rpath_reader(candidate, architecture) - ALLOWED_RPATHS
            if unexpected:
                raise BundleVerificationError(
                    f"{candidate.name} [{architecture}] has unsafe runtime search paths: "
                    + ", ".join(sorted(unexpected))
                )
            if build_path_reader(candidate, architecture):
                raise BundleVerificationError(
                    f"{candidate.name} [{architecture}] contains an absolute build-host path"
                )
            unsafe_dependencies = {
                dependency
                for dependency in dependency_reader(candidate, architecture)
                if "." in Path(dependency).parts
                or ".." in Path(dependency).parts
                or (
                    dependency != ALLOWED_NON_SYSTEM_DEPENDENCY
                    and not dependency.startswith("/System/Library/")
                    and not dependency.startswith("/usr/lib/")
                )
            }
            if unsafe_dependencies:
                raise BundleVerificationError(
                    f"{candidate.name} [{architecture}] has unsafe dynamic dependencies: "
                    + ", ".join(sorted(unsafe_dependencies))
                )


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


def _read_optional_signed_entitlements(
    path: Path,
    architecture: str,
) -> dict[str, Any]:
    return _read_signed_entitlements(path, architecture, required=False)


def verify_nested_code_entitlements(
    app: Path,
    machos: list[Path],
    *,
    entitlement_reader: Callable[[Path, str], dict[str, Any]] = (
        _read_optional_signed_entitlements
    ),
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
        for architecture in ARCHITECTURES:
            actual = entitlement_reader(candidate, architecture)
            if actual != expected:
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
    info = _read_plist(app / "Contents" / "Info.plist")
    verify_info_plist(info, release_version=release_version, build_number=build_number)
    verify_icon(app)
    executable = app / "Contents" / "MacOS" / EXECUTABLE_NAME
    verify_declared_executable(executable)
    machos = verify_macho_architectures(app)
    verify_macho_deployment_targets(app, machos)
    verify_macho_load_paths(machos)
    verify_sealed_bundle(app)
    for architecture in ARCHITECTURES:
        entitlements = _read_signed_entitlements(
            executable,
            architecture,
            required=True,
        )
        verify_entitlements(
            entitlements,
            distribution_mode=distribution_mode,
            team_identifier=expected_team_identifier,
        )
    verify_nested_code_entitlements(app, machos)
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
    result = argparse.ArgumentParser(
        description="Verify the immutable Marauder Notebook app identity"
    )
    result.add_argument("--app", required=True, type=Path)
    result.add_argument("--release-version", required=True)
    result.add_argument("--build-number", required=True)
    result.add_argument(
        "--distribution-mode",
        choices=DISTRIBUTION_MODES,
        default=INDEPENDENT_MODE,
    )
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
