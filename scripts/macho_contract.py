from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

try:
    from .code_signing_contract import ARCHITECTURES, BundleVerificationError
except ImportError:
    from code_signing_contract import ARCHITECTURES, BundleVerificationError


EXECUTABLE_NAME = "Marauder Notebook"
ALLOWED_RPATHS = {"/usr/lib/swift", "@executable_path/../Frameworks"}
ALLOWED_NON_SYSTEM_DEPENDENCY = "@rpath/Sparkle.framework/Versions/B/Sparkle"
BUILD_HOST_PATH = re.compile(
    r"(?:^|[^A-Za-z0-9_])(?:/Users/|/private/var/|/var/folders/|/opt/homebrew/)"
)
RPATH_OUTPUT = re.compile(r"^path (.+) \(offset [0-9]+\)$")
DEPENDENCY_OUTPUT = re.compile(
    r"^(.+) \(compatibility version [^,]+, current version [^)]+\)$"
)


def _file_description(path: Path) -> str:
    result = subprocess.run(
        ["/usr/bin/file", "-b", str(path)], check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise BundleVerificationError(
            f"file inspection failed for {path.name}: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def _architectures(path: Path) -> set[str]:
    result = subprocess.run(
        ["/usr/bin/lipo", "-archs", str(path)], check=False, capture_output=True, text=True
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
        if candidate.is_symlink() or not candidate.is_file() or "Mach-O" not in describe(candidate):
            continue
        if architectures(candidate) != {"arm64", "x86_64"}:
            relative = candidate.relative_to(app)
            raise BundleVerificationError(
                f"{relative} must contain exactly arm64 and x86_64 slices"
            )
        verified.append(candidate)
    if not verified:
        raise BundleVerificationError("the app bundle contains no Mach-O executables")
    return verified


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
        r"cmd LC_VERSION_MIN_MACOSX\s+cmdsize [0-9]+\s+version ([0-9.]+)", payload
    )
    if len(build_matches) + len(legacy_matches) != 1:
        raise BundleVerificationError("Mach-O must declare exactly one macOS deployment target")
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
