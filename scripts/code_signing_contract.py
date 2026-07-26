from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


BUNDLE_IDENTIFIER = "com.marauder.notebook"
EXECUTABLE_NAME = "Marauder Notebook"
ARCHITECTURES = ("arm64", "x86_64")
INDEPENDENT_MODE = "independent"
DEVELOPER_ID_MODE = "developer-id"
ACCOUNT_FREE_MODE = "account-free"
DISTRIBUTION_MODES = (ACCOUNT_FREE_MODE, INDEPENDENT_MODE, DEVELOPER_ID_MODE)
TEAM_IDENTIFIER = re.compile(r"[A-Z0-9]{10}")
CERTIFICATE_SHA256 = re.compile(r"[0-9A-F]{64}")
CERTIFICATE_SHA1 = re.compile(r"[0-9a-f]{40}")
INDEPENDENT_DESIGNATED_REQUIREMENT = re.compile(
    r'designated => identifier "com\.marauder\.notebook" and '
    r'certificate root = H"[0-9a-f]{40}"'
)
# Leaf release certificates may rotate under this offline root without changing
# the root-pinned application identity.
PINNED_INDEPENDENT_ROOT_CERTIFICATE_SHA256 = (
    "D4F9B7D2F3DDDCAE1DB960B555EA96A9A10EBCED7314C56301AFDFB611E4F1A3"
)
PINNED_INDEPENDENT_DESIGNATED_REQUIREMENT = (
    'designated => identifier "com.marauder.notebook" and '
    'certificate root = H"7776224323dbd2e79ed7430e0c7efb2196523c0f"'
)
# app_bundle.sh stages Sparkle 2.9.4 and preserves each code object's existing
# identifier when it applies the root-bound designated requirement. Pinning the
# complete set prevents a correctly certified but relabelled or partial bundle
# from reaching the public update channel.
EXPECTED_CODE_IDENTIFIERS = {
    "Contents/MacOS/Marauder Notebook": BUNDLE_IDENTIFIER,
    "Contents/Frameworks/Sparkle.framework/Versions/B/Sparkle": (
        "org.sparkle-project.Sparkle"
    ),
    "Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate": (
        "Autoupdate-555549442401fd215d503466a26c3d081e5a8443"
    ),
    (
        "Contents/Frameworks/Sparkle.framework/Versions/B/Updater.app/"
        "Contents/MacOS/Updater"
    ): "org.sparkle-project.Sparkle.Updater",
    (
        "Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices/"
        "Installer.xpc/Contents/MacOS/Installer"
    ): "org.sparkle-project.InstallerLauncher",
    (
        "Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices/"
        "Downloader.xpc/Contents/MacOS/Downloader"
    ): "org.sparkle-project.DownloaderService",
}


class BundleVerificationError(ValueError):
    pass


@dataclass(frozen=True)
class CertificateChain:
    sha256: tuple[str, ...]
    root_sha1: str

    @property
    def leaf_sha256(self) -> str:
        return self.sha256[0]

    @property
    def root_sha256(self) -> str:
        return self.sha256[-1]


def parse_codesign_details(payload: str) -> dict[str, list[str]]:
    details: dict[str, list[str]] = {}
    for line in payload.splitlines():
        flags = re.search(r"(?:^|\s)flags=([^\s]+)", line)
        if flags is not None:
            details.setdefault("flags", []).append(flags.group(1))
            if line.lstrip().startswith("flags="):
                continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        details.setdefault(key.strip(), []).append(value.strip())
    return details


def _single_detail(details: dict[str, list[str]], key: str) -> str | None:
    values = details.get(key, [])
    if len(values) > 1:
        raise BundleVerificationError(f"the code signature has multiple {key} values")
    return values[0] if values else None


def _has_hardened_runtime(details: dict[str, list[str]]) -> bool:
    return any(
        re.search(r"(?:^|[,(])runtime(?:[),]|$)", value)
        for value in details.get("flags", [])
    )


def verify_signing_details(
    details: dict[str, list[str]],
    *,
    label: str,
    distribution_mode: str,
    expected_team_identifier: str | None,
    is_main_executable: bool,
    require_hardened_runtime: bool,
    expected_root_certificate_sha256: str | None = None,
    expected_leaf_certificate_sha256: str | None = None,
    actual_certificate_chain: CertificateChain | None = None,
    expected_designated_requirement: str | None = None,
    actual_designated_requirement: str | None = None,
) -> None:
    signature = _single_detail(details, "Signature")
    team_identifier = _single_detail(details, "TeamIdentifier")
    authorities = details.get("Authority", [])
    has_runtime = _has_hardened_runtime(details)

    if distribution_mode == ACCOUNT_FREE_MODE:
        if expected_team_identifier is not None:
            raise BundleVerificationError("account-free distribution cannot expect an Apple team")
        if signature != "adhoc" or team_identifier != "not set":
            raise BundleVerificationError(f"{label} is not account-free ad-hoc signed")
        if authorities or details.get("Timestamp") or actual_certificate_chain is not None:
            raise BundleVerificationError(
                f"{label} must not contain a certificate authority, timestamp, or chain"
            )
        if not has_runtime:
            raise BundleVerificationError(f"{label} must retain Hardened Runtime")
        return

    if distribution_mode == INDEPENDENT_MODE:
        if expected_team_identifier is not None:
            raise BundleVerificationError("independent distribution cannot expect an Apple team")
        if signature == "adhoc":
            raise BundleVerificationError(f"{label} is only ad-hoc signed")
        if details.get("Timestamp"):
            raise BundleVerificationError(
                f"{label} must not depend on an Apple secure timestamp"
            )
        if team_identifier != "not set":
            raise BundleVerificationError(
                f"{label} is not signed by the independent Marauder identity"
            )
        if (
            expected_root_certificate_sha256 is None
            or CERTIFICATE_SHA256.fullmatch(expected_root_certificate_sha256) is None
        ):
            raise BundleVerificationError(
                "the independent root certificate fingerprint is invalid"
            )
        if (
            actual_certificate_chain is None
            or len(actual_certificate_chain.sha256) != 2
            or CERTIFICATE_SHA1.fullmatch(actual_certificate_chain.root_sha1) is None
            or any(
                CERTIFICATE_SHA256.fullmatch(fingerprint) is None
                for fingerprint in actual_certificate_chain.sha256
            )
        ):
            raise BundleVerificationError(
                f"{label} does not contain the required leaf and private-CA root chain"
            )
        if actual_certificate_chain.root_sha256 != expected_root_certificate_sha256:
            raise BundleVerificationError(
                f"{label} is signed under the wrong independent root certificate"
            )
        if (
            expected_leaf_certificate_sha256 is None
            or actual_certificate_chain.leaf_sha256
            != expected_leaf_certificate_sha256
        ):
            raise BundleVerificationError(
                f"{label} is signed by a different independent release certificate"
            )
        identifier = _single_detail(details, "Identifier")
        if identifier is None or re.fullmatch(r"[A-Za-z0-9._+-]+", identifier) is None:
            raise BundleVerificationError(f"{label} has an invalid code identifier")
        root_bound_requirement = (
            f'designated => identifier "{identifier}" and '
            f'certificate root = H"{actual_certificate_chain.root_sha1}"'
        )
        if actual_designated_requirement != root_bound_requirement:
            raise BundleVerificationError(
                f"{label} does not have its exact root-bound designated requirement"
            )
        if is_main_executable:
            if (
                expected_designated_requirement is None
                or INDEPENDENT_DESIGNATED_REQUIREMENT.fullmatch(
                    expected_designated_requirement
                )
                is None
                or expected_designated_requirement != root_bound_requirement
            ):
                raise BundleVerificationError(
                    "the pinned independent designated requirement is invalid"
                )
        if require_hardened_runtime and not has_runtime:
            raise BundleVerificationError(f"{label} must retain Hardened Runtime")
        return

    if distribution_mode != DEVELOPER_ID_MODE:
        raise BundleVerificationError("the distribution mode is unsupported")
    if (
        expected_team_identifier is None
        or TEAM_IDENTIFIER.fullmatch(expected_team_identifier) is None
    ):
        raise BundleVerificationError("the Developer ID team identifier is invalid")
    if signature == "adhoc":
        raise BundleVerificationError(f"{label} is unexpectedly ad-hoc signed")
    if team_identifier != expected_team_identifier:
        raise BundleVerificationError(f"{label} is signed by the wrong Apple team")
    if not any(authority.startswith("Developer ID Application:") for authority in authorities):
        raise BundleVerificationError(f"{label} is not Developer ID Application signed")
    if not details.get("Timestamp"):
        raise BundleVerificationError(f"{label} is missing an Apple secure timestamp")
    if expected_leaf_certificate_sha256 is not None or actual_certificate_chain is not None:
        if (
            expected_leaf_certificate_sha256 is None
            or actual_certificate_chain is None
            or not actual_certificate_chain.sha256
            or actual_certificate_chain.leaf_sha256
            != expected_leaf_certificate_sha256
        ):
            raise BundleVerificationError(
                f"{label} is signed by a different Developer ID certificate"
            )
    if not has_runtime:
        raise BundleVerificationError(f"{label} must use Hardened Runtime")


def _certificate_chain(path: Path, architecture: str) -> CertificateChain:
    with tempfile.TemporaryDirectory(prefix="notebook-code-certificate-") as directory:
        prefix = Path(directory) / "leaf-"
        result = subprocess.run(
            [
                "/usr/bin/codesign",
                "-d",
                "--architecture",
                architecture,
                f"--extract-certificates={prefix}",
                str(path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise BundleVerificationError(
                f"{path.name} does not contain a readable signing certificate chain"
            )
        certificates: list[Path] = []
        for index in range(8):
            certificate = Path(f"{prefix}{index}")
            if not certificate.exists():
                break
            if certificate.is_symlink() or not certificate.is_file():
                raise BundleVerificationError(
                    f"{path.name} has an invalid embedded signing certificate"
                )
            certificates.append(certificate)
        extracted_entries = set(prefix.parent.glob(f"{prefix.name}*"))
        if (
            not certificates
            or extracted_entries != set(certificates)
            or Path(f"{prefix}{len(certificates)}").exists()
        ):
            raise BundleVerificationError(
                f"{path.name} does not contain a bounded signing certificate chain"
            )
        verify_arguments = [
            "/usr/bin/security",
            "verify-cert",
            "-N",
            "-L",
            "-p",
            "codeSign",
        ]
        for certificate in certificates[:-1]:
            verify_arguments.extend(("-c", str(certificate)))
        verify_arguments.extend(("-r", str(certificates[-1]), "-q"))
        chain_verification = subprocess.run(
            verify_arguments,
            check=False,
            capture_output=True,
            text=True,
        )
        if chain_verification.returncode != 0:
            raise BundleVerificationError(
                f"{path.name} does not contain a valid code-signing certificate chain"
            )
        return CertificateChain(
            sha256=tuple(
                hashlib.sha256(certificate.read_bytes()).hexdigest().upper()
                for certificate in certificates
            ),
            root_sha1=hashlib.sha1(  # noqa: S324 - code-signing DR uses SHA-1 by contract.
                certificates[-1].read_bytes()
            ).hexdigest(),
        )


def _designated_requirement(path: Path, architecture: str) -> str:
    result = subprocess.run(
        [
            "/usr/bin/codesign",
            "-d",
            "--architecture",
            architecture,
            "-r-",
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(f"unable to read the designated requirement for {path.name}")
    requirements = [
        line.strip()
        for line in (result.stdout + result.stderr).splitlines()
        if line.strip().startswith("designated =>")
    ]
    if len(requirements) != 1:
        raise BundleVerificationError(f"{path.name} has no single designated requirement")
    return requirements[0]


def _codesign_details(path: Path, architecture: str) -> dict[str, list[str]]:
    result = subprocess.run(
        [
            "/usr/bin/codesign",
            "-d",
            "--architecture",
            architecture,
            "--verbose=4",
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(f"{path.name} is unsigned or has an unreadable signature")
    return parse_codesign_details(result.stdout + result.stderr)


def verify_sealed_bundle(app: Path) -> None:
    result = subprocess.run(
        [
            "/usr/bin/codesign",
            "--verify",
            "--all-architectures",
            "--deep",
            "--strict",
            "--verbose=2",
            str(app),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleVerificationError(
            "the app signature is invalid, unsealed, or contains invalid nested code"
        )


def verify_code_signatures(
    app: Path,
    machos: list[Path],
    *,
    distribution_mode: str,
    expected_team_identifier: str | None,
    expected_root_certificate_sha256: str | None = None,
    expected_designated_requirement: str | None = None,
    expected_code_identifiers: dict[str, str] | None = None,
    details_for: Callable[[Path, str], dict[str, list[str]]] = _codesign_details,
    certificate_chain_for: Callable[[Path, str], CertificateChain] = _certificate_chain,
    designated_requirement_for: Callable[[Path, str], str] = _designated_requirement,
) -> None:
    main_executable = app / "Contents" / "MacOS" / EXECUTABLE_NAME
    if main_executable not in machos:
        raise BundleVerificationError(
            "the verified Mach-O set does not contain the declared app executable"
        )
    if expected_code_identifiers is not None:
        actual_code_paths = {candidate.relative_to(app).as_posix() for candidate in machos}
        expected_code_paths = set(expected_code_identifiers)
        missing = sorted(expected_code_paths - actual_code_paths)
        unexpected = sorted(actual_code_paths - expected_code_paths)
        if missing or unexpected:
            problems = []
            if missing:
                problems.append("missing: " + ", ".join(missing))
            if unexpected:
                problems.append("unexpected: " + ", ".join(unexpected))
            raise BundleVerificationError(
                "the app has an unexpected signed-code layout (" + "; ".join(problems) + ")"
            )
    main_certificate_chain = None
    main_leaf_certificate_sha256 = None
    if distribution_mode != ACCOUNT_FREE_MODE:
        main_certificate_chain = certificate_chain_for(main_executable, ARCHITECTURES[0])
        if not main_certificate_chain.sha256:
            raise BundleVerificationError("the main app has no signing certificate chain")
        main_leaf_certificate_sha256 = main_certificate_chain.leaf_sha256
    for candidate in machos:
        relative = candidate.relative_to(app)
        is_main = candidate == main_executable
        is_sparkle_code = "Sparkle.framework" in relative.parts
        for architecture in ARCHITECTURES:
            details = details_for(candidate, architecture)
            expected_identifier = (
                expected_code_identifiers.get(relative.as_posix())
                if expected_code_identifiers is not None
                else BUNDLE_IDENTIFIER if is_main else None
            )
            if (
                expected_identifier is not None
                and _single_detail(details, "Identifier") != expected_identifier
            ):
                raise BundleVerificationError(
                    f"{relative} [{architecture}] has the wrong signed code identifier"
                )
            actual_certificate_chain = (
                None
                if distribution_mode == ACCOUNT_FREE_MODE
                else certificate_chain_for(candidate, architecture)
            )
            actual_designated_requirement = (
                designated_requirement_for(candidate, architecture)
                if distribution_mode == INDEPENDENT_MODE
                else None
            )
            verify_signing_details(
                details,
                label=f"{relative} [{architecture}]",
                distribution_mode=distribution_mode,
                expected_team_identifier=expected_team_identifier,
                expected_root_certificate_sha256=(
                    expected_root_certificate_sha256
                    if distribution_mode == INDEPENDENT_MODE
                    else None
                ),
                expected_leaf_certificate_sha256=main_leaf_certificate_sha256,
                actual_certificate_chain=actual_certificate_chain,
                expected_designated_requirement=expected_designated_requirement,
                actual_designated_requirement=actual_designated_requirement,
                is_main_executable=is_main,
                require_hardened_runtime=True,
            )
