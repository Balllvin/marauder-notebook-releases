from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from scripts import code_signing_contract


LEAF_CERTIFICATE_SHA256 = "A" * 64
ROOT_CERTIFICATE_SHA256 = "B" * 64
ROOT_CERTIFICATE_SHA1 = "b" * 40
DESIGNATED_REQUIREMENT = (
    'designated => identifier "com.marauder.notebook" and '
    f'certificate root = H"{ROOT_CERTIFICATE_SHA1}"'
)


def certificate_chain(
    *,
    leaf_sha256: str = LEAF_CERTIFICATE_SHA256,
    root_sha256: str = ROOT_CERTIFICATE_SHA256,
    root_sha1: str = ROOT_CERTIFICATE_SHA1,
) -> code_signing_contract.CertificateChain:
    return code_signing_contract.CertificateChain(
        sha256=(leaf_sha256, root_sha256),
        root_sha1=root_sha1,
    )


def independent_details(*, identifier: str, runtime: bool) -> dict[str, list[str]]:
    return {
        "Signature": ["cms"],
        "Identifier": [identifier],
        "TeamIdentifier": ["not set"],
        "Authority": ["Marauder Notebook Release", "Marauder Notebook Root"],
        "flags": ["0x10000(runtime)" if runtime else "0x0(none)"],
    }


class CodeSigningContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def assert_independent(
        self,
        details: dict[str, list[str]],
        *,
        main: bool,
        sparkle: bool,
        actual_leaf_certificate_sha256: str = LEAF_CERTIFICATE_SHA256,
        actual_root_certificate_sha256: str = ROOT_CERTIFICATE_SHA256,
        actual_root_certificate_sha1: str = ROOT_CERTIFICATE_SHA1,
        actual_requirement: str | None = None,
    ) -> None:
        if actual_requirement is None:
            identifier = details["Identifier"][0]
            actual_requirement = (
                f'designated => identifier "{identifier}" and '
                f'certificate root = H"{actual_root_certificate_sha1}"'
            )
        code_signing_contract.verify_signing_details(
            details,
            label="main" if main else "helper",
            distribution_mode=code_signing_contract.INDEPENDENT_MODE,
            expected_team_identifier=None,
            is_main_executable=main,
            require_hardened_runtime=main or sparkle,
            expected_root_certificate_sha256=ROOT_CERTIFICATE_SHA256,
            expected_leaf_certificate_sha256=LEAF_CERTIFICATE_SHA256,
            actual_certificate_chain=certificate_chain(
                leaf_sha256=actual_leaf_certificate_sha256,
                root_sha256=actual_root_certificate_sha256,
                root_sha1=actual_root_certificate_sha1,
            ),
            expected_designated_requirement=DESIGNATED_REQUIREMENT,
            actual_designated_requirement=actual_requirement,
        )

    def test_codesign_detail_parser_handles_real_verbose_shape(self) -> None:
        details = code_signing_contract.parse_codesign_details(
            "Identifier=com.marauder.notebook\n"
            "Authority=Developer ID Application: Publisher\n"
            "Authority=Developer ID Certification Authority\n"
            "TeamIdentifier=A1B2C3D4E5\n"
            "CodeDirectory v=20500 size=302 flags=0x10000(runtime) hashes=3+2\n"
        )
        self.assertEqual(
            details["Authority"],
            [
                "Developer ID Application: Publisher",
                "Developer ID Certification Authority",
            ],
        )
        self.assertEqual(details["flags"], ["0x10000(runtime)"])

    def test_independent_identity_accepts_main_and_hardened_sparkle_helper(self) -> None:
        self.assert_independent(
            independent_details(
                identifier=code_signing_contract.BUNDLE_IDENTIFIER,
                runtime=True,
            ),
            main=True,
            sparkle=False,
        )
        self.assert_independent(
            independent_details(identifier="org.sparkle-project.Downloader", runtime=True),
            main=False,
            sparkle=True,
        )

    def test_independent_identity_rejects_adhoc_apple_team_or_timestamp(self) -> None:
        main = independent_details(
            identifier=code_signing_contract.BUNDLE_IDENTIFIER,
            runtime=True,
        )
        cases = (
            ({**main, "Signature": ["adhoc"]}, "only ad-hoc signed"),
            (
                {**main, "TeamIdentifier": ["A1B2C3D4E5"]},
                "independent Marauder identity",
            ),
            (
                {**main, "Timestamp": ["Apple secure timestamp"]},
                "must not depend on an Apple secure timestamp",
            ),
        )
        for details, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(
                    code_signing_contract.BundleVerificationError,
                    message,
                ):
                    self.assert_independent(details, main=True, sparkle=False)

    def test_independent_identity_requires_runtime_for_every_code_object(self) -> None:
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "retain Hardened Runtime",
        ):
            self.assert_independent(
                independent_details(
                    identifier=code_signing_contract.BUNDLE_IDENTIFIER,
                    runtime=False,
                ),
                main=True,
                sparkle=False,
            )
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "retain Hardened Runtime",
        ):
            self.assert_independent(
                independent_details(identifier="org.sparkle-project.Updater", runtime=False),
                main=False,
                sparkle=True,
            )

    def test_independent_identity_enforces_pinned_root_leaf_and_requirement(self) -> None:
        main = independent_details(
            identifier=code_signing_contract.BUNDLE_IDENTIFIER,
            runtime=True,
        )
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "different independent release certificate",
        ):
            self.assert_independent(
                main,
                main=True,
                sparkle=False,
                actual_leaf_certificate_sha256="C" * 64,
            )
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "wrong independent root certificate",
        ):
            self.assert_independent(
                main,
                main=True,
                sparkle=False,
                actual_root_certificate_sha256="C" * 64,
            )
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "exact root-bound designated requirement",
        ):
            self.assert_independent(
                main,
                main=True,
                sparkle=False,
                actual_requirement='designated => identifier "com.marauder.impostor"',
            )
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "pinned independent designated requirement is invalid",
        ):
            self.assert_independent(
                main,
                main=True,
                sparkle=False,
                actual_root_certificate_sha1="c" * 40,
            )

    def test_optional_developer_id_mode_requires_one_team_certificate_and_runtime(self) -> None:
        details = {
            "Identifier": [code_signing_contract.BUNDLE_IDENTIFIER],
            "TeamIdentifier": ["A1B2C3D4E5"],
            "Authority": ["Developer ID Application: Publisher (A1B2C3D4E5)"],
            "Timestamp": ["secure timestamp"],
            "flags": ["0x10000(runtime)"],
        }
        code_signing_contract.verify_signing_details(
            details,
            label="main",
            distribution_mode=code_signing_contract.DEVELOPER_ID_MODE,
            expected_team_identifier="A1B2C3D4E5",
            is_main_executable=True,
            require_hardened_runtime=False,
            expected_leaf_certificate_sha256=LEAF_CERTIFICATE_SHA256,
            actual_certificate_chain=certificate_chain(),
        )
        cases = (
            ({**details, "TeamIdentifier": ["Z9Y8X7W6V5"]}, "wrong Apple team"),
            (
                {**details, "Authority": ["Apple Development: Publisher"]},
                "not Developer ID",
            ),
            ({**details, "flags": ["0x0(none)"]}, "must use Hardened Runtime"),
            (
                {key: value for key, value in details.items() if key != "Timestamp"},
                "secure timestamp",
            ),
            ({**details, "Signature": ["adhoc"]}, "unexpectedly ad-hoc"),
        )
        for changed, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(
                    code_signing_contract.BundleVerificationError,
                    message,
                ):
                    code_signing_contract.verify_signing_details(
                        changed,
                        label="main",
                        distribution_mode=code_signing_contract.DEVELOPER_ID_MODE,
                        expected_team_identifier="A1B2C3D4E5",
                        is_main_executable=True,
                        require_hardened_runtime=False,
                        expected_leaf_certificate_sha256=LEAF_CERTIFICATE_SHA256,
                        actual_certificate_chain=certificate_chain(),
                    )
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "different Developer ID certificate",
        ):
            code_signing_contract.verify_signing_details(
                details,
                label="main",
                distribution_mode=code_signing_contract.DEVELOPER_ID_MODE,
                expected_team_identifier="A1B2C3D4E5",
                is_main_executable=True,
                require_hardened_runtime=False,
                expected_leaf_certificate_sha256=LEAF_CERTIFICATE_SHA256,
                actual_certificate_chain=certificate_chain(
                    leaf_sha256="C" * 64,
                ),
            )

    def test_bundle_seal_failure_is_fatal(self) -> None:
        app = self.root / "Marauder Notebook.app"
        app.mkdir()
        failed = CompletedProcess(
            args=["codesign"],
            returncode=1,
            stdout="",
            stderr="resource envelope is obsolete",
        )
        with mock.patch.object(code_signing_contract.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(
                code_signing_contract.BundleVerificationError,
                "invalid, unsealed",
            ):
                code_signing_contract.verify_sealed_bundle(app)

    def test_signature_walk_rejects_mixed_nested_certificate(self) -> None:
        app = self.root / "Marauder Notebook.app"
        main = app / "Contents" / "MacOS" / code_signing_contract.EXECUTABLE_NAME
        helper = (
            app
            / "Contents"
            / "Frameworks"
            / "Sparkle.framework"
            / "Versions"
            / "B"
            / "Resources"
            / "Updater.app"
            / "Contents"
            / "MacOS"
            / "Updater"
        )
        details = {
            main: independent_details(
                identifier=code_signing_contract.BUNDLE_IDENTIFIER,
                runtime=True,
            ),
            helper: independent_details(
                identifier="org.sparkle-project.Updater",
                runtime=True,
            ),
        }
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "different independent release certificate",
        ):
            code_signing_contract.verify_code_signatures(
                app,
                [main, helper],
                distribution_mode=code_signing_contract.INDEPENDENT_MODE,
                expected_team_identifier=None,
                expected_root_certificate_sha256=ROOT_CERTIFICATE_SHA256,
                expected_designated_requirement=DESIGNATED_REQUIREMENT,
                details_for=lambda path, _: details[path],
                certificate_chain_for=lambda path, _: (
                    certificate_chain()
                    if path == main
                    else certificate_chain(leaf_sha256="C" * 64)
                ),
                designated_requirement_for=lambda *_: DESIGNATED_REQUIREMENT,
            )

    def test_signature_walk_rejects_wrong_main_signing_identifier(self) -> None:
        app = self.root / "Marauder Notebook.app"
        main = app / "Contents" / "MacOS" / code_signing_contract.EXECUTABLE_NAME
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "wrong signed code identifier",
        ):
            code_signing_contract.verify_code_signatures(
                app,
                [main],
                distribution_mode=code_signing_contract.INDEPENDENT_MODE,
                expected_team_identifier=None,
                expected_root_certificate_sha256=ROOT_CERTIFICATE_SHA256,
                expected_designated_requirement=DESIGNATED_REQUIREMENT,
                details_for=lambda *_: independent_details(
                    identifier="com.marauder.impostor",
                    runtime=True,
                ),
                certificate_chain_for=lambda *_: certificate_chain(),
                designated_requirement_for=lambda *_: DESIGNATED_REQUIREMENT,
            )

    def test_signature_walk_enforces_exact_code_layout_and_identifiers(self) -> None:
        app = self.root / "Marauder Notebook.app"
        main = app / "Contents" / "MacOS" / code_signing_contract.EXECUTABLE_NAME
        helper = (
            app
            / "Contents"
            / "Frameworks"
            / "Sparkle.framework"
            / "Versions"
            / "B"
            / "Sparkle"
        )
        expected = {
            main.relative_to(app).as_posix(): code_signing_contract.BUNDLE_IDENTIFIER,
            helper.relative_to(app).as_posix(): "org.sparkle-project.Sparkle",
        }
        identifiers = {
            main: code_signing_contract.BUNDLE_IDENTIFIER,
            helper: "org.sparkle-project.Sparkle",
        }

        def details(path: Path, _: str) -> dict[str, list[str]]:
            return independent_details(
                identifier=identifiers[path],
                runtime=True,
            )

        def requirement(path: Path, _: str) -> str:
            return (
                f'designated => identifier "{identifiers[path]}" and '
                f'certificate root = H"{ROOT_CERTIFICATE_SHA1}"'
            )

        code_signing_contract.verify_code_signatures(
            app,
            [main, helper],
            distribution_mode=code_signing_contract.INDEPENDENT_MODE,
            expected_team_identifier=None,
            expected_root_certificate_sha256=ROOT_CERTIFICATE_SHA256,
            expected_designated_requirement=DESIGNATED_REQUIREMENT,
            expected_code_identifiers=expected,
            details_for=details,
            certificate_chain_for=lambda *_: certificate_chain(),
            designated_requirement_for=requirement,
        )

        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "unexpected signed-code layout.*missing",
        ):
            code_signing_contract.verify_code_signatures(
                app,
                [main],
                distribution_mode=code_signing_contract.INDEPENDENT_MODE,
                expected_team_identifier=None,
                expected_root_certificate_sha256=ROOT_CERTIFICATE_SHA256,
                expected_designated_requirement=DESIGNATED_REQUIREMENT,
                expected_code_identifiers=expected,
                details_for=details,
                certificate_chain_for=lambda *_: certificate_chain(),
                designated_requirement_for=requirement,
            )

        identifiers[helper] = "org.sparkle-project.Impostor"
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "wrong signed code identifier",
        ):
            code_signing_contract.verify_code_signatures(
                app,
                [main, helper],
                distribution_mode=code_signing_contract.INDEPENDENT_MODE,
                expected_team_identifier=None,
                expected_root_certificate_sha256=ROOT_CERTIFICATE_SHA256,
                expected_designated_requirement=DESIGNATED_REQUIREMENT,
                expected_code_identifiers=expected,
                details_for=details,
                certificate_chain_for=lambda *_: certificate_chain(),
                designated_requirement_for=requirement,
            )

    def test_signature_walk_verifies_both_architecture_slices(self) -> None:
        app = self.root / "Marauder Notebook.app"
        main = app / "Contents" / "MacOS" / code_signing_contract.EXECUTABLE_NAME
        inspected: list[tuple[Path, str]] = []

        def details(path: Path, architecture: str) -> dict[str, list[str]]:
            inspected.append((path, architecture))
            return independent_details(
                identifier=code_signing_contract.BUNDLE_IDENTIFIER,
                runtime=True,
            )

        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "different independent release certificate",
        ):
            code_signing_contract.verify_code_signatures(
                app,
                [main],
                distribution_mode=code_signing_contract.INDEPENDENT_MODE,
                expected_team_identifier=None,
                expected_root_certificate_sha256=ROOT_CERTIFICATE_SHA256,
                expected_designated_requirement=DESIGNATED_REQUIREMENT,
                details_for=details,
                certificate_chain_for=lambda _, architecture: certificate_chain(
                    leaf_sha256=(
                        LEAF_CERTIFICATE_SHA256
                        if architecture == "arm64"
                        else "C" * 64
                    )
                ),
                designated_requirement_for=lambda *_: DESIGNATED_REQUIREMENT,
            )
        self.assertEqual(
            inspected,
            [(main, "arm64"), (main, "x86_64")],
        )

    def test_unsigned_macho_has_no_acceptable_fallback(self) -> None:
        unsigned = self.root / "unsigned"
        unsigned.write_bytes(b"fixture")
        failed = CompletedProcess(
            args=["codesign"],
            returncode=1,
            stdout="",
            stderr="code object is not signed at all",
        )
        with mock.patch.object(code_signing_contract.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(
                code_signing_contract.BundleVerificationError,
                "unsigned or has an unreadable signature",
            ):
                code_signing_contract._codesign_details(unsigned, "arm64")

    def test_certificate_chain_fingerprints_are_derived_from_embedded_der(self) -> None:
        signed = self.root / "signed"
        signed.write_bytes(b"fixture")
        certificate_der = b"self-signed certificate fixture"

        def extract(arguments: list[str], **_: object) -> CompletedProcess[str]:
            if arguments[:2] == ["/usr/bin/security", "verify-cert"]:
                return CompletedProcess(arguments, 0, "", "")
            self.assertEqual(arguments[:2], ["/usr/bin/codesign", "-d"])
            self.assertEqual(arguments[5], str(signed))
            self.assertEqual(arguments[2:4], ["--architecture", "arm64"])
            self.assertTrue(arguments[4].startswith("--extract-certificates="))
            prefix = Path(arguments[4].split("=", 1)[1])
            Path(f"{prefix}0").write_bytes(certificate_der)
            return CompletedProcess(arguments, 0, "", "")

        with mock.patch.object(code_signing_contract.subprocess, "run", side_effect=extract):
            self.assertEqual(
                code_signing_contract._certificate_chain(signed, "arm64"),
                code_signing_contract.CertificateChain(
                    sha256=(hashlib.sha256(certificate_der).hexdigest().upper(),),
                    root_sha1=hashlib.sha1(certificate_der).hexdigest(),
                ),
            )

    def test_certificate_chain_preserves_leaf_to_root_order(self) -> None:
        signed = self.root / "signed"
        signed.write_bytes(b"fixture")

        def extract(arguments: list[str], **_: object) -> CompletedProcess[str]:
            if arguments[:2] == ["/usr/bin/security", "verify-cert"]:
                return CompletedProcess(arguments, 0, "", "")
            prefix = Path(arguments[4].split("=", 1)[1])
            Path(f"{prefix}0").write_bytes(b"leaf")
            Path(f"{prefix}1").write_bytes(b"issuer")
            return CompletedProcess(arguments, 0, "", "")

        with mock.patch.object(code_signing_contract.subprocess, "run", side_effect=extract):
            self.assertEqual(
                code_signing_contract._certificate_chain(signed, "arm64"),
                code_signing_contract.CertificateChain(
                    sha256=(
                        hashlib.sha256(b"leaf").hexdigest().upper(),
                        hashlib.sha256(b"issuer").hexdigest().upper(),
                    ),
                    root_sha1=hashlib.sha1(b"issuer").hexdigest(),
                ),
            )

    def test_certificate_chain_must_validate_for_code_signing_offline(self) -> None:
        signed = self.root / "signed"
        signed.write_bytes(b"fixture")

        def extract(arguments: list[str], **_: object) -> CompletedProcess[str]:
            if arguments[:2] == ["/usr/bin/security", "verify-cert"]:
                self.assertIn("-N", arguments)
                self.assertIn("-L", arguments)
                self.assertIn("codeSign", arguments)
                return CompletedProcess(arguments, 1, "", "certificate verify failed")
            prefix = Path(arguments[4].split("=", 1)[1])
            Path(f"{prefix}0").write_bytes(b"leaf")
            Path(f"{prefix}1").write_bytes(b"root")
            return CompletedProcess(arguments, 0, "", "")

        with mock.patch.object(code_signing_contract.subprocess, "run", side_effect=extract):
            with self.assertRaisesRegex(
                code_signing_contract.BundleVerificationError,
                "valid code-signing certificate chain",
            ):
                code_signing_contract._certificate_chain(signed, "arm64")

    def test_signature_walk_requires_main_and_rejects_mixed_developer_id_certificate(self) -> None:
        app = self.root / "Marauder Notebook.app"
        main = app / "Contents" / "MacOS" / code_signing_contract.EXECUTABLE_NAME
        helper = app / "Contents" / "Frameworks" / "Helper"
        developer_details = {
            "Identifier": [code_signing_contract.BUNDLE_IDENTIFIER],
            "TeamIdentifier": ["A1B2C3D4E5"],
            "Authority": ["Developer ID Application: Publisher (A1B2C3D4E5)"],
            "Timestamp": ["secure timestamp"],
            "flags": ["0x10000(runtime)"],
        }
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "does not contain the declared app executable",
        ):
            code_signing_contract.verify_code_signatures(
                app,
                [helper],
                distribution_mode=code_signing_contract.DEVELOPER_ID_MODE,
                expected_team_identifier="A1B2C3D4E5",
                details_for=lambda *_: developer_details,
                certificate_chain_for=lambda *_: certificate_chain(),
            )
        with self.assertRaisesRegex(
            code_signing_contract.BundleVerificationError,
            "different Developer ID certificate",
        ):
            code_signing_contract.verify_code_signatures(
                app,
                [main, helper],
                distribution_mode=code_signing_contract.DEVELOPER_ID_MODE,
                expected_team_identifier="A1B2C3D4E5",
                details_for=lambda *_: developer_details,
                certificate_chain_for=lambda path, _: (
                    certificate_chain()
                    if path == main
                    else certificate_chain(leaf_sha256="C" * 64)
                ),
            )

    def test_designated_requirement_must_be_one_explicit_rule(self) -> None:
        signed = self.root / "signed"
        signed.write_bytes(b"fixture")
        result = CompletedProcess(
            args=["codesign"],
            returncode=0,
            stdout="",
            stderr=f"Executable={signed}\n{DESIGNATED_REQUIREMENT}\n",
        )
        with mock.patch.object(code_signing_contract.subprocess, "run", return_value=result):
            self.assertEqual(
                code_signing_contract._designated_requirement(signed, "arm64"),
                DESIGNATED_REQUIREMENT,
            )


if __name__ == "__main__":
    unittest.main()
