from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import verify_app_bundle


class VerifyAppBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def info(self) -> dict[str, object]:
        return {
            "CFBundleIdentifier": verify_app_bundle.BUNDLE_IDENTIFIER,
            "CFBundleExecutable": verify_app_bundle.EXECUTABLE_NAME,
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleVersion": "42",
            "LSMinimumSystemVersion": verify_app_bundle.MINIMUM_SYSTEM_VERSION,
            "SUFeedURL": verify_app_bundle.FEED_URL,
            "SUPublicEDKey": verify_app_bundle.PUBLIC_ED_KEY,
            "SURequireSignedFeed": True,
            "SUVerifyUpdateBeforeExtraction": True,
            "SUEnableInstallerLauncherService": True,
            "CFBundleURLTypes": [
                {
                    "CFBundleURLName": verify_app_bundle.BUNDLE_IDENTIFIER,
                    "CFBundleURLSchemes": [verify_app_bundle.DEEP_LINK_SCHEME],
                }
            ],
        }

    def entitlements(self) -> dict[str, object]:
        return dict(verify_app_bundle.REQUIRED_ENTITLEMENTS)

    def test_accepts_exact_info_and_security_contract(self) -> None:
        verify_app_bundle.verify_info_plist(
            self.info(),
            release_version="1.2.3",
            build_number="42",
        )
        verify_app_bundle.verify_entitlements(
            self.entitlements(),
            team_identifier="A1B2C3D4E5",
        )

    def test_rejects_changed_update_key_and_dangerous_entitlement(self) -> None:
        info = self.info()
        info["SUPublicEDKey"] = "replacement"
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "SUPublicEDKey"):
            verify_app_bundle.verify_info_plist(
                info,
                release_version="1.2.3",
                build_number="42",
            )
        entitlements = self.entitlements()
        entitlements["com.apple.security.files.downloads.read-write"] = True
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "unexpected entitlements"):
            verify_app_bundle.verify_entitlements(
                entitlements,
                team_identifier="A1B2C3D4E5",
            )

    def test_rejects_integer_substitutes_for_security_booleans(self) -> None:
        info = self.info()
        info["SURequireSignedFeed"] = 1
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "SURequireSignedFeed"):
            verify_app_bundle.verify_info_plist(
                info,
                release_version="1.2.3",
                build_number="42",
            )
        entitlements = self.entitlements()
        entitlements["com.apple.security.app-sandbox"] = 1
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "app-sandbox"):
            verify_app_bundle.verify_entitlements(
                entitlements,
                team_identifier="A1B2C3D4E5",
            )

    def test_rejects_identity_entitlements_from_another_team(self) -> None:
        entitlements = self.entitlements()
        entitlements["com.apple.application-identifier"] = "Z9Y8X7W6V5.com.marauder.notebook"
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "application identifier"):
            verify_app_bundle.verify_entitlements(
                entitlements,
                team_identifier="A1B2C3D4E5",
            )

    def test_rejects_another_same_team_apps_keychain_group(self) -> None:
        entitlements = self.entitlements()
        entitlements["keychain-access-groups"] = ["A1B2C3D4E5.com.marauder.other"]
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "keychain access groups"):
            verify_app_bundle.verify_entitlements(
                entitlements,
                team_identifier="A1B2C3D4E5",
            )

    def test_checks_every_nested_macho_and_rejects_a_thin_component(self) -> None:
        app = self.root / "Marauder Notebook.app"
        main = app / "Contents" / "MacOS" / "Marauder Notebook"
        nested = app / "Contents" / "Frameworks" / "Sparkle.framework" / "Versions" / "B" / "Sparkle"
        resource = app / "Contents" / "Resources" / "copy.txt"
        for path in (main, nested, resource):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture")

        def describe(path: Path) -> str:
            return "ASCII text" if path == resource else "Mach-O universal binary"

        def architectures(path: Path) -> set[str]:
            return {"arm64"} if path == nested else {"arm64", "x86_64"}

        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "Sparkle.*not a universal"):
            verify_app_bundle.verify_macho_architectures(
                app,
                describe=describe,
                architectures=architectures,
            )

        verified = verify_app_bundle.verify_macho_architectures(
            app,
            describe=describe,
            architectures=lambda _: {"arm64", "x86_64"},
        )
        self.assertEqual(verified, [nested, main])

    def test_rejects_an_executable_script_even_when_a_nested_framework_is_universal(self) -> None:
        executable = self.root / "Marauder Notebook"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "not a Mach-O"):
            verify_app_bundle.verify_declared_executable(
                executable,
                describe=lambda _: "POSIX shell script, ASCII text executable",
                architectures=lambda _: {"arm64", "x86_64"},
            )

    def test_declared_executable_requires_exactly_the_two_supported_slices(self) -> None:
        executable = self.root / "Marauder Notebook"
        executable.write_bytes(b"fixture")
        executable.chmod(0o755)
        verify_app_bundle.verify_declared_executable(
            executable,
            describe=lambda _: "Mach-O universal binary",
            architectures=lambda _: {"arm64", "x86_64"},
        )
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "exactly arm64"):
            verify_app_bundle.verify_declared_executable(
                executable,
                describe=lambda _: "Mach-O universal binary",
                architectures=lambda _: {"arm64", "x86_64", "i386"},
            )


if __name__ == "__main__":
    unittest.main()
