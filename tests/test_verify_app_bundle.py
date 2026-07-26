from __future__ import annotations

import hashlib
import plistlib
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from scripts import verify_app_bundle


class VerifyAppBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def info(self) -> dict[str, object]:
        return {
            "CFBundleDevelopmentRegion": "en",
            "CFBundleDisplayName": verify_app_bundle.EXECUTABLE_NAME,
            "CFBundleIdentifier": verify_app_bundle.BUNDLE_IDENTIFIER,
            "CFBundleExecutable": verify_app_bundle.EXECUTABLE_NAME,
            "CFBundleIconFile": verify_app_bundle.ICON_NAME,
            "CFBundleInfoDictionaryVersion": "6.0",
            "CFBundleName": verify_app_bundle.EXECUTABLE_NAME,
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleVersion": "42",
            "LSApplicationCategoryType": "public.app-category.productivity",
            "LSMinimumSystemVersion": verify_app_bundle.MINIMUM_SYSTEM_VERSION,
            "NSHighResolutionCapable": True,
            "NSMicrophoneUsageDescription": verify_app_bundle.MICROPHONE_USAGE,
            "NSPrincipalClass": "NSApplication",
            "NSSpeechRecognitionUsageDescription": (
                verify_app_bundle.SPEECH_RECOGNITION_USAGE
            ),
            "SUFeedURL": verify_app_bundle.FEED_URL,
            "SUPublicEDKey": verify_app_bundle.PUBLIC_ED_KEY,
            "SURequireSignedFeed": True,
            "SUVerifyUpdateBeforeExtraction": True,
            "SUEnableInstallerLauncherService": True,
            "SUEnableAutomaticChecks": True,
            "SUAutomaticallyUpdate": True,
            "SUAllowsAutomaticUpdates": True,
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
            distribution_mode=verify_app_bundle.INDEPENDENT_MODE,
        )

    def test_rejects_wrong_bundle_version_build_and_update_key(self) -> None:
        for key, value in (
            ("CFBundleIdentifier", "com.marauder.impostor"),
            ("CFBundleShortVersionString", "9.9.9"),
            ("CFBundleVersion", "99"),
            ("SUPublicEDKey", "replacement"),
        ):
            info = self.info()
            info[key] = value
            with self.subTest(key=key):
                with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, key):
                    verify_app_bundle.verify_info_plist(
                        info,
                        release_version="1.2.3",
                        build_number="42",
                    )

    def test_rejects_dangerous_or_integer_security_entitlements(self) -> None:
        entitlements = self.entitlements()
        entitlements["com.apple.security.files.downloads.read-write"] = True
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "unexpected entitlements",
        ):
            verify_app_bundle.verify_entitlements(
                entitlements,
                distribution_mode=verify_app_bundle.INDEPENDENT_MODE,
            )
        entitlements = self.entitlements()
        entitlements["com.apple.security.app-sandbox"] = 1
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "app-sandbox"):
            verify_app_bundle.verify_entitlements(
                entitlements,
                distribution_mode=verify_app_bundle.INDEPENDENT_MODE,
            )

    def test_rejects_integer_substitute_for_signed_update_boolean(self) -> None:
        info = self.info()
        info["SURequireSignedFeed"] = 1
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "SURequireSignedFeed",
        ):
            verify_app_bundle.verify_info_plist(
                info,
                release_version="1.2.3",
                build_number="42",
            )

    def test_rejects_disabled_automatic_updates_or_extra_launch_policy(self) -> None:
        for key in (
            "SUEnableAutomaticChecks",
            "SUAutomaticallyUpdate",
            "SUAllowsAutomaticUpdates",
        ):
            info = self.info()
            info[key] = False
            with self.subTest(key=key):
                with self.assertRaisesRegex(
                    verify_app_bundle.BundleVerificationError,
                    key,
                ):
                    verify_app_bundle.verify_info_plist(
                        info,
                        release_version="1.2.3",
                        build_number="42",
                    )
        for key in (
            "LSEnvironment",
            "NSUpdateSecurityPolicy",
            "NSAppTransportSecurity",
            "LSUIElement",
        ):
            info = self.info()
            info[key] = {"DYLD_LIBRARY_PATH": "/Library/Injected"}
            with self.subTest(key=key):
                with self.assertRaisesRegex(
                    verify_app_bundle.BundleVerificationError,
                    f"unexpected: {key}",
                ):
                    verify_app_bundle.verify_info_plist(
                        info,
                        release_version="1.2.3",
                        build_number="42",
                    )

    def test_info_plist_requires_every_exact_producer_key(self) -> None:
        for key in tuple(self.info()):
            info = self.info()
            del info[key]
            with self.subTest(key=key):
                with self.assertRaisesRegex(
                    verify_app_bundle.BundleVerificationError,
                    f"missing: .*{key}",
                ):
                    verify_app_bundle.verify_info_plist(
                        info,
                        release_version="1.2.3",
                        build_number="42",
                    )

    def test_requires_a_complete_regular_icns_icon(self) -> None:
        app = self.root / "Marauder Notebook.app"
        icon = app / "Contents" / "Resources" / verify_app_bundle.ICON_FILE_NAME
        icon.parent.mkdir(parents=True)
        payload = b"icns" + (12).to_bytes(4, "big") + b"test"
        icon.write_bytes(payload)
        with mock.patch.object(
            verify_app_bundle,
            "ICON_SHA256",
            hashlib.sha256(payload).hexdigest(),
        ):
            verify_app_bundle.verify_icon(app)

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "trusted product icon",
        ):
            verify_app_bundle.verify_icon(app)

        invalid_payloads = (
            b"short",
            b"nope" + (12).to_bytes(4, "big") + b"test",
            b"icns" + (13).to_bytes(4, "big") + b"test",
        )
        for invalid in invalid_payloads:
            icon.write_bytes(invalid)
            with self.subTest(payload=invalid):
                with self.assertRaises(verify_app_bundle.BundleVerificationError):
                    verify_app_bundle.verify_icon(app)

        with icon.open("wb") as icon_file:
            icon_file.seek(verify_app_bundle.MAX_ICON_BYTES)
            icon_file.write(b"\0")
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "invalid size",
        ):
            verify_app_bundle.verify_icon(app)

        icon.unlink()
        icon.symlink_to("missing.icns")
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "regular AppIcon",
        ):
            verify_app_bundle.verify_icon(app)

    def test_rejects_identity_entitlements_from_another_team(self) -> None:
        entitlements = self.entitlements()
        entitlements["com.apple.application-identifier"] = (
            "Z9Y8X7W6V5.com.marauder.notebook"
        )
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "application identifier",
        ):
            verify_app_bundle.verify_entitlements(
                entitlements,
                distribution_mode=verify_app_bundle.DEVELOPER_ID_MODE,
                team_identifier="A1B2C3D4E5",
            )

    def test_rejects_another_same_team_apps_keychain_group(self) -> None:
        entitlements = self.entitlements()
        entitlements["keychain-access-groups"] = ["A1B2C3D4E5.com.marauder.other"]
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "keychain access groups",
        ):
            verify_app_bundle.verify_entitlements(
                entitlements,
                distribution_mode=verify_app_bundle.DEVELOPER_ID_MODE,
                team_identifier="A1B2C3D4E5",
            )

    def test_independent_entitlements_reject_every_apple_team_identity(self) -> None:
        for key, value in (
            ("com.apple.application-identifier", "A1B2C3D4E5.com.marauder.notebook"),
            ("com.apple.developer.team-identifier", "A1B2C3D4E5"),
            ("keychain-access-groups", ["A1B2C3D4E5.com.marauder.notebook"]),
        ):
            entitlements = self.entitlements()
            entitlements[key] = value
            with self.subTest(key=key):
                with self.assertRaisesRegex(
                    verify_app_bundle.BundleVerificationError,
                    "cannot contain Apple team",
                ):
                    verify_app_bundle.verify_entitlements(
                        entitlements,
                        distribution_mode=verify_app_bundle.INDEPENDENT_MODE,
                    )

    def test_checks_every_nested_macho_and_rejects_wrong_slices(self) -> None:
        app = self.root / "Marauder Notebook.app"
        main = app / "Contents" / "MacOS" / "Marauder Notebook"
        nested = (
            app / "Contents" / "Frameworks" / "Sparkle.framework" / "Versions" / "B" / "Sparkle"
        )
        resource = app / "Contents" / "Resources" / "copy.txt"
        for path in (main, nested, resource):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture")

        def describe(path: Path) -> str:
            return "ASCII text" if path == resource else "Mach-O universal binary"

        def architectures(path: Path) -> set[str]:
            return {"arm64"} if path == nested else {"arm64", "x86_64"}

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "Sparkle.*exactly arm64",
        ):
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
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "exactly arm64"):
            verify_app_bundle.verify_macho_architectures(
                app,
                describe=describe,
                architectures=lambda _: {"arm64", "x86_64", "i386"},
            )

    def test_declared_executable_must_be_executable_macho_with_exact_slices(self) -> None:
        executable = self.root / "Marauder Notebook"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "not a Mach-O"):
            verify_app_bundle.verify_declared_executable(
                executable,
                describe=lambda _: "POSIX shell script, ASCII text executable",
                architectures=lambda _: {"arm64", "x86_64"},
            )
        executable.write_bytes(b"fixture")
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "exactly arm64"):
            verify_app_bundle.verify_declared_executable(
                executable,
                describe=lambda _: "Mach-O universal binary",
                architectures=lambda _: {"arm64", "x86_64", "i386"},
            )

    def test_rejects_build_host_rpath_and_embedded_path_in_every_slice(self) -> None:
        self.assertIsNone(verify_app_bundle.BUILD_HOST_PATH.search("/tmp/XXXXXX.png"))
        executable = self.root / verify_app_bundle.EXECUTABLE_NAME

        def clean_rpaths(_: Path, __: str) -> set[str]:
            return set(verify_app_bundle.ALLOWED_RPATHS)

        verify_app_bundle.verify_macho_load_paths(
            [executable],
            rpath_reader=clean_rpaths,
            build_path_reader=lambda *_: (),
            dependency_reader=lambda *_: {"/usr/lib/libSystem.B.dylib"},
        )

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "unsafe runtime search paths",
        ):
            verify_app_bundle.verify_macho_load_paths(
                [executable],
                rpath_reader=lambda *_: {
                    "/usr/lib/swift",
                    "/opt/homebrew/Cellar/swift/toolchain/usr/lib/swift/macosx",
                },
                build_path_reader=lambda *_: (),
                dependency_reader=lambda *_: {"/usr/lib/libSystem.B.dylib"},
            )

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "absolute build-host path",
        ):
            verify_app_bundle.verify_macho_load_paths(
                [executable],
                rpath_reader=clean_rpaths,
                build_path_reader=lambda _, architecture: (
                    "/Users/builder/project/.build/release/NotebookKit.bundle",
                ) if architecture == "x86_64" else (),
                dependency_reader=lambda *_: {"/usr/lib/libSystem.B.dylib"},
            )

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "unsafe dynamic dependencies",
        ):
            verify_app_bundle.verify_macho_load_paths(
                [executable],
                rpath_reader=clean_rpaths,
                build_path_reader=lambda *_: (),
                dependency_reader=lambda *_: {
                    "/usr/lib/libSystem.B.dylib",
                    "/System/Library/../../Library/Frameworks/Injected.framework/Injected",
                },
            )

        self.assertEqual(
            verify_app_bundle.parse_rpaths(
                "cmd LC_RPATH\n"
                "  cmdsize 64\n"
                "  path @executable_path/../Frameworks Evil (offset 12)\n"
            ),
            {"@executable_path/../Frameworks Evil"},
        )
        self.assertEqual(
            verify_app_bundle.parse_dependencies(
                "fixture:\n"
                "\t/usr/lib/My Library.dylib "
                "(compatibility version 1.0.0, current version 1.0.0)\n"
            ),
            {"/usr/lib/My Library.dylib"},
        )

    def test_signed_entitlement_reader_uses_current_codesign_output_contract(self) -> None:
        helper = self.root / "helper"
        entitlements = {"com.apple.security.app-sandbox": True}
        result = CompletedProcess(
            args=["codesign"],
            returncode=0,
            stdout=plistlib.dumps(entitlements),
            stderr=b"Executable=helper\n",
        )
        with mock.patch.object(verify_app_bundle.subprocess, "run", return_value=result) as run:
            self.assertEqual(
                verify_app_bundle._read_signed_entitlements(
                    helper,
                    "arm64",
                    required=False,
                ),
                entitlements,
            )
        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/codesign",
                "-d",
                "--architecture",
                "arm64",
                "--entitlements=-",
                "--xml",
                str(helper),
            ],
        )
        empty_result = CompletedProcess(
            args=["codesign"],
            returncode=0,
            stdout=b"",
            stderr=b"Executable=helper\n",
        )
        with mock.patch.object(
            verify_app_bundle.subprocess,
            "run",
            return_value=empty_result,
        ):
            self.assertEqual(
                verify_app_bundle._read_signed_entitlements(
                    helper,
                    "arm64",
                    required=False,
                ),
                {},
            )
            with self.assertRaisesRegex(
                verify_app_bundle.BundleVerificationError,
                "missing its entitlements",
            ):
                verify_app_bundle._read_signed_entitlements(
                    helper,
                    "arm64",
                    required=True,
                )


if __name__ == "__main__":
    unittest.main()
