from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import code_signing_contract, verify_app_bundle


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
            "SUAutomaticallyUpdate": False,
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

    def independent_entitlements(self) -> dict[str, object]:
        return dict(verify_app_bundle.INDEPENDENT_MAIN_ENTITLEMENTS)

    def test_accepts_exact_info_and_security_contract(self) -> None:
        verify_app_bundle.verify_info_plist(
            self.info(),
            release_version="1.2.3",
            build_number="42",
        )
        verify_app_bundle.verify_entitlements(
            self.independent_entitlements(),
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
        entitlements = self.independent_entitlements()
        entitlements["com.apple.security.files.downloads.read-write"] = True
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "unexpected entitlements",
        ):
            verify_app_bundle.verify_entitlements(
                entitlements,
                distribution_mode=verify_app_bundle.INDEPENDENT_MODE,
            )
        entitlements = self.independent_entitlements()
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

    def test_requires_safe_automatic_update_defaults_and_rejects_extra_launch_policy(
        self,
    ) -> None:
        for key in (
            "SUEnableAutomaticChecks",
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
        for value in (True, 0):
            info = self.info()
            info["SUAutomaticallyUpdate"] = value
            with self.subTest(SUAutomaticallyUpdate=value):
                with self.assertRaisesRegex(
                    verify_app_bundle.BundleVerificationError,
                    "SUAutomaticallyUpdate",
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

    def test_accepts_only_the_explicit_legacy_automatic_update_default(self) -> None:
        info = self.info()
        info["SUAutomaticallyUpdate"] = True
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "SUAutomaticallyUpdate",
        ):
            verify_app_bundle.verify_info_plist(
                info,
                release_version="1.2.3",
                build_number="42",
            )
        verify_app_bundle.verify_info_plist(
            info,
            release_version="1.2.3",
            build_number="42",
            allow_legacy_automatic_update_default=True,
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
            entitlements = self.independent_entitlements()
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

# The account-free table published with 1.0.6. Independent mode must reject it.
ACCOUNT_FREE_ENTITLEMENTS = {
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
INDEPENDENT_MAIN_ENTITLEMENTS = {
    **ACCOUNT_FREE_ENTITLEMENTS,
    "com.apple.security.application-groups": ["group.com.marauder.notebook"],
    "com.apple.security.network.server": True,
}
HELPER_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": True,
    "com.apple.security.inherit": True,
}
HARNESS_PATH = "Contents/MacOS/notebook-harness"
CONTROL_PATH = "Contents/MacOS/notebook-control"
MAIN_PATH = f"Contents/MacOS/{verify_app_bundle.EXECUTABLE_NAME}"
AUTOUPDATE_ENTITLEMENTS = {
    "com.apple.application-identifier": "org.sparkle-project.Sparkle.Autoupdate"
}


class IndependentBundleLayoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.identifiers = {
            **verify_app_bundle.EXPECTED_CODE_IDENTIFIERS,
            HARNESS_PATH: "com.marauder.notebook.harness",
            CONTROL_PATH: "com.marauder.notebook.control",
        }

    def install(self, relatives: tuple[str, ...]) -> Path:
        app = self.root / "Marauder Notebook.app"
        info = app / "Contents" / "Info.plist"
        info.parent.mkdir(parents=True, exist_ok=True)
        info.write_bytes(plistlib.dumps(VerifyAppBundleTests.info(self)))
        for relative in relatives:
            path = app / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"macho")
        return app

    def verify(
        self,
        relatives: tuple[str, ...],
        mode: str,
        *,
        main_entitlements: dict[str, object],
        helper_entitlements: dict[str, object] | None = None,
    ) -> None:
        app = self.install(relatives)
        helpers = HELPER_ENTITLEMENTS if helper_entitlements is None else helper_entitlements
        root_sha1 = verify_app_bundle.PINNED_INDEPENDENT_DESIGNATED_REQUIREMENT.split('H"', 1)[1][:40]
        root_sha256 = verify_app_bundle.PINNED_INDEPENDENT_ROOT_CERTIFICATE_SHA256

        def entitlements(path: Path, _architecture: str, *, required: bool = False) -> dict[str, object]:
            del required
            relative = path.relative_to(app).as_posix()
            if relative == MAIN_PATH:
                return main_entitlements
            if relative == HARNESS_PATH:
                return HELPER_ENTITLEMENTS
            if relative == CONTROL_PATH:
                return helpers
            if relative.endswith("/Autoupdate") and mode == verify_app_bundle.INDEPENDENT_MODE:
                return AUTOUPDATE_ENTITLEMENTS
            return {}

        def details(path: Path, _architecture: str) -> dict[str, list[str]]:
            identifier = self.identifiers.get(path.relative_to(app).as_posix(), "com.marauder.injected")
            if mode == verify_app_bundle.ACCOUNT_FREE_MODE:
                return {
                    "Signature": ["adhoc"],
                    "TeamIdentifier": ["not set"],
                    "Identifier": [identifier],
                    "flags": ["0x10000(runtime)"],
                }
            return {
                "Signature": ["cms"],
                "Identifier": [identifier],
                "TeamIdentifier": ["not set"],
                "Authority": ["Marauder Notebook Release"],
                "flags": ["0x10000(runtime)"],
            }

        def chain(_path: Path, _architecture: str) -> code_signing_contract.CertificateChain:
            return code_signing_contract.CertificateChain(
                sha256=("A" * 64, root_sha256),
                root_sha1=root_sha1,
            )

        def requirement(path: Path, _architecture: str) -> str:
            identifier = self.identifiers.get(path.relative_to(app).as_posix(), "com.marauder.injected")
            return f'designated => identifier "{identifier}" and certificate root = H"{root_sha1}"'

        real_verify = verify_app_bundle.verify_code_signatures

        def wrapped(bundle: Path, machos: list[Path], **kwargs: object) -> None:
            kwargs["details_for"] = details
            kwargs["certificate_chain_for"] = chain
            kwargs["designated_requirement_for"] = requirement
            real_verify(bundle, machos, **kwargs)  # type: ignore[arg-type]

        with (
            mock.patch.object(verify_app_bundle, "verify_icon"),
            mock.patch.object(verify_app_bundle, "verify_declared_executable"),
            mock.patch.object(
                verify_app_bundle,
                "verify_macho_architectures",
                lambda bundle: [bundle / relative for relative in relatives],
            ),
            mock.patch.object(verify_app_bundle, "verify_macho_deployment_targets"),
            mock.patch.object(verify_app_bundle, "verify_macho_load_paths"),
            mock.patch.object(verify_app_bundle, "verify_sealed_bundle"),
            mock.patch.object(verify_app_bundle, "verify_code_signatures", wrapped),
            mock.patch.object(verify_app_bundle, "_read_signed_entitlements", entitlements),
        ):
            verify_app_bundle.verify_app_bundle(
                app,
                release_version="1.2.3",
                build_number="42",
                distribution_mode=mode,
            )

    def independent_paths(self, *, control: bool = True, extra: str | None = None) -> tuple[str, ...]:
        paths = list(verify_app_bundle.EXPECTED_CODE_IDENTIFIERS)
        paths.append(HARNESS_PATH)
        if control:
            paths.append(CONTROL_PATH)
        if extra is not None:
            paths.append(extra)
        return tuple(paths)

    def test_independent_bundle_with_harness_and_control_passes(self) -> None:
        self.verify(
            self.independent_paths(),
            verify_app_bundle.INDEPENDENT_MODE,
            main_entitlements=INDEPENDENT_MAIN_ENTITLEMENTS,
        )
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "notebook-control.*unexpected signed entitlements",
        ):
            self.verify(
                self.independent_paths(),
                verify_app_bundle.INDEPENDENT_MODE,
                main_entitlements=INDEPENDENT_MAIN_ENTITLEMENTS,
                helper_entitlements={
                    **HELPER_ENTITLEMENTS,
                    "com.apple.security.cs.allow-jit": True,
                },
            )
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "Contents/MacOS/injected",
        ):
            self.verify(
                self.independent_paths(extra="Contents/MacOS/injected"),
                verify_app_bundle.INDEPENDENT_MODE,
                main_entitlements=INDEPENDENT_MAIN_ENTITLEMENTS,
            )

    def test_independent_bundle_missing_control_fails(self) -> None:
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "missing:.*notebook-control",
        ):
            self.verify(
                self.independent_paths(control=False),
                verify_app_bundle.INDEPENDENT_MODE,
                main_entitlements=INDEPENDENT_MAIN_ENTITLEMENTS,
            )

    def test_account_free_table_unchanged(self) -> None:
        self.verify(
            tuple(verify_app_bundle.EXPECTED_CODE_IDENTIFIERS),
            verify_app_bundle.ACCOUNT_FREE_MODE,
            main_entitlements=ACCOUNT_FREE_ENTITLEMENTS,
        )
        verify_app_bundle.verify_entitlements(
            ACCOUNT_FREE_ENTITLEMENTS,
            distribution_mode=verify_app_bundle.ACCOUNT_FREE_MODE,
        )
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "application-groups",
        ):
            verify_app_bundle.verify_entitlements(
                ACCOUNT_FREE_ENTITLEMENTS,
                distribution_mode=verify_app_bundle.INDEPENDENT_MODE,
            )
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "notebook-harness is outside the expected nested-code",
        ):
            self.verify(
                tuple(verify_app_bundle.EXPECTED_CODE_IDENTIFIERS) + (HARNESS_PATH,),
                verify_app_bundle.ACCOUNT_FREE_MODE,
                main_entitlements=ACCOUNT_FREE_ENTITLEMENTS,
            )


if __name__ == "__main__":
    unittest.main()
