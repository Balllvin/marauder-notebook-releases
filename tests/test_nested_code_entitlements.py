from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import verify_app_bundle


class NestedCodeEntitlementTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.app = Path(temporary_directory.name) / "Marauder Notebook.app"
        self.main = (
            self.app / "Contents" / "MacOS" / verify_app_bundle.EXECUTABLE_NAME
        )
        self.sparkle = (
            self.app
            / "Contents"
            / "Frameworks"
            / "Sparkle.framework"
            / "Versions"
            / "B"
            / "Sparkle"
        )

    def test_nested_code_requires_the_exact_producer_entitlements(self) -> None:
        verify_app_bundle.verify_nested_code_entitlements(
            self.app,
            [self.main, self.sparkle],
            distribution_mode=verify_app_bundle.ACCOUNT_FREE_MODE,
            entitlement_reader=lambda *_: {},
        )
        for entitlement in (
            "com.apple.security.network.client",
            "com.apple.security.cs.allow-jit",
        ):
            with self.subTest(entitlement=entitlement):
                with self.assertRaisesRegex(
                    verify_app_bundle.BundleVerificationError,
                    "unexpected signed entitlements",
                ):
                    verify_app_bundle.verify_nested_code_entitlements(
                        self.app,
                        [self.main, self.sparkle],
                        distribution_mode=verify_app_bundle.ACCOUNT_FREE_MODE,
                        entitlement_reader=lambda *_, key=entitlement: {key: True},
                    )

    def test_autoupdate_entitlements_follow_the_distribution_mode(self) -> None:
        autoupdate = self.sparkle.with_name("Autoupdate")
        independent_entitlements = {
            "com.apple.application-identifier": (
                "org.sparkle-project.Sparkle.Autoupdate"
            )
        }
        verify_app_bundle.verify_nested_code_entitlements(
            self.app,
            [self.main, autoupdate],
            distribution_mode=verify_app_bundle.INDEPENDENT_MODE,
            entitlement_reader=lambda *_: independent_entitlements,
        )
        verify_app_bundle.verify_nested_code_entitlements(
            self.app,
            [self.main, autoupdate],
            distribution_mode=verify_app_bundle.ACCOUNT_FREE_MODE,
            entitlement_reader=lambda *_: {},
        )
        for distribution_mode, entitlements in (
            (verify_app_bundle.INDEPENDENT_MODE, {}),
            (verify_app_bundle.ACCOUNT_FREE_MODE, independent_entitlements),
        ):
            with self.subTest(distribution_mode=distribution_mode):
                with self.assertRaisesRegex(
                    verify_app_bundle.BundleVerificationError,
                    "unexpected signed entitlements",
                ):
                    verify_app_bundle.verify_nested_code_entitlements(
                        self.app,
                        [self.main, autoupdate],
                        distribution_mode=distribution_mode,
                        entitlement_reader=lambda *_, value=entitlements: value,
                    )

    def test_nested_code_checks_entitlements_in_both_architecture_slices(self) -> None:
        inspected: list[tuple[Path, str]] = []

        def entitlements(path: Path, architecture: str) -> dict[str, object]:
            inspected.append((path, architecture))
            if architecture == "x86_64":
                return {"com.apple.security.cs.allow-jit": True}
            return {}

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            r"Sparkle \[x86_64\].*unexpected signed entitlements",
        ):
            verify_app_bundle.verify_nested_code_entitlements(
                self.app,
                [self.sparkle],
                distribution_mode=verify_app_bundle.ACCOUNT_FREE_MODE,
                entitlement_reader=entitlements,
            )
        self.assertEqual(
            inspected,
            [(self.sparkle, "arm64"), (self.sparkle, "x86_64")],
        )


if __name__ == "__main__":
    unittest.main()
