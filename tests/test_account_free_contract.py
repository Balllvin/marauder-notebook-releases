from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess

from scripts import code_signing_contract, verify_account_free_gatekeeper, verify_app_bundle


class AccountFreeContractTests(unittest.TestCase):
    def details(self, **overrides: list[str]) -> dict[str, list[str]]:
        result = {
            "Signature": ["adhoc"],
            "TeamIdentifier": ["not set"],
            "Identifier": [code_signing_contract.BUNDLE_IDENTIFIER],
            "flags": ["0x10000(runtime)"],
        }
        result.update(overrides)
        return result

    def test_account_free_signature_is_exact_and_keeps_hardened_runtime(self) -> None:
        code_signing_contract.verify_signing_details(
            self.details(),
            label="main",
            distribution_mode=code_signing_contract.ACCOUNT_FREE_MODE,
            expected_team_identifier=None,
            is_main_executable=True,
            require_hardened_runtime=True,
        )
        malformed = (
            {"Authority": ["Developer ID Application: Unexpected"]},
            {"Timestamp": ["secure"]},
            {"flags": ["0x0(none)"]},
            {"TeamIdentifier": ["ABCDEFGHIJ"]},
        )
        for override in malformed:
            with self.subTest(override=override), self.assertRaises(
                code_signing_contract.BundleVerificationError
            ):
                code_signing_contract.verify_signing_details(
                    self.details(**override),
                    label="main",
                    distribution_mode=code_signing_contract.ACCOUNT_FREE_MODE,
                    expected_team_identifier=None,
                    is_main_executable=True,
                    require_hardened_runtime=True,
                )

    def test_account_free_verification_never_extracts_a_certificate_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            app = Path(temporary_directory) / "Marauder Notebook.app"
            main = app / "Contents" / "MacOS" / "Marauder Notebook"
            main.parent.mkdir(parents=True)
            main.write_bytes(b"binary")

            def no_certificate_chain(_path: Path, _architecture: str):
                raise AssertionError("account-free verification must not read certificates")

            code_signing_contract.verify_code_signatures(
                app,
                [main],
                distribution_mode=code_signing_contract.ACCOUNT_FREE_MODE,
                expected_team_identifier=None,
                expected_code_identifiers={
                    "Contents/MacOS/Marauder Notebook": code_signing_contract.BUNDLE_IDENTIFIER,
                },
                details_for=lambda _path, _architecture: self.details(),
                certificate_chain_for=no_certificate_chain,
            )

    def test_account_free_entitlements_cannot_smuggle_an_apple_identity(self) -> None:
        verify_app_bundle.verify_entitlements(
            dict(verify_app_bundle.REQUIRED_ENTITLEMENTS),
            distribution_mode=verify_app_bundle.ACCOUNT_FREE_MODE,
        )
        for entitlement in verify_app_bundle.APPLE_IDENTITY_ENTITLEMENTS:
            payload = dict(verify_app_bundle.REQUIRED_ENTITLEMENTS)
            payload[entitlement] = "unexpected"
            with self.subTest(entitlement=entitlement), self.assertRaises(
                verify_app_bundle.BundleVerificationError
            ):
                verify_app_bundle.verify_entitlements(
                    payload,
                    distribution_mode=verify_app_bundle.ACCOUNT_FREE_MODE,
                )

    def test_gatekeeper_boundary_accepts_only_no_ticket_and_policy_denial_codes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            app = Path(temporary_directory) / "Marauder Notebook.app"
            app.mkdir()

            def run_ok(arguments, **_kwargs):
                code = 65 if "stapler" in arguments else 3
                return CompletedProcess(arguments, code, "", "")

            verify_account_free_gatekeeper.verify_account_free_gatekeeper(app, run=run_ok)
            for stapler_code, assessment_code in ((1, 3), (65, 1), (65, 0)):
                calls = 0

                def run_bad(arguments, **_kwargs):
                    nonlocal calls
                    calls += 1
                    code = stapler_code if calls == 1 else assessment_code
                    return CompletedProcess(arguments, code, "", "")

                with self.subTest(
                    stapler_code=stapler_code, assessment_code=assessment_code
                ), self.assertRaises(
                    verify_account_free_gatekeeper.GatekeeperBoundaryError
                ):
                    verify_account_free_gatekeeper.verify_account_free_gatekeeper(
                        app, run=run_bad
                    )


if __name__ == "__main__":
    unittest.main()
