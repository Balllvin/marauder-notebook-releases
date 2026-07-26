from __future__ import annotations

import shutil
import stat
import subprocess
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class WorkflowContractTests(unittest.TestCase):
    def workflow(self) -> str:
        return (
            REPOSITORY_ROOT / ".github" / "workflows" / "notebook-release-publish.yml"
        ).read_text(encoding="utf-8")

    def publisher(self) -> str:
        return (REPOSITORY_ROOT / "scripts" / "publish_local.sh").read_text(
            encoding="utf-8"
        )

    def test_manual_publisher_workflow_uses_only_protected_main(self) -> None:
        workflow = self.workflow()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("schedule:", workflow)
        self.assertNotIn("workflow_run:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("ref: refs/heads/main", workflow)
        self.assertIn("scripts/publish_local.sh --publish", workflow)
        self.assertNotIn("github.sha", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        publisher = self.publisher()
        self.assertIn("Balllvin/marauder-notebook-release-intake", publisher)
        self.assertIn("scripts/prepare_intake.py prepare-pending", publisher)
        self.assertIn('PUBLICATION_LOCK_COMMIT="$(jq -er .publication_lock_commit', publisher)
        self.assertIn('--publication-lock-commit "$PUBLICATION_LOCK_COMMIT"', publisher)
        self.assertIn("refs/remotes/intake/publication/*", publisher)
        self.assertIn("git fetch origin refs/heads/main:refs/remotes/origin/main --prune", publisher)

    def test_no_pending_intake_is_a_successful_idle_run(self) -> None:
        jq = shutil.which("jq")
        if jq is None:
            self.skipTest("jq is required for the workflow-selection contract")
        program = (
            'if (.available | type) == "boolean" '
            'then (.available | tostring) '
            'else error("available must be a boolean") end'
        )
        publisher = self.publisher()
        self.assertIn('if (.available | type) == "boolean"', publisher)
        self.assertNotIn("jq -er '.available'", publisher)
        result = subprocess.run(
            [jq, "-r", program],
            input='{"available":false}\n',
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "false\n")

    def test_public_publisher_requires_the_exact_account_free_contract(self) -> None:
        contract = self.workflow() + self.publisher()
        self.assertIn('export NOTEBOOK_DISTRIBUTION_MODE="$DISTRIBUTION_MODE"', contract)
        self.assertIn("NOTEBOOK_EXPECTED_TEAM_IDENTIFIER", contract)
        self.assertIn("^[A-Z0-9]{10}$", contract)
        self.assertIn("scripts/verify_app_bundle.py", contract)
        self.assertIn('--distribution-mode "$DISTRIBUTION_MODE"', contract)
        self.assertIn("--expected-team-identifier", contract)
        self.assertIn("xcrun stapler validate", contract)
        self.assertIn("spctl --assess --type execute", contract)
        self.assertIn("scripts/verify_account_free_gatekeeper.py", contract)

    def test_publication_keeps_all_distribution_gates_before_publish(self) -> None:
        workflow = self.publisher()
        publisher = (REPOSITORY_ROOT / "scripts" / "publish_release.py").read_text(
            encoding="utf-8"
        )
        gateway = (REPOSITORY_ROOT / "scripts" / "publisher_gateway.py").read_text(
            encoding="utf-8"
        )
        for contract in (
            "verify_intake.py assert-newer",
            "verify_intake.py assert-source-link",
            "previous-signed-release",
            "--previous-manifest",
            "scripts/verify_release_archive.py",
            "scripts/verify_app_bundle.py",
            'export NOTEBOOK_DISTRIBUTION_MODE="$DISTRIBUTION_MODE"',
        ):
            self.assertIn(contract, workflow)
        for contract in (
            "release_state.plan_assets",
            "filecmp.cmp",
            "verify_asset",
            "verify_intake.assert_newer",
            "PublishState.PUBLISH_ATTEMPTED",
        ):
            self.assertIn(contract, publisher)
        self.assertIn('"gh", "release", "verify-asset"', gateway)
        self.assertLess(
            workflow.index("scripts/verify_release_archive.py"),
            workflow.index("/usr/bin/ditto -x -k"),
        )
        self.assertLess(
            workflow.index("scripts/verify_app_bundle.py"),
            workflow.index("scripts/publish_release.py"),
        )
        self.assertLess(
            workflow.index("xcrun stapler validate"),
            workflow.index("scripts/publish_release.py"),
        )
        self.assertLess(
            workflow.index("spctl --assess --type execute"),
            workflow.index("scripts/publish_release.py"),
        )
        verifier = "\n".join(
            (REPOSITORY_ROOT / "scripts" / name).read_text(encoding="utf-8")
            for name in (
                "verify_app_bundle.py",
                "macho_contract.py",
                "code_signing_contract.py",
            )
        )
        for contract in (
            '"--all-architectures"',
            'signature == "adhoc"',
            "PINNED_INDEPENDENT_ROOT_CERTIFICATE_SHA256",
            "PINNED_INDEPENDENT_DESIGNATED_REQUIREMENT",
            "wrong independent root certificate",
            "different independent release certificate",
            "exact root-bound designated requirement",
            '"Sparkle.framework" in relative.parts',
            "must retain Hardened Runtime",
            "must not depend on an Apple secure timestamp",
            "EXPECTED_NESTED_CODE_ENTITLEMENTS",
            "EXPECTED_CODE_IDENTIFIERS",
            "ALLOWED_RPATHS",
            "BUILD_HOST_PATH",
            "unsafe dynamic dependencies",
        ):
            self.assertIn(contract, verifier)

    def test_local_publication_uses_the_verified_manifest_distribution(self) -> None:
        workflow = self.publisher()
        self.assertIn("export NOTEBOOK_DISTRIBUTION_MODE=\"$DISTRIBUTION_MODE\"", workflow)
        self.assertEqual(workflow.count('--distribution-mode "$DISTRIBUTION_MODE"'), 2)
        self.assertIn('.distribution_mode | select(. == "account-free" or . == "developer-id")', workflow)
        self.assertNotIn("--distribution-mode independent", workflow)
        self.assertIn(
            "arguments.distribution_mode not in verify_intake.PUBLIC_DISTRIBUTIONS",
            (REPOSITORY_ROOT / "scripts" / "publish_release.py").read_text(
                encoding="utf-8"
            ),
        )

    def test_user_copy_explains_account_free_first_launch_approval(self) -> None:
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        for contract in (
            "account-free",
            "Privacy & Security",
            "Open Anyway",
        ):
            self.assertIn(contract, readme)
        self.assertIn(
            "Integrity-verified account-free universal macOS application",
            (REPOSITORY_ROOT / "scripts" / "publish_release.py").read_text(
                encoding="utf-8"
            ),
        )
        self.assertNotIn("xattr", readme)
        self.assertNotIn("Control-click", readme)

    def test_partial_drafts_are_repaired_before_exact_byte_publication(self) -> None:
        workflow = self.publisher()
        publisher = (REPOSITORY_ROOT / "scripts" / "publish_release.py").read_text(
            encoding="utf-8"
        )
        gateway = (REPOSITORY_ROOT / "scripts" / "publisher_gateway.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("release_state.select_draft", publisher)
        self.assertIn("release_state.plan_assets", publisher)
        self.assertIn("existing draft asset differs", publisher)
        self.assertIn("uploaded release asset differs", publisher)
        self.assertIn('"gh", "release", "upload"', gateway)
        self.assertIn("Accept: application/octet-stream", gateway)
        self.assertNotIn("gh release upload", workflow)

    def test_publish_boundary_is_revocable_and_cleanup_stops_before_publish(self) -> None:
        workflow = self.publisher()
        publisher = (REPOSITORY_ROOT / "scripts" / "publish_release.py").read_text(
            encoding="utf-8"
        )
        gateway = (REPOSITORY_ROOT / "scripts" / "publisher_gateway.py").read_text(
            encoding="utf-8"
        )
        final_ref_check = publisher.rindex("self._assert_intake_unchanged()")
        publish_attempt = publisher.index("self.state = PublishState.PUBLISH_ATTEMPTED")
        publish_call = publisher.index("self.gateway.publish")
        self.assertLess(final_ref_check, publish_attempt)
        self.assertLess(publish_attempt, publish_call)
        self.assertIn("release_state.cleanup_allowed", publisher)
        self.assertIn("self.state >= PublishState.PUBLISH_ATTEMPTED", publisher)
        self.assertNotIn("git/refs/tags/$RELEASE_TAG", workflow)
        self.assertNotIn("OWNED_TAG_CREATED", workflow)
        self.assertIn('"git", "merge-base", "--is-ancestor"', gateway)
        self.assertIn('PUBLISHER_COMMIT="$(git rev-parse HEAD^{commit})"', workflow)

    def test_tag_discovery_fails_closed_without_destructive_cleanup(self) -> None:
        workflow = self.publisher()
        gateway = (REPOSITORY_ROOT / "scripts" / "publisher_gateway.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("def current_tag_target", gateway)
        self.assertIn('"gh", "api", "graphql"', gateway)
        self.assertIn("ref(qualifiedName: $qualifiedName)", gateway)
        self.assertNotIn('git/ref/tags/$RELEASE_TAG" 2>/dev/null || true', workflow)
        self.assertNotIn("--method DELETE \"repos/$GITHUB_REPOSITORY/git/refs/tags", workflow)

    def test_published_attestations_are_reconciled_on_later_idle_runs(self) -> None:
        workflow = self.publisher()
        selection = workflow.index("prepare_intake.py select")
        self.assertLess(workflow.index("scripts/audit_latest_release.sh"), selection)
        self.assertGreater(workflow.rindex("scripts/audit_latest_release.sh"), selection)
        self.assertEqual(workflow.count("scripts/audit_latest_release.sh"), 2)

        audit = (REPOSITORY_ROOT / "scripts" / "audit_latest_release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("release_state.py audit-published", audit)
        self.assertIn('gh release verify "$published_tag"', audit)
        self.assertIn(".tags[-1]", audit)
        self.assertIn("verify_app_bundle.py", audit)
        self.assertIn("verify_release_archive.py", audit)
        self.assertLess(
            audit.index("verify_release_archive.py"),
            audit.index("/usr/bin/ditto -x -k"),
        )
        self.assertIn("--allow-legacy-published", audit)
        self.assertIn("RELEASE_DISTRIBUTION_MODE", audit)
        self.assertIn("historical input only", audit)

    def test_workflow_executes_only_executable_verifier_scripts(self) -> None:
        for name in (
            "audit_latest_release.sh",
            "configure_branch_protection.sh",
            "install_actionlint.sh",
            "publish_release.py",
            "publish_local.sh",
            "verify_publisher_boundary.sh",
            "verify_openssl.sh",
        ):
            mode = (REPOSITORY_ROOT / "scripts" / name).stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR, f"{name} must be executable")

    def test_publisher_ci_is_optional_and_branch_policy_is_local_first(self) -> None:
        ci = (REPOSITORY_ROOT / ".github" / "workflows" / "publisher-ci.yml").read_text(
            encoding="utf-8"
        )
        bootstrap = (
            REPOSITORY_ROOT / "scripts" / "configure_branch_protection.sh"
        ).read_text(encoding="utf-8")
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        local_verifier = (
            REPOSITORY_ROOT / "scripts" / "verify_publisher_boundary.sh"
        ).read_text(encoding="utf-8")
        for contract in (
            "workflow_dispatch:",
            "Reverify protected publisher main",
            "scripts/verify_publisher_boundary.sh",
        ):
            self.assertIn(contract, ci)
        self.assertNotIn("pull_request:", ci)
        self.assertNotIn("pull_request_target:", ci)
        self.assertNotIn("\n  push:", ci)
        self.assertNotIn("schedule:", ci)
        self.assertNotIn("statuses: write", ci)
        self.assertNotIn("statuses/$HEAD_SHA", ci)
        self.assertIn("Check out protected publisher main", ci)
        self.assertIn("ref: refs/heads/main", ci)
        self.assertIn("run: scripts/verify_publisher_boundary.sh", ci)
        for contract in (
            'scripts/install_actionlint.sh "$ACTIONLINT_ROOT"',
            "notebook-release-publish.yml",
            "publisher-ci.yml",
            "python3 -m compileall -q scripts tests",
            "bash -n scripts/*.sh",
            "scripts/verify_openssl.sh",
            "python3 -m unittest discover",
            "--root",
            '[[ -z "$(git status --porcelain)" ]]',
        ):
            self.assertIn(contract, local_verifier)
        for forbidden in ("--record-status", "GH_TOKEN", "GITHUB_TOKEN", "gh api"):
            self.assertNotIn(forbidden, local_verifier)
        self.assertNotIn('"$SCRIPT_DIR/install_actionlint.sh"', local_verifier)
        for contract in (
            'REPOSITORY="Balllvin/marauder-notebook-releases"',
            '"required_status_checks": null',
            '"enforce_admins": true',
            '"allow_force_pushes": false',
            '"allow_deletions": false',
            "--apply",
            "Dry run: branch protection was not changed",
        ):
            self.assertIn(contract, bootstrap)
        self.assertIn('"required_approving_review_count": 0', bootstrap)
        self.assertIn("--root /path/to/candidate-checkout", readme)
        self.assertIn("scripts/configure_branch_protection.sh --apply", readme)

    def test_publish_workflow_delegates_the_release_state_machine(self) -> None:
        workflow = self.workflow()
        publisher = self.publisher()
        self.assertIn("scripts/publish_local.sh --publish", workflow)
        self.assertNotIn("scripts/publish_release.py", workflow)
        self.assertIn("python3 scripts/publish_release.py", publisher)
        for legacy_shell in (
            "cleanup_failed_draft",
            "current_tag_target()",
            "gh release upload",
            "gh release edit",
            "PUBLISH_ATTEMPTED=true",
        ):
            self.assertNotIn(legacy_shell, workflow)


if __name__ == "__main__":
    unittest.main()
