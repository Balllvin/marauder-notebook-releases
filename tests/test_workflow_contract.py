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

    def test_publisher_schedule_and_manual_fallback_use_only_protected_main(self) -> None:
        workflow = self.workflow()
        self.assertIn("schedule:", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("workflow_run:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("Balllvin/marauder-notebook-release-intake", workflow)
        self.assertIn("scripts/prepare_intake.py prepare-pending", workflow)
        self.assertIn("publication_lock_commit", workflow)
        self.assertIn('--publication-lock-commit "$PUBLICATION_LOCK_COMMIT"', workflow)
        self.assertIn("refs/remotes/intake/publication/*", workflow)
        self.assertIn("ref: refs/heads/main", workflow)
        self.assertIn('[[ "$GITHUB_REF" == "refs/heads/main" ]]', workflow)
        self.assertIn("git fetch --no-tags origin main:refs/remotes/origin/main", workflow)
        self.assertNotIn("github.sha", workflow)
        self.assertIn("fetch-depth: 0", workflow)

    def test_no_pending_intake_is_a_successful_idle_run(self) -> None:
        jq = shutil.which("jq")
        if jq is None:
            self.skipTest("jq is required for the workflow-selection contract")
        program = (
            'if (.available | type) == "boolean" '
            'then (.available | tostring) '
            'else error("available must be a boolean") end'
        )
        workflow = self.workflow()
        self.assertIn('if (.available | type) == "boolean"', workflow)
        self.assertNotIn("jq -er '.available'", workflow)
        result = subprocess.run(
            [jq, "-r", program],
            input='{"available":false}\n',
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "false\n")

    def test_default_publisher_requires_no_apple_credentials(self) -> None:
        workflow = self.workflow()
        self.assertIn("NOTEBOOK_DISTRIBUTION_MODE: independent", workflow)
        self.assertIn('NOTEBOOK_EXPECTED_TEAM_IDENTIFIER: ""', workflow)
        self.assertIn("scripts/verify_app_bundle.py", workflow)
        self.assertIn('--distribution-mode "$NOTEBOOK_DISTRIBUTION_MODE"', workflow)
        self.assertIn('[[ -z "$NOTEBOOK_EXPECTED_TEAM_IDENTIFIER" ]]', workflow)
        self.assertNotIn("secrets.APPLE", workflow)
        self.assertNotIn("notarytool", workflow)
        self.assertNotIn("security import", workflow)
        self.assertNotIn("Contents/MacOS/MarauderNotebook", workflow)

    def test_publication_keeps_all_distribution_gates_before_publish(self) -> None:
        workflow = self.workflow()
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
            "NOTEBOOK_DISTRIBUTION_MODE: independent",
            "xcrun stapler validate",
            "spctl --assess --type execute",
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
        verifier = "\n".join(
            (REPOSITORY_ROOT / "scripts" / name).read_text(encoding="utf-8")
            for name in ("verify_app_bundle.py", "code_signing_contract.py")
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
        ):
            self.assertIn(contract, verifier)

    def test_developer_id_and_gatekeeper_checks_are_dormant_and_explicit(self) -> None:
        workflow = self.workflow()
        developer_guard = 'if [[ "$NOTEBOOK_DISTRIBUTION_MODE" == "developer-id" ]]'
        self.assertGreaterEqual(workflow.count(developer_guard), 2)
        self.assertIn(
            'cfg.distribution_mode == "developer-id"',
            (REPOSITORY_ROOT / "scripts" / "publish_release.py").read_text(
                encoding="utf-8"
            ),
        )
        self.assertIn('--expected-team-identifier "$NOTEBOOK_EXPECTED_TEAM_IDENTIFIER"', workflow)
        self.assertIn("xcrun stapler validate", workflow)
        self.assertIn("spctl --assess --type execute", workflow)
        self.assertLess(workflow.index(developer_guard), workflow.index("xcrun stapler validate"))

    def test_user_copy_is_honest_about_the_one_time_gatekeeper_choice(self) -> None:
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        for contract in (
            "Neither downloading nor using the app requires an Apple account",
            "Control-click",
            "Privacy & Security",
            "Open Anyway",
            "Xcode",
            "terminal commands",
            "Sparkle Ed25519 archive signature",
        ):
            self.assertIn(contract, readme)
        self.assertIn("NOTEBOOK_DISTRIBUTION_MODE: independent", self.workflow())
        self.assertIn(
            "Independently signed universal macOS application",
            (REPOSITORY_ROOT / "scripts" / "publish_release.py").read_text(
                encoding="utf-8"
            ),
        )
        self.assertNotIn("Keychain", readme)

    def test_partial_drafts_are_repaired_before_exact_byte_publication(self) -> None:
        workflow = self.workflow()
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
        workflow = self.workflow()
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
        self.assertIn('PUBLISHER_COMMIT="$(git rev-parse HEAD)"', workflow)

    def test_tag_discovery_fails_closed_without_destructive_cleanup(self) -> None:
        workflow = self.workflow()
        gateway = (REPOSITORY_ROOT / "scripts" / "publisher_gateway.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("def current_tag_target", gateway)
        self.assertIn('"gh", "api", "graphql"', gateway)
        self.assertIn("ref(qualifiedName: $qualifiedName)", gateway)
        self.assertNotIn('git/ref/tags/$RELEASE_TAG" 2>/dev/null || true', workflow)
        self.assertNotIn("--method DELETE \"repos/$GITHUB_REPOSITORY/git/refs/tags", workflow)

    def test_published_attestations_are_reconciled_on_later_idle_runs(self) -> None:
        workflow = self.workflow()
        before = workflow.index("Audit the current immutable release before publication")
        selection = workflow.index("Select the locked or oldest legacy unpublished intake")
        after = workflow.index("Audit the current immutable release after publication")
        self.assertLess(before, selection)
        self.assertGreater(after, selection)
        self.assertEqual(workflow.count("run: scripts/audit_latest_release.sh"), 2)
        self.assertIn("always() && !cancelled()", workflow)

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
        self.assertIn('${NOTEBOOK_DISTRIBUTION_MODE:-independent}', audit)

    def test_workflow_executes_only_executable_verifier_scripts(self) -> None:
        for name in (
            "audit_latest_release.sh",
            "configure_branch_protection.sh",
            "install_actionlint.sh",
            "publish_release.py",
            "verify_openssl.sh",
        ):
            mode = (REPOSITORY_ROOT / "scripts" / name).stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR, f"{name} must be executable")

    def test_publisher_ci_has_a_tracked_required_check_policy(self) -> None:
        ci = (REPOSITORY_ROOT / ".github" / "workflows" / "publisher-ci.yml").read_text(
            encoding="utf-8"
        )
        bootstrap = (
            REPOSITORY_ROOT / "scripts" / "configure_branch_protection.sh"
        ).read_text(encoding="utf-8")
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        for contract in (
            "pull_request_target:",
            "push:",
            "Verify publisher boundary",
            "Run publisher boundary validation",
            "Report publisher validation",
            "python3 -m unittest discover",
            "publisher-policy/scripts/install_actionlint.sh",
            "Check out protected publisher policy",
            "ref: refs/heads/main",
            "working-directory: candidate",
            '"$RUNNER_TEMP/actionlint-bin/actionlint"',
            "notebook-release-publish.yml",
            "github.event.pull_request.head.sha || github.sha",
            "github.event.pull_request.head.repo.full_name || github.repository",
            "statuses: write",
            '"repos/$GITHUB_REPOSITORY/statuses/$HEAD_SHA"',
            'context="Verify publisher boundary"',
            "github.event.pull_request.head.sha || github.sha",
        ):
            self.assertIn(contract, ci)
        self.assertNotIn("name: Verify publisher boundary", ci)
        self.assertLess(ci.index("needs: verify"), ci.index("statuses: write"))
        for contract in (
            'REPOSITORY="Balllvin/marauder-notebook-releases"',
            'REQUIRED_CHECK="Verify publisher boundary"',
            '"strict": true',
            '"contexts": ["$REQUIRED_CHECK"]',
            '"enforce_admins": true',
            '"allow_force_pushes": false',
            '"allow_deletions": false',
            "--apply",
            "Dry run: branch protection was not changed",
        ):
            self.assertIn(contract, bootstrap)
        self.assertIn('"required_approving_review_count": 0', bootstrap)
        self.assertIn("pull_request_target", readme)
        self.assertIn("scripts/configure_branch_protection.sh --apply", readme)

    def test_publish_workflow_delegates_the_release_state_machine(self) -> None:
        workflow = self.workflow()
        self.assertIn("python3 scripts/publish_release.py", workflow)
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
