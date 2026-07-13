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

    def test_publisher_uses_only_the_protected_default_branch_schedule(self) -> None:
        workflow = self.workflow()
        self.assertIn("schedule:", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("workflow_run:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("Balllvin/marauder-notebook-release-intake", workflow)
        self.assertIn("scripts/prepare_intake.py prepare", workflow)
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

    def test_gatekeeper_resolves_the_packaged_executable_contract(self) -> None:
        workflow = self.workflow()
        self.assertIn("scripts/verify_app_bundle.py", workflow)
        self.assertIn("--team-identifier", workflow)
        self.assertIn("codesign -d --entitlements :-", workflow)
        self.assertIn('[[ "$SIGNING_IDENTIFIER" == "com.marauder.notebook" ]]', workflow)
        self.assertNotIn("Contents/MacOS/MarauderNotebook", workflow)

    def test_publication_keeps_all_distribution_gates_before_publish(self) -> None:
        workflow = self.workflow()
        for contract in (
            "verify_intake.py assert-newer",
            "codesign --verify --deep --strict",
            "Authority=Developer ID Application:",
            "flags=0x10000(runtime)",
            "xcrun stapler validate",
            "spctl --assess --type execute",
            "scripts/release_state.py plan-assets",
            'cmp "$INTAKE/$name" "$DOWNLOADED/$name"',
            "gh release verify-asset",
        ):
            self.assertIn(contract, workflow)
        self.assertLess(
            workflow.index("spctl --assess --type execute"),
            workflow.index("gh api --method POST"),
        )

    def test_partial_drafts_are_repaired_before_exact_byte_publication(self) -> None:
        workflow = self.workflow()
        self.assertIn("gh api --method POST", workflow)
        self.assertIn("gh release upload", workflow)
        self.assertIn("scripts/release_state.py plan-assets", workflow)
        self.assertIn("Accept: application/octet-stream", workflow)
        self.assertIn('cmp "$INTAKE/$name" "$RUNNER_TEMP/existing-$name"', workflow)
        self.assertIn('[[ "$(jq -er \'.missing | length\' "$FINAL_ASSET_PLAN")" -eq 0 ]]', workflow)

    def test_publish_boundary_is_revocable_and_cleanup_stops_before_publish(self) -> None:
        workflow = self.workflow()
        final_ref_check = workflow.rindex("CURRENT_INTAKE_REF=")
        publish_attempt = workflow.index("PUBLISH_ATTEMPTED=true")
        publish_call = workflow.index('gh release edit "$RELEASE_TAG"')
        self.assertLess(final_ref_check, publish_attempt)
        self.assertLess(publish_attempt, publish_call)
        self.assertIn("scripts/release_state.py cleanup-allowed", workflow)
        self.assertIn('--publish-attempted "$PUBLISH_ATTEMPTED"', workflow)
        self.assertNotIn("git/refs/tags/$RELEASE_TAG", workflow)
        self.assertNotIn("OWNED_TAG_CREATED", workflow)
        self.assertIn("git merge-base --is-ancestor", workflow)
        self.assertIn('PUBLISHER_COMMIT="$(git rev-parse HEAD)"', workflow)

    def test_tag_discovery_fails_closed_without_destructive_cleanup(self) -> None:
        workflow = self.workflow()
        self.assertIn("current_tag_target()", workflow)
        self.assertIn("gh api graphql", workflow)
        self.assertIn("ref(qualifiedName: $qualifiedName)", workflow)
        self.assertNotIn('git/ref/tags/$RELEASE_TAG" 2>/dev/null || true', workflow)
        self.assertNotIn("--method DELETE \"repos/$GITHUB_REPOSITORY/git/refs/tags", workflow)

    def test_published_attestations_are_reconciled_on_later_idle_runs(self) -> None:
        workflow = self.workflow()
        before = workflow.index("Audit the current immutable release before publication")
        selection = workflow.index("Select the oldest unpublished intake")
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

    def test_workflow_executes_only_executable_verifier_scripts(self) -> None:
        for name in ("audit_latest_release.sh", "verify_openssl.sh"):
            mode = (REPOSITORY_ROOT / "scripts" / name).stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR, f"{name} must be executable")


if __name__ == "__main__":
    unittest.main()
