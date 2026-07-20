from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPOSITORY_ROOT / "scripts" / "publish_local.sh"


class LocalPublisherTests(unittest.TestCase):
    def script(self) -> str:
        return SCRIPT.read_text(encoding="utf-8")

    def run_origin_normalizer(self, remote_url: str) -> subprocess.CompletedProcess[str]:
        script = self.script()
        function = script.split("canonical_github_repository_from_url() {", 1)[1].split(
            "\n}\n\ncd", 1
        )[0]
        command = (
            "canonical_github_repository_from_url() {"
            f"{function}\n}}\n"
            'canonical_github_repository_from_url "$1"'
        )
        return subprocess.run(
            ["bash", "-c", command, "--", remote_url],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_safe_default_and_explicit_publish_boundary(self) -> None:
        script = self.script()
        self.assertIn("MODE=verify", script)
        self.assertIn("--verify) MODE=verify", script)
        self.assertIn("--publish) MODE=publish", script)
        verification_exit = script.index('if [[ "$MODE" == "verify" ]]')
        publish_call = script.index("python3 scripts/publish_release.py")
        post_audit = script.rindex("scripts/audit_latest_release.sh")
        self.assertLess(verification_exit, publish_call)
        self.assertLess(publish_call, post_audit)
        self.assertNotIn("gh release upload", script)
        self.assertNotIn("gh release edit", script)

    def test_exact_protected_main_and_immutable_release_preflight(self) -> None:
        script = self.script()
        for contract in (
            'REPOSITORY="Balllvin/marauder-notebook-releases"',
            'INTAKE_REPOSITORY="Balllvin/marauder-notebook-release-intake"',
            '[[ -z "$(git status --porcelain)" ]]',
            "git fetch origin refs/heads/main:refs/remotes/origin/main --prune",
            '[[ "$PUBLISHER_COMMIT" == "$ORIGIN_MAIN_COMMIT" ]]',
            '"https://github.com/$REPOSITORY.git" refs/heads/main',
            '"repos/$REPOSITORY/branches/main/protection"',
            ".required_status_checks.strict == true",
            ".enforce_admins.enabled == true",
            ".required_linear_history.enabled == true",
            ".required_conversation_resolution.enabled == true",
            ".allow_force_pushes.enabled == false",
            ".allow_deletions.enabled == false",
            '"repos/$REPOSITORY/immutable-releases"',
        ):
            self.assertIn(contract, script)
        self.assertLess(
            script.index('[[ "$PUBLISHER_COMMIT" == "$ORIGIN_MAIN_COMMIT" ]]'),
            script.index("scripts/audit_latest_release.sh"),
        )

    def test_reuses_one_verified_intake_and_publication_state_machine(self) -> None:
        script = self.script()
        for contract in (
            "scripts/prepare_intake.py select",
            "scripts/prepare_intake.py prepare-pending",
            "scripts/verify_release_archive.py",
            "/usr/bin/ditto -x -k",
            "scripts/verify_app_bundle.py",
            "scripts/release_state.py audit-published",
            "scripts/verify_intake.py assert-source-link",
            "scripts/verify_intake.py assert-newer",
            "python3 scripts/publish_release.py",
            "--publication-lock-commit",
        ):
            self.assertIn(contract, script)
        self.assertLess(
            script.index("scripts/verify_release_archive.py"),
            script.index("/usr/bin/ditto -x -k"),
        )
        self.assertLess(
            script.index("scripts/verify_app_bundle.py"),
            script.index("python3 scripts/publish_release.py"),
        )
        self.assertIn('trap cleanup EXIT', script)
        self.assertIn('git init -q "$INTAKE_CHECKOUT"', script)
        self.assertNotIn("git remote add intake", script)

    def test_origin_normalizer_accepts_only_the_public_publisher(self) -> None:
        for remote_url in (
            "git@github.com:Balllvin/marauder-notebook-releases.git",
            "https://github.com/Balllvin/marauder-notebook-releases.git",
            "ssh://git@github.com/Balllvin/marauder-notebook-releases.git",
        ):
            with self.subTest(remote_url=remote_url):
                result = self.run_origin_normalizer(remote_url)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    result.stdout.strip(), "Balllvin/marauder-notebook-releases"
                )
        for remote_url in (
            "git@github.com:Balllvin/marauder.git",
            "git@github.com:Other/marauder-notebook-releases.git",
            "https://token@github.com/Balllvin/marauder-notebook-releases.git",
            "https://github.com/Balllvin/marauder-notebook-releases.git?ref=main",
        ):
            with self.subTest(remote_url=remote_url):
                self.assertNotEqual(self.run_origin_normalizer(remote_url).returncode, 0)


if __name__ == "__main__":
    unittest.main()
