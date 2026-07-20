from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import intake_selection, publisher_gateway


class PublisherGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.remote = self.root / "intake.git"
        self.git(self.root, "init", "--bare", str(self.remote))
        repository = self.root / "seed"
        repository.mkdir()
        self.git(repository, "init", "-b", "main")
        self.git(repository, "config", "user.name", "Release test")
        self.git(repository, "config", "user.email", "release-test@example.invalid")
        (repository / "README.md").write_text("intake\n", encoding="utf-8")
        self.git(repository, "add", "README.md")
        self.git(repository, "commit", "-m", "Create intake")
        self.commit = self.git(repository, "rev-parse", "HEAD")
        self.branch = intake_selection.PUBLICATION_LOCK_BRANCH
        self.git(
            repository,
            "push",
            str(self.remote),
            f"{self.commit}:refs/heads/{self.branch}",
        )

    def git(self, repository: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_intake_target_distinguishes_a_valid_ref_from_an_absent_ref(self) -> None:
        real_run = subprocess.run

        def local_ls_remote(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            redirected = [
                str(self.remote) if argument == "https://github.com/Balllvin/intake.git" else argument
                for argument in arguments
            ]
            return real_run(redirected, **kwargs)

        gateway = publisher_gateway.CommandGateway()
        with mock.patch.object(
            publisher_gateway.subprocess,
            "run",
            side_effect=local_ls_remote,
        ):
            self.assertEqual(gateway.intake_target("Balllvin/intake", self.branch), self.commit)
            self.assertIsNone(gateway.intake_target("Balllvin/intake", "missing"))

    def test_intake_target_rejects_malformed_or_failed_ref_reads(self) -> None:
        gateway = publisher_gateway.CommandGateway()
        malformed = subprocess.CompletedProcess(
            args=["git"],
            returncode=0,
            stdout=(
                f"not-a-commit\t{intake_selection.PUBLICATION_LOCK_REF}\n"
            ).encode(),
            stderr=b"",
        )
        with mock.patch.object(gateway, "_run", return_value=malformed):
            with self.assertRaisesRegex(publisher_gateway.GatewayError, "invalid identity"):
                gateway.intake_target("Balllvin/intake", self.branch)

        failed = subprocess.CompletedProcess(
            args=["git"],
            returncode=128,
            stdout=b"",
            stderr=b"transport failed\n",
        )
        with mock.patch.object(gateway, "_run", return_value=failed):
            with self.assertRaisesRegex(publisher_gateway.GatewayError, "transport failed"):
                gateway.intake_target("Balllvin/intake", self.branch)


if __name__ == "__main__":
    unittest.main()
