from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import prepare_intake


class PrepareIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def git(self, repository: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def make_repository(self, *, extra_path: str | None = None, symlink_checksum: bool = False) -> tuple[Path, str, str]:
        repository = self.root / "repository"
        repository.mkdir()
        self.git(repository, "init", "-b", "main")
        self.git(repository, "config", "user.name", "Release test")
        self.git(repository, "config", "user.email", "release-test@example.invalid")
        (repository / "README.md").write_text("trusted intake root\n", encoding="utf-8")
        self.git(repository, "add", "README.md")
        self.git(repository, "commit", "-m", "Initialize trusted intake")
        main_commit = self.git(repository, "rev-parse", "HEAD")
        self.git(repository, "update-ref", "refs/remotes/origin/main", main_commit)
        self.git(repository, "switch", "-c", "publication")

        version = "1.2.3"
        build = "42"
        source_commit = "a" * 40
        branch = f"publication/{version}-{build}-{source_commit}"
        archive = f"Marauder-Notebook-{version}-{build}-universal.zip"
        intake = repository / "intake"
        intake.mkdir()
        (intake / archive).write_bytes(b"archive")
        (intake / f"{archive}.sha256").write_text("checksum\n", encoding="utf-8")
        (intake / "appcast.xml").write_text("appcast\n", encoding="utf-8")
        (intake / "notebook-release.json").write_text(
            json.dumps({"asset": {"name": archive}}),
            encoding="utf-8",
        )
        (intake / "update-feed.json").write_text("{}\n", encoding="utf-8")
        if symlink_checksum:
            checksum = intake / f"{archive}.sha256"
            checksum.unlink()
            checksum.symlink_to(archive)
        if extra_path is not None:
            path = repository / extra_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("untrusted workflow\n", encoding="utf-8")
        self.git(repository, "add", "--all")
        self.git(repository, "commit", "-m", "Stage release intake")
        return repository, self.git(repository, "rev-parse", "HEAD"), branch

    def test_extracts_only_exact_regular_intake_blobs(self) -> None:
        repository, commit, branch = self.make_repository()
        output = self.root / "output"
        expected_result = {
            "version": "1.2.3",
            "build_number": "42",
            "tag": "notebook-v1.2.3-42",
            "archive": "Marauder-Notebook-1.2.3-42-universal.zip",
            "source_commit": "a" * 40,
            "branch": branch,
        }
        with mock.patch.object(
            prepare_intake.verify_intake,
            "validate_intake",
            return_value=expected_result,
        ) as validator:
            result = prepare_intake.prepare_intake(
                repository,
                commit,
                branch,
                output,
                openssl="openssl",
            )
        validator.assert_called_once_with(output, branch, openssl="openssl")
        self.assertEqual(result["intake_commit"], commit)
        self.assertEqual(
            {path.name for path in output.iterdir()},
            {
                "Marauder-Notebook-1.2.3-42-universal.zip",
                "Marauder-Notebook-1.2.3-42-universal.zip.sha256",
                "appcast.xml",
                "notebook-release.json",
                "update-feed.json",
            },
        )

    def test_rejects_commit_that_also_adds_workflow_code(self) -> None:
        repository, commit, branch = self.make_repository(
            extra_path=".github/workflows/pwn.yml"
        )
        with self.assertRaisesRegex(prepare_intake.PreparationError, "exactly the five"):
            prepare_intake.prepare_intake(
                repository,
                commit,
                branch,
                self.root / "output",
                openssl="openssl",
            )

    def test_rejects_symbolic_link_intake_entry(self) -> None:
        repository, commit, branch = self.make_repository(symlink_checksum=True)
        with self.assertRaisesRegex(prepare_intake.PreparationError, "ordinary non-executable blobs"):
            prepare_intake.prepare_intake(
                repository,
                commit,
                branch,
                self.root / "output",
                openssl="openssl",
            )

    def test_rejects_unlocked_publication_intake(self) -> None:
        refs = self.root / "refs.json"
        releases = self.root / "releases.json"
        refs.write_text(
            json.dumps(
                [[
                    {
                        "ref": f"refs/heads/publication/1.3.0-50-{'c' * 40}",
                        "object": {"type": "commit", "sha": "d" * 40},
                    },
                    {
                        "ref": f"refs/heads/publication/1.2.0-40-{'a' * 40}",
                        "object": {"type": "commit", "sha": "b" * 40},
                    },
                ]]
            ),
            encoding="utf-8",
        )
        releases.write_text(
            json.dumps([[{"tag_name": "notebook-v1.2.0-40", "draft": False}]]),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(prepare_intake.PreparationError, "required lock"):
            prepare_intake.select_pending_intake(refs, releases)

    def test_publication_lock_selects_only_its_matching_candidate(self) -> None:
        refs = self.root / "refs.json"
        releases = self.root / "releases.json"
        locked_commit = "d" * 40
        refs.write_text(
            json.dumps(
                [
                    {
                        "ref": f"refs/heads/publication/1.2.0-40-{'a' * 40}",
                        "object": {"type": "commit", "sha": "b" * 40},
                    },
                    {
                        "ref": f"refs/heads/publication/1.3.0-50-{'c' * 40}",
                        "object": {"type": "commit", "sha": locked_commit},
                    },
                    {
                        "ref": prepare_intake.PUBLICATION_LOCK_REF,
                        "object": {"type": "commit", "sha": locked_commit},
                    },
                ]
            ),
            encoding="utf-8",
        )
        releases.write_text("[]\n", encoding="utf-8")
        result = prepare_intake.select_pending_intake(refs, releases)
        self.assertEqual(result["branch"], f"publication/1.3.0-50-{'c' * 40}")
        self.assertEqual(result["commit"], locked_commit)
        self.assertEqual(result["candidates"], [{"branch": result["branch"], "commit": locked_commit}])
        self.assertEqual(result["publication_lock_commit"], locked_commit)
        self.assertEqual(result["ignored_ref_count"], 1)

    def test_discovery_reads_publication_branches_and_lock_from_one_git_snapshot(self) -> None:
        remote = self.root / "intake.git"
        self.git(self.root, "init", "--bare", str(remote))
        repository = self.root / "seed"
        repository.mkdir()
        self.git(repository, "init", "-b", "main")
        self.git(repository, "config", "user.name", "Release test")
        self.git(repository, "config", "user.email", "release-test@example.invalid")
        (repository / "README.md").write_text("intake\n", encoding="utf-8")
        self.git(repository, "add", "README.md")
        self.git(repository, "commit", "-m", "Create intake")
        commit = self.git(repository, "rev-parse", "HEAD")
        branch = f"publication/1.2.3-42-{'a' * 40}"
        self.git(
            repository,
            "push",
            str(remote),
            f"{commit}:refs/heads/{branch}",
            f"{commit}:{prepare_intake.PUBLICATION_LOCK_REF}",
        )
        releases = self.root / "releases.json"
        releases.write_text("[]\n", encoding="utf-8")

        real_run = subprocess.run
        calls: list[list[str]] = []

        def local_ls_remote(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            calls.append(arguments)
            redirected = list(arguments)
            redirected[3] = str(remote)
            return real_run(redirected, **kwargs)

        with mock.patch.object(
            prepare_intake.subprocess,
            "run",
            side_effect=local_ls_remote,
        ):
            result = prepare_intake.discover_pending_intake(
                "https://github.com/example/intake.git",
                releases,
            )

        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0][4:],
            ["refs/heads/publication/*", prepare_intake.PUBLICATION_LOCK_REF],
        )
        self.assertEqual(result["branch"], branch)
        self.assertEqual(result["commit"], commit)
        self.assertEqual(result["publication_lock_commit"], commit)

    def test_published_locked_candidate_is_an_idle_success(self) -> None:
        refs = self.root / "refs.json"
        releases = self.root / "releases.json"
        locked_commit = "b" * 40
        refs.write_text(
            json.dumps(
                [
                    {
                        "ref": f"refs/heads/publication/1.2.0-40-{'a' * 40}",
                        "object": {"type": "commit", "sha": locked_commit},
                    },
                    {
                        "ref": prepare_intake.PUBLICATION_LOCK_REF,
                        "object": {"type": "commit", "sha": locked_commit},
                    },
                ]
            ),
            encoding="utf-8",
        )
        releases.write_text(
            json.dumps([{"tag_name": "notebook-v1.2.0-40", "draft": False}]),
            encoding="utf-8",
        )
        result = prepare_intake.select_pending_intake(refs, releases)
        self.assertFalse(result["available"])
        self.assertEqual(result["publication_lock_commit"], locked_commit)

    def test_rejects_missing_malformed_or_ambiguous_locked_candidate(self) -> None:
        releases = self.root / "releases.json"
        releases.write_text("[]\n", encoding="utf-8")
        cases = (
            [
                {
                    "ref": prepare_intake.PUBLICATION_LOCK_REF,
                    "object": {"type": "blob", "sha": "a" * 40},
                }
            ],
            [
                {
                    "ref": prepare_intake.PUBLICATION_LOCK_REF,
                    "object": {"type": "commit", "sha": "a" * 40},
                }
            ],
            [
                {
                    "ref": f"refs/heads/publication/1.2.0-40-{'a' * 40}",
                    "object": {"type": "commit", "sha": "b" * 40},
                },
                {
                    "ref": f"refs/heads/publication/1.3.0-50-{'c' * 40}",
                    "object": {"type": "commit", "sha": "b" * 40},
                },
                {
                    "ref": prepare_intake.PUBLICATION_LOCK_REF,
                    "object": {"type": "commit", "sha": "b" * 40},
                },
            ],
        )
        for index, payload in enumerate(cases):
            with self.subTest(index=index):
                refs = self.root / f"refs-{index}.json"
                refs.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(prepare_intake.PreparationError):
                    prepare_intake.select_pending_intake(refs, releases)

    def test_quarantines_duplicate_identity_without_starving_a_valid_candidate(self) -> None:
        refs = self.root / "refs.json"
        releases = self.root / "releases.json"
        refs.write_text(
            json.dumps(
                [[
                    {
                        "ref": f"refs/heads/publication/1.2.3-42-{'a' * 40}",
                        "object": {"type": "commit", "sha": "b" * 40},
                    },
                    {
                        "ref": f"refs/heads/publication/1.2.3-42-{'c' * 40}",
                        "object": {"type": "commit", "sha": "d" * 40},
                    },
                    {
                        "ref": f"refs/heads/publication/1.3.0-43-{'e' * 40}",
                        "object": {"type": "commit", "sha": "f" * 40},
                    },
                    {
                        "ref": prepare_intake.PUBLICATION_LOCK_REF,
                        "object": {"type": "commit", "sha": "f" * 40},
                    },
                ]]
            ),
            encoding="utf-8",
        )
        releases.write_text("[]\n", encoding="utf-8")
        result = prepare_intake.select_pending_intake(refs, releases)
        self.assertEqual(result["branch"], f"publication/1.3.0-43-{'e' * 40}")
        self.assertEqual(result["ignored_ref_count"], 2)

    def test_stale_and_malformed_refs_cannot_starve_a_newer_candidate(self) -> None:
        refs = self.root / "refs.json"
        releases = self.root / "releases.json"
        refs.write_text(
            json.dumps(
                [[
                    {
                        "ref": f"refs/heads/publication/1.9.9-201-{'a' * 40}",
                        "object": {"type": "commit", "sha": "b" * 40},
                    },
                    {
                        "ref": "refs/heads/publication/not-a-release",
                        "object": {"type": "commit", "sha": "c" * 40},
                    },
                    {"malformed": True},
                    {
                        "ref": f"refs/heads/publication/2.1.0-202-{'d' * 40}",
                        "object": {"type": "commit", "sha": "e" * 40},
                    },
                    {
                        "ref": prepare_intake.PUBLICATION_LOCK_REF,
                        "object": {"type": "commit", "sha": "e" * 40},
                    },
                ]]
            ),
            encoding="utf-8",
        )
        releases.write_text(
            json.dumps([[{"tag_name": "notebook-v2.0.0-200", "draft": False}]]),
            encoding="utf-8",
        )
        result = prepare_intake.select_pending_intake(refs, releases)
        self.assertEqual(result["branch"], f"publication/2.1.0-202-{'d' * 40}")
        self.assertEqual(result["ignored_ref_count"], 2)

    def test_rejects_non_notebook_or_prerelease_publication_history(self) -> None:
        refs = self.root / "refs.json"
        releases = self.root / "releases.json"
        refs.write_text("[]\n", encoding="utf-8")
        releases.write_text(
            json.dumps([{"tag_name": "other-product", "draft": False, "prerelease": False}]),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(prepare_intake.PreparationError, "non-Notebook"):
            prepare_intake.select_pending_intake(refs, releases)
        releases.write_text(
            json.dumps([{"tag_name": "notebook-v1.2.3-42", "draft": False, "prerelease": True}]),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(prepare_intake.PreparationError, "prereleases"):
            prepare_intake.select_pending_intake(refs, releases)

    def test_prepares_only_the_locked_candidate(self) -> None:
        selection = self.root / "selection.json"
        later_branch = f"publication/1.3.0-43-{'c' * 40}"
        selection.write_text(
            json.dumps(
                {
                    "available": True,
                    "publication_lock_commit": "d" * 40,
                    "candidates": [
                        {"branch": later_branch, "commit": "d" * 40},
                    ],
                }
            ),
            encoding="utf-8",
        )

        def fake_prepare(
            _repository: Path,
            commit: str,
            branch: str,
            output: Path,
            **_arguments: object,
        ) -> dict[str, object]:
            output.mkdir()
            (output / "verified").write_text(commit, encoding="utf-8")
            return {"branch": branch, "intake_commit": commit}

        output = self.root / "verified-intake"
        with mock.patch.object(prepare_intake, "prepare_intake", side_effect=fake_prepare):
            result = prepare_intake.prepare_pending_intake(
                self.root,
                selection,
                output,
                openssl="openssl",
            )
        self.assertEqual(result["branch"], later_branch)
        self.assertEqual(result["invalid_candidate_count"], 0)
        self.assertEqual(result["invalid_candidates"], [])
        self.assertEqual((output / "verified").read_text(encoding="utf-8"), "d" * 40)

    def test_all_invalid_pending_candidates_fail_loudly(self) -> None:
        selection = self.root / "selection.json"
        selection.write_text(
            json.dumps(
                {
                    "available": True,
                    "publication_lock_commit": "b" * 40,
                    "candidates": [
                        {
                            "branch": f"publication/1.2.3-42-{'a' * 40}",
                            "commit": "b" * 40,
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.object(
            prepare_intake,
            "prepare_intake",
            side_effect=prepare_intake.PreparationError("rejected"),
        ):
            with self.assertRaisesRegex(
                prepare_intake.PreparationError,
                "all 1 pending intake candidates failed verification",
            ):
                prepare_intake.prepare_pending_intake(
                    self.root,
                    selection,
                    self.root / "verified-intake",
                    openssl="openssl",
                )

    def test_prepare_rejects_a_selection_that_does_not_match_its_lock(self) -> None:
        selection = self.root / "selection.json"
        selection.write_text(
            json.dumps(
                {
                    "available": True,
                    "publication_lock_commit": "a" * 40,
                    "candidates": [
                        {
                            "branch": f"publication/1.2.3-42-{'b' * 40}",
                            "commit": "c" * 40,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            prepare_intake.PreparationError,
            "different candidate",
        ):
            prepare_intake.prepare_pending_intake(
                self.root,
                selection,
                self.root / "verified-intake",
                openssl="openssl",
            )

    def test_no_pending_candidates_remains_an_idle_success(self) -> None:
        selection = self.root / "selection.json"
        selection.write_text(
            json.dumps(
                {
                    "available": False,
                    "candidates": [],
                    "publication_lock_commit": "none",
                }
            ),
            encoding="utf-8",
        )
        result = prepare_intake.prepare_pending_intake(
            self.root,
            selection,
            self.root / "verified-intake",
            openssl="openssl",
        )
        self.assertEqual(
            result,
            {
                "available": False,
                "invalid_candidate_count": 0,
                "invalid_candidates": [],
                "publication_lock_commit": "none",
            },
        )
        self.assertFalse((self.root / "verified-intake").exists())


if __name__ == "__main__":
    unittest.main()
