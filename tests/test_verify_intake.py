from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import verify_intake


class VerifyIntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = "/opt/homebrew/opt/openssl@3/bin/openssl"
        if not Path(cls.openssl).is_file():
            cls.openssl = shutil.which("openssl") or ""
        if not cls.openssl:
            raise unittest.SkipTest("OpenSSL is required for the release-signature tests")

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.private_key = self.root / "private.pem"
        self.public_der = self.root / "public.der"
        self.run_openssl("genpkey", "-algorithm", "ED25519", "-out", str(self.private_key))
        self.run_openssl("pkey", "-in", str(self.private_key), "-pubout", "-outform", "DER", "-out", str(self.public_der))
        public_der = self.public_der.read_bytes()
        self.public_key = base64.b64encode(public_der[-32:]).decode("ascii")

    def run_openssl(self, *arguments: str) -> None:
        result = subprocess.run([self.openssl, *arguments], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def sign(self, path: Path) -> str:
        signature = self.root / f"{path.name}.signature"
        self.run_openssl(
            "pkeyutl",
            "-sign",
            "-inkey",
            str(self.private_key),
            "-rawin",
            "-in",
            str(path),
            "-out",
            str(signature),
        )
        return base64.b64encode(signature.read_bytes()).decode("ascii")

    def make_intake(self, *, version: str = "1.2.3", build_number: str = "42") -> tuple[Path, str]:
        intake = self.root / "intake"
        intake.mkdir()
        source_commit = "a" * 40
        tag = f"notebook-v{version}-{build_number}"
        archive_name = f"Marauder-Notebook-{version}-{build_number}-universal.zip"
        archive = intake / archive_name
        archive.write_bytes(b"signed universal archive")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (intake / f"{archive_name}.sha256").write_text(f"{digest}  {archive_name}\n", encoding="utf-8")
        archive_signature = self.sign(archive)
        archive_url = f"{verify_intake.DOWNLOAD_URL_PREFIX}/{tag}/{archive_name}"
        feed_content = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            f'<rss xmlns:sparkle="{verify_intake.SPARKLE_NAMESPACE}" version="2.0"><channel><item>'
            f'<enclosure url="{archive_url}" length="{archive.stat().st_size}" '
            f'sparkle:shortVersionString="{version}" sparkle:version="{build_number}" '
            f'sparkle:edSignature="{archive_signature}" />'
            '</item></channel></rss>\n'
        ).encode("utf-8")
        unsigned_feed = self.root / "unsigned-appcast.xml"
        unsigned_feed.write_bytes(feed_content)
        feed_signature = self.sign(unsigned_feed)
        (intake / "appcast.xml").write_bytes(
            feed_content
            + f"<!-- sparkle-signatures:\nedSignature: {feed_signature}\nlength: {len(feed_content)}\n-->\n".encode("ascii")
        )
        metadata = {
            "schema": 1,
            "product": verify_intake.PRODUCT_NAME,
            "version": version,
            "build_number": build_number,
            "tag": tag,
            "architecture": "universal",
            "source": {"repository": verify_intake.SOURCE_REPOSITORY, "commit": source_commit},
            "asset": {
                "name": archive_name,
                "url": archive_url,
                "length": archive.stat().st_size,
                "sha256": digest,
                "sparkle_ed_signature": archive_signature,
            },
            "checksum": {
                "name": f"{archive_name}.sha256",
                "url": f"{verify_intake.DOWNLOAD_URL_PREFIX}/{tag}/{archive_name}.sha256",
            },
            "appcast": {"name": "appcast.xml", "url": verify_intake.FEED_URL, "enclosure_url": archive_url},
        }
        self.write_signed_metadata(intake / "notebook-release.json", metadata)
        trust = {
            "schema": 1,
            "enabled": True,
            "repository": verify_intake.RELEASE_REPOSITORY,
            "feed_url": verify_intake.FEED_URL,
            "download_url_prefix": verify_intake.DOWNLOAD_URL_PREFIX,
            "release_metadata_url": verify_intake.METADATA_URL,
            "public_ed_key": self.public_key,
        }
        (intake / "update-feed.json").write_text(json.dumps(trust), encoding="utf-8")
        return intake, f"publication/{version}-{build_number}-{source_commit}"

    def write_signed_metadata(self, path: Path, metadata: dict[str, object]) -> None:
        unsigned = dict(metadata)
        unsigned.pop("provenance", None)
        canonical = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        statement = self.root / "release-provenance.json"
        statement.write_bytes(canonical)
        metadata["provenance"] = {
            "algorithm": "ed25519",
            "sparkle_ed_signature": self.sign(statement),
        }
        path.write_text(json.dumps(metadata), encoding="utf-8")

    def validate(self, intake: Path, branch: str) -> dict[str, str]:
        return verify_intake.validate_intake(
            intake,
            branch,
            public_key=self.public_key,
            openssl=self.openssl,
        )

    def test_accepts_exact_signed_release_intake(self) -> None:
        intake, branch = self.make_intake()
        result = self.validate(intake, branch)
        self.assertEqual(result["tag"], "notebook-v1.2.3-42")
        self.assertEqual(result["source_commit"], "a" * 40)

    def test_rejects_archive_changed_after_signing(self) -> None:
        intake, branch = self.make_intake()
        archive = next(intake.glob("*.zip"))
        archive.write_bytes(b"unsigned universal archive")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksum = next(intake.glob("*.sha256"))
        checksum.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
        metadata_path = intake / "notebook-release.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["asset"]["sha256"] = digest
        metadata["asset"]["length"] = archive.stat().st_size
        self.write_signed_metadata(metadata_path, metadata)
        appcast = intake / "appcast.xml"
        appcast.write_bytes(
            appcast.read_bytes().replace(b'length="24"', f'length="{archive.stat().st_size}"'.encode("ascii"), 1)
        )
        with self.assertRaisesRegex(verify_intake.IntakeError, "Ed25519 signature verification"):
            self.validate(intake, branch)

    def test_rejects_feed_changed_after_signing(self) -> None:
        intake, branch = self.make_intake()
        appcast = intake / "appcast.xml"
        appcast.write_bytes(appcast.read_bytes().replace(b'version="2.0"', b'version="2.1"', 1))
        with self.assertRaisesRegex(verify_intake.IntakeError, "Ed25519 signature verification"):
            self.validate(intake, branch)

    def test_rejects_wrong_publication_branch(self) -> None:
        intake, _ = self.make_intake()
        with self.assertRaisesRegex(verify_intake.IntakeError, "publication branch"):
            self.validate(intake, "publication/other")

    def test_rejects_source_commit_relabeling_without_provenance_key(self) -> None:
        intake, _ = self.make_intake()
        metadata_path = intake / "notebook-release.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["source"]["commit"] = "b" * 40
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        relabeled_branch = f"publication/1.2.3-42-{'b' * 40}"
        with self.assertRaisesRegex(verify_intake.IntakeError, "Ed25519 signature verification"):
            self.validate(intake, relabeled_branch)

    def test_rejects_extra_file_and_symbolic_link(self) -> None:
        intake, branch = self.make_intake()
        (intake / "notes.txt").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(verify_intake.IntakeError, "exactly the five"):
            self.validate(intake, branch)
        (intake / "notes.txt").unlink()
        checksum = next(intake.glob("*.sha256"))
        checksum.unlink()
        checksum.symlink_to(next(intake.glob("*.zip")))
        with self.assertRaises(verify_intake.IntakeError):
            self.validate(intake, branch)

    def test_rejects_duplicate_metadata_key(self) -> None:
        intake, branch = self.make_intake()
        metadata = intake / "notebook-release.json"
        payload = metadata.read_text(encoding="utf-8")
        metadata.write_text(payload.replace('{"schema": 1,', '{"schema": 1, "schema": 1,', 1), encoding="utf-8")
        with self.assertRaisesRegex(verify_intake.IntakeError, "duplicate key"):
            self.validate(intake, branch)

    def test_rejects_changed_trust_boundary(self) -> None:
        intake, branch = self.make_intake()
        trust_path = intake / "update-feed.json"
        trust = json.loads(trust_path.read_text(encoding="utf-8"))
        trust["feed_url"] = "https://example.test/appcast.xml"
        trust_path.write_text(json.dumps(trust), encoding="utf-8")
        with self.assertRaisesRegex(verify_intake.IntakeError, "trust boundary"):
            self.validate(intake, branch)

    def test_requires_strictly_newer_version_and_build(self) -> None:
        intake, _ = self.make_intake()
        releases = self.root / "releases.json"
        releases.write_text(
            json.dumps([[{"tag_name": "notebook-v1.2.2-41", "draft": False, "prerelease": False}]]),
            encoding="utf-8",
        )
        verify_intake.assert_newer(intake / "notebook-release.json", releases)
        releases.write_text(
            json.dumps([[{"tag_name": "notebook-v1.2.3-41", "draft": False, "prerelease": False}]]),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(verify_intake.IntakeError, "strictly newer"):
            verify_intake.assert_newer(intake / "notebook-release.json", releases)
        releases.write_text(
            json.dumps([[{"tag_name": "notebook-v1.2.2-42", "draft": False, "prerelease": False}]]),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(verify_intake.IntakeError, "strictly greater"):
            verify_intake.assert_newer(intake / "notebook-release.json", releases)


if __name__ == "__main__":
    unittest.main()
