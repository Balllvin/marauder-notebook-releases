from __future__ import annotations

import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts import verify_release_archive


class VerifyReleaseArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    @staticmethod
    def _entry(name: str, mode: int) -> zipfile.ZipInfo:
        entry = zipfile.ZipInfo(name)
        entry.create_system = 3
        entry.external_attr = mode << 16
        entry.compress_type = zipfile.ZIP_STORED
        return entry

    def make_archive(
        self,
        *,
        extra: list[tuple[str, int, bytes]] | None = None,
        omit_symlink: str | None = None,
        required_modes: dict[str, int] | None = None,
    ) -> Path:
        archive_path = self.root / "Marauder-Notebook-1.2.3-42-universal.zip"
        root = verify_release_archive.APP_ROOT
        entries: list[tuple[str, int, bytes]] = [
            (f"{root}/", stat.S_IFDIR | 0o755, b""),
            (f"{root}/Contents/Info.plist", stat.S_IFREG | 0o644, b"plist"),
            (
                f"{root}/Contents/MacOS/Marauder Notebook",
                stat.S_IFREG | 0o755,
                bytes(range(256)),
            ),
            (
                f"{root}/Contents/Resources/AppIcon.icns",
                stat.S_IFREG | 0o644,
                b"icns\x00\x00\x00\x08",
            ),
        ]
        entries.extend(
            (name, stat.S_IFLNK | 0o755, target.encode("utf-8"))
            for name, target in verify_release_archive.EXPECTED_SYMLINKS.items()
            if name != omit_symlink
        )
        entries.extend(extra or [])
        required_modes = required_modes or {}
        with zipfile.ZipFile(archive_path, "w") as archive:
            for name, mode, payload in entries:
                mode = required_modes.get(name, mode)
                archive.writestr(self._entry(name, mode), payload)
        return archive_path

    def test_accepts_exact_app_root_and_sparkle_symlinks(self) -> None:
        verify_release_archive.verify_archive(self.make_archive())

    def test_rejects_appledouble_traversal_absolute_and_backslash_paths(self) -> None:
        cases = (
            "__MACOSX/._Marauder Notebook.app",
            f"{verify_release_archive.APP_ROOT}/../outside",
            f"{verify_release_archive.APP_ROOT}/Contents/./outside",
            f"{verify_release_archive.APP_ROOT}/Contents//outside",
            "/tmp/outside",
            f"{verify_release_archive.APP_ROOT}\\Contents\\outside",
        )
        for index, name in enumerate(cases):
            with self.subTest(name=name):
                archive = self.make_archive(
                    extra=[(name, stat.S_IFREG | 0o644, b"fixture")]
                )
                with self.assertRaises(verify_release_archive.ArchiveVerificationError):
                    verify_release_archive.verify_archive(archive)
                archive.rename(self.root / f"rejected-{index}.zip")

    def test_rejects_duplicate_case_collisions_and_encryption(self) -> None:
        root = verify_release_archive.APP_ROOT
        archive = self.make_archive(
            extra=[
                (
                    f"{root}/contents/info.plist",
                    stat.S_IFREG | 0o644,
                    b"collision",
                )
            ]
        )
        with self.assertRaisesRegex(
            verify_release_archive.ArchiveVerificationError,
            "duplicate or colliding",
        ):
            verify_release_archive.verify_archive(archive)

        archive = self.make_archive()
        with zipfile.ZipFile(archive, "a") as writer:
            entry = self._entry(f"{root}/Contents/encrypted", stat.S_IFREG | 0o644)
            entry.flag_bits |= 0x1
            writer.writestr(entry, b"encrypted")
        # Python's writer clears unsupported encryption flags. Exercise the
        # policy by mutating the central-directory bit explicitly.
        payload = bytearray(archive.read_bytes())
        central = payload.index(b"PK\x01\x02")
        flags = int.from_bytes(payload[central + 8 : central + 10], "little") | 0x1
        payload[central + 8 : central + 10] = flags.to_bytes(2, "little")
        archive.write_bytes(payload)
        with self.assertRaises(verify_release_archive.ArchiveVerificationError):
            verify_release_archive.verify_archive(archive)

    def test_rejects_missing_or_changed_framework_symlink(self) -> None:
        missing = next(iter(verify_release_archive.EXPECTED_SYMLINKS))
        with self.assertRaisesRegex(
            verify_release_archive.ArchiveVerificationError,
            "incomplete framework symlink",
        ):
            verify_release_archive.verify_archive(
                self.make_archive(omit_symlink=missing)
            )

        changed = self.make_archive(
            extra=[
                (
                    f"{verify_release_archive.APP_ROOT}/Contents/Injected",
                    stat.S_IFLNK | 0o755,
                    b"../../outside",
                )
            ]
        )
        with self.assertRaisesRegex(
            verify_release_archive.ArchiveVerificationError,
            "unexpected symlink",
        ):
            verify_release_archive.verify_archive(changed)

    def test_rejects_symlink_descendants_and_non_directory_parents(self) -> None:
        root = verify_release_archive.APP_ROOT
        descendant = self.make_archive(
            extra=[
                (
                    f"{root}/Contents/Frameworks/Sparkle.framework/Versions/Current/Injected",
                    stat.S_IFREG | 0o644,
                    b"fixture",
                )
            ]
        )
        with self.assertRaisesRegex(
            verify_release_archive.ArchiveVerificationError,
            "nested below a symlink",
        ):
            verify_release_archive.verify_archive(descendant)

        parent = f"{root}/Contents/NotDirectory"
        invalid_parent = self.make_archive(
            extra=[
                (parent, stat.S_IFREG | 0o644, b"parent"),
                (f"{parent}/child", stat.S_IFREG | 0o644, b"child"),
            ]
        )
        with self.assertRaisesRegex(
            verify_release_archive.ArchiveVerificationError,
            "parent is not a directory",
        ):
            verify_release_archive.verify_archive(invalid_parent)

    def test_rejects_oversized_symlinks_unsafe_modes_and_wrong_required_type(self) -> None:
        root = verify_release_archive.APP_ROOT
        oversized_link = self.make_archive(
            extra=[
                (
                    f"{root}/Contents/OversizedLink",
                    stat.S_IFLNK | 0o755,
                    b"x" * (verify_release_archive.MAX_SYMLINK_BYTES + 1),
                )
            ]
        )
        with self.assertRaisesRegex(
            verify_release_archive.ArchiveVerificationError,
            "symlink target has an invalid size",
        ):
            verify_release_archive.verify_archive(oversized_link)

        unsafe_mode = self.make_archive(
            extra=[
                (f"{root}/Contents/Writable", stat.S_IFREG | 0o777, b"fixture")
            ]
        )
        with self.assertRaisesRegex(
            verify_release_archive.ArchiveVerificationError,
            "unexpected permissions",
        ):
            verify_release_archive.verify_archive(unsafe_mode)

        info = f"{root}/Contents/Info.plist"
        wrong_required_type = self.make_archive(
            required_modes={info: stat.S_IFLNK | 0o755}
        )
        with self.assertRaises(verify_release_archive.ArchiveVerificationError):
            verify_release_archive.verify_archive(wrong_required_type)

    def test_enforces_archive_entry_and_expanded_size_limits(self) -> None:
        archive = self.make_archive()
        for constant in (
            "MAX_ARCHIVE_BYTES",
            "MAX_ENTRY_COUNT",
            "MAX_ENTRY_BYTES",
            "MAX_EXPANDED_BYTES",
        ):
            with self.subTest(constant=constant):
                with mock.patch.object(verify_release_archive, constant, 1):
                    with self.assertRaises(
                        verify_release_archive.ArchiveVerificationError
                    ):
                        verify_release_archive.verify_archive(archive)

    def test_rejects_nul_truncated_entry_names(self) -> None:
        root = verify_release_archive.APP_ROOT
        archive = self.make_archive(
            extra=[(f"{root}/Contents/null0", stat.S_IFREG | 0o644, b"fixture")]
        )
        payload = archive.read_bytes()
        payload = payload.replace(b"Contents/null0", b"Contents/null\x00")
        archive.write_bytes(payload)
        with self.assertRaisesRegex(
            verify_release_archive.ArchiveVerificationError,
            "NUL-truncated",
        ):
            verify_release_archive.verify_archive(archive)

    def test_rejects_zip_bomb_ratios_and_unsupported_file_types(self) -> None:
        root = verify_release_archive.APP_ROOT
        archive = self.root / "bomb.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as writer:
            for name, target in verify_release_archive.EXPECTED_SYMLINKS.items():
                writer.writestr(self._entry(name, stat.S_IFLNK | 0o755), target)
            writer.writestr(
                self._entry(f"{root}/Contents/Info.plist", stat.S_IFREG | 0o644),
                b"A" * 1024 * 1024,
                compress_type=zipfile.ZIP_DEFLATED,
            )
            writer.writestr(
                self._entry(f"{root}/Contents/MacOS/Marauder Notebook", stat.S_IFREG | 0o755),
                b"main",
            )
            writer.writestr(
                self._entry(f"{root}/Contents/Resources/AppIcon.icns", stat.S_IFREG | 0o644),
                b"icns\x00\x00\x00\x08",
            )
        with self.assertRaisesRegex(
            verify_release_archive.ArchiveVerificationError,
            "compression-ratio",
        ):
            verify_release_archive.verify_archive(archive)

        fifo = self.make_archive(
            extra=[(f"{root}/Contents/fifo", stat.S_IFIFO | 0o644, b"")]
        )
        with self.assertRaisesRegex(
            verify_release_archive.ArchiveVerificationError,
            "non-file entry",
        ):
            verify_release_archive.verify_archive(fifo)


if __name__ == "__main__":
    unittest.main()
