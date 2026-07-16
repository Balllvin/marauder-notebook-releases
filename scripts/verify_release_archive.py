#!/usr/bin/env python3

from __future__ import annotations

import argparse
import stat
import sys
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath


APP_ROOT = "Marauder Notebook.app"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ENTRY_COUNT = 4_096
MAX_ENTRY_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_SYMLINK_BYTES = 256
MAX_ENTRY_COMPRESSION_RATIO = 100
MAX_TOTAL_COMPRESSION_RATIO = 25
ALLOWED_COMPRESSION_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
EXPECTED_SYMLINKS = {
    f"{APP_ROOT}/Contents/Frameworks/Sparkle.framework/Autoupdate": (
        "Versions/Current/Autoupdate"
    ),
    f"{APP_ROOT}/Contents/Frameworks/Sparkle.framework/Headers": (
        "Versions/Current/Headers"
    ),
    f"{APP_ROOT}/Contents/Frameworks/Sparkle.framework/Modules": (
        "Versions/Current/Modules"
    ),
    f"{APP_ROOT}/Contents/Frameworks/Sparkle.framework/PrivateHeaders": (
        "Versions/Current/PrivateHeaders"
    ),
    f"{APP_ROOT}/Contents/Frameworks/Sparkle.framework/Resources": (
        "Versions/Current/Resources"
    ),
    f"{APP_ROOT}/Contents/Frameworks/Sparkle.framework/Sparkle": (
        "Versions/Current/Sparkle"
    ),
    f"{APP_ROOT}/Contents/Frameworks/Sparkle.framework/Updater.app": (
        "Versions/Current/Updater.app"
    ),
    f"{APP_ROOT}/Contents/Frameworks/Sparkle.framework/Versions/Current": "B",
    f"{APP_ROOT}/Contents/Frameworks/Sparkle.framework/XPCServices": (
        "Versions/Current/XPCServices"
    ),
}


class ArchiveVerificationError(ValueError):
    pass


def _safe_name(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise ArchiveVerificationError("archive contains an invalid entry name")
    if unicodedata.normalize("NFC", name) != name:
        raise ArchiveVerificationError("archive entry names must use canonical Unicode")
    if any(part in ("", ".", "..") for part in name.split("/")):
        raise ArchiveVerificationError("archive contains an unsafe entry path")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name:
        raise ArchiveVerificationError("archive contains an unsafe entry path")
    if path.parts[0] != APP_ROOT:
        raise ArchiveVerificationError("archive must contain only the Notebook app bundle")
    return path


def _check_local_header(archive: zipfile.ZipFile, entry: zipfile.ZipInfo) -> None:
    # Opening each member makes zipfile reconcile the central-directory name
    # with the local header and reject overlapped entries before ditto sees it.
    with archive.open(entry, "r") as source:
        source.read(1)


def _read_symlink(archive: zipfile.ZipFile, entry: zipfile.ZipInfo) -> bytes:
    if entry.file_size <= 0 or entry.file_size > MAX_SYMLINK_BYTES:
        raise ArchiveVerificationError("archive symlink target has an invalid size")
    with archive.open(entry, "r") as source:
        payload = source.read(MAX_SYMLINK_BYTES + 1)
    if len(payload) != entry.file_size:
        raise ArchiveVerificationError("archive symlink size does not match its contents")
    return payload


def verify_archive(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ArchiveVerificationError("release archive must be a regular file")
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ArchiveVerificationError("release archive has an invalid compressed size")

    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as error:
        raise ArchiveVerificationError(f"release archive is not a valid ZIP: {error}") from error

    with archive:
        entries = archive.infolist()
        if not entries or len(entries) > MAX_ENTRY_COUNT:
            raise ArchiveVerificationError("release archive has an invalid entry count")

        seen: set[str] = set()
        entry_types: dict[str, str] = {}
        expanded_bytes = 0
        compressed_bytes = 0
        actual_symlinks: dict[str, str] = {}
        for entry in entries:
            if "\x00" in entry.orig_filename or entry.orig_filename != entry.filename:
                raise ArchiveVerificationError("archive contains a NUL-truncated entry name")
            if entry.is_dir():
                if entry.filename.endswith("//"):
                    raise ArchiveVerificationError("archive directory path is not canonical")
                name = entry.filename[:-1]
            else:
                name = entry.filename
            archive_path = _safe_name(name)
            collision_key = unicodedata.normalize("NFC", name).casefold()
            if collision_key in seen:
                raise ArchiveVerificationError("archive contains duplicate or colliding entries")
            seen.add(collision_key)

            if entry.create_system != 3:
                raise ArchiveVerificationError("archive entries must preserve Unix file types")
            if entry.flag_bits & 0x1:
                raise ArchiveVerificationError("encrypted archive entries are not allowed")
            if entry.compress_type not in ALLOWED_COMPRESSION_METHODS:
                raise ArchiveVerificationError("archive uses an unsupported compression method")
            if entry.file_size < 0 or entry.file_size > MAX_ENTRY_BYTES:
                raise ArchiveVerificationError("archive entry has an invalid expanded size")
            if entry.compress_size < 0:
                raise ArchiveVerificationError("archive entry has an invalid compressed size")
            if entry.file_size and entry.compress_size == 0:
                raise ArchiveVerificationError("archive entry has an invalid compression ratio")
            if entry.compress_size and entry.file_size / entry.compress_size > MAX_ENTRY_COMPRESSION_RATIO:
                raise ArchiveVerificationError("archive entry exceeds the compression-ratio limit")

            mode = entry.external_attr >> 16
            if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                raise ArchiveVerificationError("archive entry has unsafe permission bits")
            is_directory = entry.is_dir()
            if is_directory:
                if not stat.S_ISDIR(mode):
                    raise ArchiveVerificationError("archive directory has an invalid file type")
                if stat.S_IMODE(mode) != 0o755:
                    raise ArchiveVerificationError("archive directory has unexpected permissions")
                entry_types[name] = "directory"
            elif not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
                raise ArchiveVerificationError("archive contains a non-file entry")
            elif stat.S_ISLNK(mode):
                if entry.compress_type != zipfile.ZIP_STORED:
                    raise ArchiveVerificationError("archive symlinks must not be compressed")
                if stat.S_IMODE(mode) != 0o755:
                    raise ArchiveVerificationError("archive symlink has unexpected permissions")
                entry_types[name] = "symlink"
            else:
                if stat.S_IMODE(mode) not in (0o644, 0o755):
                    raise ArchiveVerificationError("archive file has unexpected permissions")
                entry_types[name] = "regular"

            expanded_bytes += entry.file_size
            compressed_bytes += entry.compress_size
            if expanded_bytes > MAX_EXPANDED_BYTES:
                raise ArchiveVerificationError("release archive exceeds the expanded-size limit")

            if stat.S_ISLNK(mode):
                link_bytes = _read_symlink(archive, entry)
                try:
                    link_target = link_bytes.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ArchiveVerificationError("archive symlink target is not UTF-8") from error
                expected_target = EXPECTED_SYMLINKS.get(archive_path.as_posix())
                if expected_target is None or link_target != expected_target:
                    raise ArchiveVerificationError("archive contains an unexpected symlink")
                actual_symlinks[archive_path.as_posix()] = link_target
            else:
                _check_local_header(archive, entry)

        for name in entry_types:
            parts = PurePosixPath(name).parts
            for index in range(1, len(parts)):
                parent = PurePosixPath(*parts[:index]).as_posix()
                parent_type = entry_types.get(parent)
                if parent_type == "symlink":
                    raise ArchiveVerificationError("archive entry is nested below a symlink")
                if parent_type is not None and parent_type != "directory":
                    raise ArchiveVerificationError("archive entry parent is not a directory")

        if compressed_bytes == 0 or expanded_bytes / compressed_bytes > MAX_TOTAL_COMPRESSION_RATIO:
            raise ArchiveVerificationError("release archive exceeds the total compression-ratio limit")
        if actual_symlinks != EXPECTED_SYMLINKS:
            raise ArchiveVerificationError("release archive has an incomplete framework symlink layout")
        if entry_types.get(APP_ROOT) != "directory":
            raise ArchiveVerificationError("release archive is missing its app root directory")
        required = {
            f"{APP_ROOT}/Contents/Info.plist",
            f"{APP_ROOT}/Contents/MacOS/Marauder Notebook",
            f"{APP_ROOT}/Contents/Resources/AppIcon.icns",
        }
        if any(entry_types.get(name) != "regular" for name in required):
            raise ArchiveVerificationError("release archive is missing required app files")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the Notebook ZIP before extracting untrusted archive paths"
    )
    parser.add_argument("--archive", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        verify_archive(arguments.archive)
    except (ArchiveVerificationError, OSError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
