from __future__ import annotations

import hashlib
import plistlib
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from scripts import macho_contract, verify_app_bundle


class VerifyAppBundleMachOTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def test_requires_a_complete_regular_icns_icon(self) -> None:
        app = self.root / "Marauder Notebook.app"
        icon = app / "Contents" / "Resources" / verify_app_bundle.ICON_FILE_NAME
        icon.parent.mkdir(parents=True)
        payload = b"icns" + (12).to_bytes(4, "big") + b"test"
        icon.write_bytes(payload)
        with mock.patch.object(
            verify_app_bundle,
            "ICON_SHA256",
            hashlib.sha256(payload).hexdigest(),
        ):
            verify_app_bundle.verify_icon(app)

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "trusted product icon",
        ):
            verify_app_bundle.verify_icon(app)

        invalid_payloads = (
            b"short",
            b"nope" + (12).to_bytes(4, "big") + b"test",
            b"icns" + (13).to_bytes(4, "big") + b"test",
        )
        for invalid in invalid_payloads:
            icon.write_bytes(invalid)
            with self.subTest(payload=invalid):
                with self.assertRaises(verify_app_bundle.BundleVerificationError):
                    verify_app_bundle.verify_icon(app)

        with icon.open("wb") as icon_file:
            icon_file.seek(verify_app_bundle.MAX_ICON_BYTES)
            icon_file.write(b"\0")
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "invalid size",
        ):
            verify_app_bundle.verify_icon(app)

        icon.unlink()
        icon.symlink_to("missing.icns")
        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "regular AppIcon",
        ):
            verify_app_bundle.verify_icon(app)

    def test_checks_every_nested_macho_and_rejects_wrong_slices(self) -> None:
        app = self.root / "Marauder Notebook.app"
        main = app / "Contents" / "MacOS" / "Marauder Notebook"
        nested = (
            app / "Contents" / "Frameworks" / "Sparkle.framework" / "Versions" / "B" / "Sparkle"
        )
        resource = app / "Contents" / "Resources" / "copy.txt"
        for path in (main, nested, resource):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture")

        def describe(path: Path) -> str:
            return "ASCII text" if path == resource else "Mach-O universal binary"

        def architectures(path: Path) -> set[str]:
            return {"arm64"} if path == nested else {"arm64", "x86_64"}

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "Sparkle.*exactly arm64",
        ):
            verify_app_bundle.verify_macho_architectures(
                app,
                describe=describe,
                architectures=architectures,
            )

        verified = verify_app_bundle.verify_macho_architectures(
            app,
            describe=describe,
            architectures=lambda _: {"arm64", "x86_64"},
        )
        self.assertEqual(verified, [nested, main])
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "exactly arm64"):
            verify_app_bundle.verify_macho_architectures(
                app,
                describe=describe,
                architectures=lambda _: {"arm64", "x86_64", "i386"},
            )

    def test_declared_executable_must_be_executable_macho_with_exact_slices(self) -> None:
        executable = self.root / "Marauder Notebook"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "not a Mach-O"):
            verify_app_bundle.verify_declared_executable(
                executable,
                describe=lambda _: "POSIX shell script, ASCII text executable",
                architectures=lambda _: {"arm64", "x86_64"},
            )
        executable.write_bytes(b"fixture")
        with self.assertRaisesRegex(verify_app_bundle.BundleVerificationError, "exactly arm64"):
            verify_app_bundle.verify_declared_executable(
                executable,
                describe=lambda _: "Mach-O universal binary",
                architectures=lambda _: {"arm64", "x86_64", "i386"},
            )

    def test_rejects_build_host_rpath_and_embedded_path_in_every_slice(self) -> None:
        self.assertIsNone(verify_app_bundle.BUILD_HOST_PATH.search("/tmp/XXXXXX.png"))
        executable = self.root / verify_app_bundle.EXECUTABLE_NAME

        def clean_rpaths(_: Path, __: str) -> set[str]:
            return set(verify_app_bundle.ALLOWED_RPATHS)

        verify_app_bundle.verify_macho_load_paths(
            [executable],
            rpath_reader=clean_rpaths,
            build_path_reader=lambda *_: (),
            dependency_reader=lambda *_: {"/usr/lib/libSystem.B.dylib"},
        )

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "unsafe runtime search paths",
        ):
            verify_app_bundle.verify_macho_load_paths(
                [executable],
                rpath_reader=lambda *_: {
                    "/usr/lib/swift",
                    "/opt/homebrew/Cellar/swift/toolchain/usr/lib/swift/macosx",
                },
                build_path_reader=lambda *_: (),
                dependency_reader=lambda *_: {"/usr/lib/libSystem.B.dylib"},
            )

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "absolute build-host path",
        ):
            verify_app_bundle.verify_macho_load_paths(
                [executable],
                rpath_reader=clean_rpaths,
                build_path_reader=lambda _, architecture: (
                    "/Users/builder/project/.build/release/NotebookKit.bundle",
                )
                if architecture == "x86_64"
                else (),
                dependency_reader=lambda *_: {"/usr/lib/libSystem.B.dylib"},
            )

        with self.assertRaisesRegex(
            verify_app_bundle.BundleVerificationError,
            "unsafe dynamic dependencies",
        ):
            verify_app_bundle.verify_macho_load_paths(
                [executable],
                rpath_reader=clean_rpaths,
                build_path_reader=lambda *_: (),
                dependency_reader=lambda *_: {
                    "/usr/lib/libSystem.B.dylib",
                    "/System/Library/../../Library/Frameworks/Injected.framework/Injected",
                },
            )

        self.assertEqual(
            verify_app_bundle.parse_rpaths(
                "cmd LC_RPATH\n"
                "  cmdsize 64\n"
                "  path @executable_path/../Frameworks Evil (offset 12)\n"
            ),
            {"@executable_path/../Frameworks Evil"},
        )
        self.assertEqual(
            verify_app_bundle.parse_dependencies(
                "fixture:\n"
                "\t/usr/lib/My Library.dylib "
                "(compatibility version 1.0.0, current version 1.0.0)\n"
            ),
            {"/usr/lib/My Library.dylib"},
        )


    def test_accepts_runtime_homebrew_search_literals_in_every_slice(self) -> None:
        runtime_literals = (
            "/opt/homebrew/bin/python3",
            "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
            "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
        )
        for literal in runtime_literals:
            with self.subTest(literal=literal):
                self.assertFalse(macho_contract.line_embeds_build_host_path(literal))

        executables = [
            self.root / macho_contract.EXECUTABLE_NAME,
            self.root / "notebook-control",
        ]
        inspected: list[tuple[str, str]] = []

        def rejected_strings(candidate: Path, architecture: str) -> tuple[str, ...]:
            inspected.append((candidate.name, architecture))
            return tuple(
                line
                for line in runtime_literals
                if macho_contract.line_embeds_build_host_path(line)
            )

        macho_contract.verify_macho_load_paths(
            executables,
            rpath_reader=lambda *_: set(macho_contract.ALLOWED_RPATHS),
            build_path_reader=rejected_strings,
            dependency_reader=lambda *_: {"/usr/lib/libSystem.B.dylib"},
        )
        self.assertEqual(
            inspected,
            [
                (executable.name, architecture)
                for executable in executables
                for architecture in ("arm64", "x86_64")
            ],
        )

    def test_rejects_homebrew_path_glued_to_allowed_literal(self) -> None:
        for line in (
            "/opt/homebrew/bin/foo",
            "/opt/homebrew/binX",
            "/opt/homebrew/bin:/opt/homebrew/lib/x",
            " /opt/homebrew/bin",
            "/opt/homebrew/Cellar/swift/usr/lib",
            "x/opt/homebrew/bin",
        ):
            with self.subTest(line=line):
                self.assertTrue(macho_contract.line_embeds_build_host_path(line))

    def test_signed_entitlement_reader_uses_current_codesign_output_contract(self) -> None:
        helper = self.root / "helper"
        entitlements = {"com.apple.security.app-sandbox": True}
        result = CompletedProcess(
            args=["codesign"],
            returncode=0,
            stdout=plistlib.dumps(entitlements),
            stderr=b"Executable=helper\n",
        )
        with mock.patch.object(verify_app_bundle.subprocess, "run", return_value=result) as run:
            self.assertEqual(
                verify_app_bundle._read_signed_entitlements(
                    helper,
                    "arm64",
                    required=False,
                ),
                entitlements,
            )
        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/codesign",
                "-d",
                "--architecture",
                "arm64",
                "--entitlements=-",
                "--xml",
                str(helper),
            ],
        )
        empty_result = CompletedProcess(
            args=["codesign"],
            returncode=0,
            stdout=b"",
            stderr=b"Executable=helper\n",
        )
        with mock.patch.object(
            verify_app_bundle.subprocess,
            "run",
            return_value=empty_result,
        ):
            self.assertEqual(
                verify_app_bundle._read_signed_entitlements(
                    helper,
                    "arm64",
                    required=False,
                ),
                {},
            )
            with self.assertRaisesRegex(
                verify_app_bundle.BundleVerificationError,
                "missing its entitlements",
            ):
                verify_app_bundle._read_signed_entitlements(
                    helper,
                    "arm64",
                    required=True,
                )


if __name__ == "__main__":
    unittest.main()
