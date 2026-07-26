#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path


class GatekeeperBoundaryError(RuntimeError):
    pass


RunCommand = Callable[..., subprocess.CompletedProcess[str]]


def verify_account_free_gatekeeper(app: Path, *, run: RunCommand = subprocess.run) -> None:
    if app.is_symlink() or not app.is_dir():
        raise GatekeeperBoundaryError("the account-free app must be an ordinary bundle")
    for tool in (Path("/usr/bin/xcrun"), Path("/usr/sbin/spctl")):
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise GatekeeperBoundaryError(f"required macOS assessment tool is unavailable: {tool}")

    stapler = run(
        ["/usr/bin/xcrun", "stapler", "validate", "-v", str(app)],
        check=False,
        capture_output=True,
        text=True,
    )
    if stapler.returncode != 65:
        raise GatekeeperBoundaryError(
            "account-free app did not produce the expected no-ticket stapler result"
        )

    assessment = run(
        [
            "/usr/sbin/spctl",
            "--assess",
            "--type",
            "execute",
            "--ignore-cache",
            "--no-cache",
            "--raw",
            str(app),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if assessment.returncode != 3:
        raise GatekeeperBoundaryError(
            "account-free app did not produce the expected policy denial for manual approval"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the account-free first-launch macOS approval boundary"
    )
    parser.add_argument("--app", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        verify_account_free_gatekeeper(arguments.app)
    except GatekeeperBoundaryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
