#!/usr/bin/env python3

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path


class GatewayError(RuntimeError):
    pass


class CommandGateway:
    def _run(
        self,
        arguments: list[str],
        *,
        input_bytes: bytes | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            arguments,
            input=input_bytes,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if check and result.returncode != 0:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise GatewayError(message or f"command failed: {arguments[0]}")
        return result

    @staticmethod
    def _json(result: subprocess.CompletedProcess[bytes]) -> object:
        try:
            return json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise GatewayError("GitHub returned invalid JSON") from error

    @staticmethod
    def _flatten(payload: object) -> list[object]:
        if not isinstance(payload, list):
            raise GatewayError("GitHub list response is not an array")
        if payload and all(isinstance(page, list) for page in payload):
            return [item for page in payload for item in page]
        if any(isinstance(page, list) for page in payload):
            raise GatewayError("GitHub list response has inconsistent pagination")
        return payload

    def head(self) -> str:
        return self._run(["git", "rev-parse", "HEAD"]).stdout.decode("ascii").strip()

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        return self._run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            check=False,
        ).returncode == 0

    def intake_target(self, repository: str, branch: str) -> str:
        result = self._run(
            [
                "git", "ls-remote", "--exit-code", "--heads",
                f"https://github.com/{repository}.git", f"refs/heads/{branch}",
            ]
        ).stdout.decode("ascii").strip()
        fields = result.split("\t")
        if len(fields) != 2 or fields[1] != f"refs/heads/{branch}":
            raise GatewayError("intake ref has an invalid identity")
        return fields[0]

    def current_tag_target(self, repository: str, tag: str) -> str | None:
        owner, name = repository.split("/", 1)
        query = """query($owner: String!, $name: String!, $qualifiedName: String!) {
          repository(owner: $owner, name: $name) {
            ref(qualifiedName: $qualifiedName) { target { __typename oid } }
          }
        }"""
        payload = self._json(
            self._run(
                [
                    "gh", "api", "graphql", "-F", f"owner={owner}", "-F", f"name={name}",
                    "-F", f"qualifiedName=refs/tags/{tag}", "-f", f"query={query}",
                ]
            )
        )
        try:
            target = payload["data"]["repository"]["ref"]
            if target is None:
                return None
            value = target["target"]
            if value["__typename"] != "Commit" or not isinstance(value["oid"], str):
                raise KeyError
            return value["oid"]
        except (KeyError, TypeError) as error:
            raise GatewayError("GitHub returned an invalid release tag target") from error

    def _list(self, endpoint: str) -> list[object]:
        payload = self._json(
            self._run(["gh", "api", "--paginate", "--slurp", endpoint])
        )
        return self._flatten(payload)

    def list_releases(self, repository: str) -> list[object]:
        return self._list(f"repos/{repository}/releases?per_page=100")

    def create_draft(self, repository: str, payload: dict[str, object]) -> object:
        return self._json(
            self._run(
                ["gh", "api", "--method", "POST", f"repos/{repository}/releases", "--input", "-"],
                input_bytes=json.dumps(payload, separators=(",", ":")).encode(),
            )
        )

    def get_release(self, repository: str, release_id: str) -> object:
        return self._json(
            self._run(["gh", "api", f"repos/{repository}/releases/{release_id}"])
        )

    def delete_release(self, repository: str, release_id: str) -> None:
        self._run(
            ["gh", "api", "--method", "DELETE", f"repos/{repository}/releases/{release_id}"]
        )

    def list_assets(self, repository: str, release_id: str) -> list[object]:
        return self._list(f"repos/{repository}/releases/{release_id}/assets?per_page=100")

    def download_asset(self, repository: str, asset_id: str, output: Path) -> None:
        result = self._run(
            ["gh", "api", "-H", "Accept: application/octet-stream", f"repos/{repository}/releases/assets/{asset_id}"]
        )
        output.write_bytes(result.stdout)

    def upload_asset(self, repository: str, tag: str, path: Path) -> None:
        self._run(["gh", "release", "upload", tag, str(path), "--repo", repository])

    def publish(self, repository: str, tag: str) -> Exception | None:
        result = self._run(
            ["gh", "release", "edit", tag, "--repo", repository, "--draft=false", "--latest"],
            check=False,
        )
        if result.returncode == 0:
            return None
        return GatewayError(
            result.stderr.decode("utf-8", errors="replace").strip() or "publish failed"
        )

    def verify_release(self, repository: str, tag: str) -> bool:
        return self._run(
            ["gh", "release", "verify", tag, "--repo", repository], check=False
        ).returncode == 0

    def verify_asset(self, repository: str, tag: str, path: Path) -> None:
        self._run(["gh", "release", "verify-asset", tag, str(path), "--repo", repository])

    def wait(self, seconds: int) -> None:
        time.sleep(seconds)
