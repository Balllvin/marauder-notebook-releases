from __future__ import annotations

import base64
import binascii
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from .intake_errors import IntakeError
except ImportError:
    from intake_errors import IntakeError


SPARKLE_NAMESPACE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
FEED_SIGNATURE_BLOCK = re.compile(
    rb"<!-- sparkle-signatures:\nedSignature: ([A-Za-z0-9+/]+={0,2})\nlength: ([1-9][0-9]*)\n-->\n\Z"
)
ED25519_SUBJECT_PUBLIC_KEY_PREFIX = bytes.fromhex("302a300506032b6570032100")


def require_regular_file(path: Path, maximum_bytes: int | None = None) -> None:
    if path.is_symlink() or not path.is_file():
        raise IntakeError(f"{path.name} must be a regular file")
    if maximum_bytes is not None and path.stat().st_size > maximum_bytes:
        raise IntakeError(f"{path.name} exceeds its size limit")


def canonical_signature(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise IntakeError(f"{label} is missing")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise IntakeError(f"{label} is not canonical base64") from error
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise IntakeError(f"{label} must be one canonical Ed25519 signature")
    return decoded


def canonical_public_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise IntakeError("the committed Sparkle public key is invalid") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise IntakeError("the committed Sparkle public key is invalid")
    return decoded


def verify_ed25519(
    input_path: Path,
    signature: bytes,
    public_key: bytes,
    openssl: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="notebook-intake-signature-") as directory:
        root = Path(directory)
        key_path = root / "public.der"
        signature_path = root / "signature.bin"
        key_path.write_bytes(ED25519_SUBJECT_PUBLIC_KEY_PREFIX + public_key)
        signature_path.write_bytes(signature)
        try:
            result = subprocess.run(
                [
                    openssl,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-keyform",
                    "DER",
                    "-rawin",
                    "-in",
                    str(input_path),
                    "-sigfile",
                    str(signature_path),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as error:
            raise IntakeError(f"unable to run the Ed25519 verifier: {error}") from error
        if result.returncode != 0:
            raise IntakeError(f"Ed25519 signature verification failed for {input_path.name}")


def validate_appcast(
    path: Path,
    *,
    archive: Path,
    archive_url: str,
    archive_signature: str,
    version: str,
    build_number: str,
    public_key: bytes,
    openssl: str,
) -> None:
    require_regular_file(path, 1024 * 1024)
    payload = path.read_bytes()
    if re.search(rb"<!\s*(DOCTYPE|ENTITY)", payload, re.IGNORECASE):
        raise IntakeError("appcast.xml cannot contain document type or entity declarations")
    signature_match = FEED_SIGNATURE_BLOCK.search(payload)
    if signature_match is None:
        raise IntakeError("appcast.xml has no valid signed-feed block")
    feed_signature = canonical_signature(
        signature_match.group(1).decode("ascii"),
        "appcast feed signature",
    )
    signed_length = int(signature_match.group(2))
    if signed_length != signature_match.start():
        raise IntakeError("appcast signed length does not match its signed content")

    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise IntakeError(f"appcast.xml is not valid XML: {error}") from error
    enclosures = root.findall(".//enclosure")
    if len(enclosures) != 1:
        raise IntakeError("appcast.xml must contain exactly one release enclosure")
    enclosure = enclosures[0]
    containing_items = [
        item for item in root.findall(".//item") if enclosure in item.findall("enclosure")
    ]
    if len(containing_items) != 1:
        raise IntakeError("appcast enclosure must belong to exactly one update item")
    item = containing_items[0]

    def version_value(name: str) -> str | None:
        qualified_name = f"{{{SPARKLE_NAMESPACE}}}{name}"
        attribute_value = enclosure.get(qualified_name)
        elements = item.findall(qualified_name)
        if len(elements) > 1:
            raise IntakeError(f"appcast item has duplicate Sparkle {name} values")
        element_value = (elements[0].text or "").strip() or None if elements else None
        if attribute_value and element_value and attribute_value != element_value:
            raise IntakeError(f"appcast has conflicting Sparkle {name} values")
        return attribute_value or element_value

    if enclosure.get("url") != archive_url:
        raise IntakeError("appcast enclosure does not use the immutable archive URL")
    if enclosure.get("length") != str(archive.stat().st_size):
        raise IntakeError("appcast enclosure length does not match the archive")
    if version_value("shortVersionString") != version:
        raise IntakeError("appcast version does not match release metadata")
    if version_value("version") != build_number:
        raise IntakeError("appcast build number does not match release metadata")
    if enclosure.get(f"{{{SPARKLE_NAMESPACE}}}edSignature") != archive_signature:
        raise IntakeError("appcast archive signature does not match release metadata")

    with tempfile.NamedTemporaryFile(prefix="notebook-appcast-content-", delete=False) as signed_file:
        signed_path = Path(signed_file.name)
        signed_file.write(payload[:signed_length])
    try:
        verify_ed25519(signed_path, feed_signature, public_key, openssl)
    finally:
        signed_path.unlink(missing_ok=True)
