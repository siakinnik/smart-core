#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 siakinnik
"""Signing keys and signed firmware images for smart-core OTA updates.

    smartsign.py keygen ~/.config/smart-core/lumenc3-release.key   # + .pub next to it
    smartsign.py sign build/lumenc3.bin --key ~/.config/smart-core/lumenc3-release.key \\
        --model-id 0x0001 -o lumenc3-2.1.0.simg
    smartsign.py verify lumenc3-2.1.0.simg --pub ota_signing.pub

A signed image is the firmware followed by a 212-byte manifest (see
smart_core.h): model, security version, size, version string, SHA-512 of
the firmware, the signer's Ed25519 public key and the signature. Flash it
over USB like a plain image, or send it with `smartctl.py ... update`.

The private key never goes into a repository; the public key (.pub) does:
the firmware is built with it and only takes updates signed by its owner.
Needs `cryptography`.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import struct
import sys

MAGIC = b"SMARTFW1"
MANIFEST_LEN = 212
ESP_APP_DESC_MAGIC = 0xABCD5432


class SignError(Exception):
    pass


# ---------- keys ----------

def _private(seed: bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return _private(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def load_hex(path: str | Path, length: int) -> bytes:
    data = bytes.fromhex(Path(path).read_text().strip())
    if len(data) != length:
        raise SignError(f"{path}: expected {length} bytes of hex, got {len(data)}")
    return data


def keygen(path: Path) -> tuple[Path, bytes]:
    pub_path = path.with_name(path.name + ".pub") if path.suffix != ".key" else path.with_suffix(".pub")
    if path.exists() or pub_path.exists():
        raise SignError(f"{path} or {pub_path} already exists: not overwriting a signing key")
    seed = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # owner-only
    with os.fdopen(fd, "w") as f:
        f.write(seed.hex() + "\n")
    pub = public_key(seed)
    pub_path.write_text(pub.hex() + "\n")
    return pub_path, pub


def fingerprint(key: bytes) -> str:
    digest = hashlib.blake2b(key, digest_size=8).hexdigest()
    return ":".join(digest[i : i + 4] for i in range(0, 16, 4))


# ---------- images ----------

@dataclass(frozen=True)
class Manifest:
    model_id: int
    security_version: int
    image_size: int
    version: str
    sha512: bytes
    signer: bytes
    signature: bytes

    @property
    def signed_part(self) -> bytes:
        return pack_unsigned(self.model_id, self.security_version, self.image_size, self.version, self.sha512, self.signer)


def pack_unsigned(model_id: int, security_version: int, size: int, version: str, sha512: bytes, signer: bytes) -> bytes:
    v = version.encode()[:32].ljust(32, b"\0")
    return MAGIC + struct.pack("<HHII", model_id, 0, security_version, size) + v + sha512 + signer


def parse_manifest(raw: bytes) -> Manifest:
    if len(raw) != MANIFEST_LEN or raw[:8] != MAGIC:
        raise SignError("no smart-core manifest: not a signed image")
    model_id, _, secver, size = struct.unpack_from("<HHII", raw, 8)
    version = raw[20:52].rstrip(b"\0").decode(errors="replace")
    return Manifest(model_id, secver, size, version, raw[52:116], raw[116:148], raw[148:212])


def esp_app_info(firmware: bytes) -> tuple[str, int] | None:
    """(version, secure_version) from an ESP-IDF app image's esp_app_desc_t."""
    # image header (24) + first segment header (8), then esp_app_desc_t
    if len(firmware) < 80 or firmware[0] != 0xE9:
        return None
    magic, secure_version = struct.unpack_from("<II", firmware, 32)
    if magic != ESP_APP_DESC_MAGIC:
        return None
    return firmware[48:80].rstrip(b"\0").decode(errors="replace"), secure_version


def sign(firmware: bytes, seed: bytes, model_id: int, security_version: int | None = None, version: str | None = None) -> bytes:
    """firmware + manifest. Version and security version default to the ESP app description."""
    if firmware[-MANIFEST_LEN:-MANIFEST_LEN + 8] == MAGIC:
        raise SignError("this image is signed already")
    info = esp_app_info(firmware)
    if version is None:
        version = info[0] if info else ""
    if security_version is None:
        security_version = info[1] if info else 0
    unsigned = pack_unsigned(model_id, security_version, len(firmware), version, hashlib.sha512(firmware).digest(), public_key(seed))
    return firmware + unsigned + _private(seed).sign(unsigned)


def verify(image: bytes, trusted: bytes | None = None) -> Manifest:
    """Check an image: manifest signature, hash, and (if given) the signer."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if len(image) <= MANIFEST_LEN:
        raise SignError("too short for a signed image")
    m = parse_manifest(image[-MANIFEST_LEN:])
    firmware = image[:-MANIFEST_LEN]
    try:
        Ed25519PublicKey.from_public_bytes(m.signer).verify(m.signature, m.signed_part)
    except InvalidSignature:
        raise SignError("bad signature") from None
    if m.image_size != len(firmware) or hashlib.sha512(firmware).digest() != m.sha512:
        raise SignError("the firmware doesn't match its manifest (modified after signing)")
    if trusted is not None and m.signer != trusted:
        raise SignError(f"signed by {fingerprint(m.signer)}, not by the expected key {fingerprint(trusted)}")
    return m


# ---------- CLI ----------

def main() -> int:
    parser = argparse.ArgumentParser(description="smart-core signing keys and signed firmware images")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("keygen", help="create a signing key (and its .pub)")
    p.add_argument("key", type=Path)
    p = sub.add_parser("pubkey", help="print the public key of a signing key")
    p.add_argument("key", type=Path)
    p = sub.add_parser("sign", help="sign a firmware image")
    p.add_argument("firmware", type=Path)
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--model-id", type=lambda s: int(s, 0), required=True, help="e.g. 0x0001")
    p.add_argument("--security-version", type=int, help="default: the image's secure_version")
    p.add_argument("--version", help="default: the image's version (esp_app_desc)")
    p.add_argument("-o", "--output", type=Path, help="default: <firmware>.simg")
    p = sub.add_parser("verify", help="check a signed image")
    p.add_argument("image", type=Path)
    p.add_argument("--pub", type=Path, help="the key it must be signed with (.pub)")
    args = parser.parse_args()

    try:
        if args.command == "keygen":
            pub_path, pub = keygen(args.key)
            print(f"private key: {args.key}  (keep it secret, never commit it)")
            print(f"public key:  {pub_path}  {fingerprint(pub)}")
        elif args.command == "pubkey":
            print(public_key(load_hex(args.key, 32)).hex())
        elif args.command == "sign":
            out = args.output or args.firmware.with_suffix(".simg")
            signed = sign(args.firmware.read_bytes(), load_hex(args.key, 32), args.model_id, args.security_version, args.version)
            out.write_bytes(signed)
            m = parse_manifest(signed[-MANIFEST_LEN:])
            print(f"{out}: model 0x{m.model_id:04X}, version {m.version or '?'}, security {m.security_version}, "
                  f"{m.image_size} bytes, signed by {fingerprint(m.signer)}")
        elif args.command == "verify":
            m = verify(args.image.read_bytes(), load_hex(args.pub, 32) if args.pub else None)
            print(f"ok: model 0x{m.model_id:04X}, version {m.version or '?'}, security {m.security_version}, "
                  f"{m.image_size} bytes, signed by {fingerprint(m.signer)}")
    except (SignError, OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
