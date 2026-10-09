"""Certificate-based IPA validation, signing and USB installation."""
from __future__ import annotations
import asyncio
import csv
import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

MAX_IPA = 512 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        who = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"],
                                      creationflags=CREATE_NO_WINDOW, text=True)
        sid = next(csv.reader([who.strip()]))[1]
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                        f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                       check=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
    else:
        path.chmod(0o700)
    return path


def inspect_ipa(path: Path) -> dict:
    if path.stat().st_size > MAX_IPA:
        raise ValueError("IPA exceeds the 512 MB limit.")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 20000 or sum(e.file_size for e in entries) > MAX_EXPANDED:
            raise ValueError("IPA expands beyond the supported limit.")
        names = set()
        for entry in entries:
            name = entry.filename
            parts = name.rstrip("/").split("/")
            normalized = name.rstrip("/").casefold()
            if (not parts or name.startswith("/") or "\\" in name or ":" in name
                    or any(not p or p in ("..", ".") or p.endswith((".", " ")) for p in parts)
                    or normalized in names or "\x00" in name
                    or any(re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p) for p in parts)
                    or stat.S_ISLNK(entry.external_attr >> 16) or entry.flag_bits & 1):
                raise ValueError("IPA contains an unsafe or unsupported ZIP entry.")
            names.add(normalized)
        names = {entry.filename for entry in entries}
        roots = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
        if len(roots) != 1:
            raise ValueError("IPA must contain one app under Payload.")
        if archive.getinfo(roots[0]).file_size > 4 * 1024 * 1024:
            raise ValueError("App metadata is too large.")
        info = plistlib.loads(archive.read(roots[0]))
        root = roots[0].rsplit("/", 1)[0] + "/"
        if any(n.startswith((root + "PlugIns/", root + "Watch/", root + "Extensions/")) for n in names):
            raise ValueError("This version supports apps without extensions or Watch apps. Nothing was removed.")
        executable = info.get("CFBundleExecutable", "")
        if not executable or "/" in executable or root + executable not in names:
            raise ValueError("IPA has no valid app executable.")
        bundle = info.get("CFBundleIdentifier", "")
        if not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", bundle):
            raise ValueError("IPA has an invalid bundle identifier.")
        # App Store encrypted binaries cannot be re-signed as working apps.
        with archive.open(root + executable) as binary:
            import struct
            header = binary.read(32)
            if len(header) < 32 or header[:4] != b"\xcf\xfa\xed\xfe":
                raise ValueError("This version requires a thin 64-bit iPad device executable.")
            ncmds, cmdsize = struct.unpack_from("<II", header, 16)
            if ncmds > 10000 or cmdsize > 16 * 1024 * 1024:
                raise ValueError("Invalid executable load commands.")
            commands = binary.read(cmdsize)
            offset = 0
            for _ in range(ncmds):
                if offset + 8 > len(commands):
                    raise ValueError("Truncated executable.")
                kind, length = struct.unpack_from("<II", commands, offset)
                if length < 8 or offset + length > len(commands):
                    raise ValueError("Invalid executable command.")
                if kind in (0x21, 0x2C):
                    if length < 20 or struct.unpack_from("<I", commands, offset + 16)[0] != 0:
                        raise ValueError("Encrypted App Store apps cannot be signed with this tool.")
                offset += length
        return {"name": str(info.get("CFBundleDisplayName", info.get("CFBundleName", bundle))),
                "bundle": bundle, "minimum_os": str(info.get("MinimumOSVersion", "")),
                "bytes": path.stat().st_size}


def read_profile(path: Path) -> dict:
    from asn1crypto import cms
    data = path.read_bytes()
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("Provisioning profile is too large.")
    envelope = cms.ContentInfo.load(data)
    if envelope["content_type"].native != "signed_data":
        raise ValueError("Not a signed provisioning profile.")
    return plistlib.loads(envelope["content"]["encap_content_info"]["content"].native)


def validate_identity(p12: Path, password: str, profile: dict, bundle: str, udid: str | None):
    key, certificate, chain = pkcs12.load_key_and_certificates(
        p12.read_bytes(), password.encode("utf-8") if password else None)
    if key is None or certificate is None:
        raise ValueError("The P12 must contain a signing certificate and its private key.")
    now = datetime.now(timezone.utc)
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise ValueError("The signing certificate is expired or not valid yet.")
    expiry = profile.get("ExpirationDate")
    if not isinstance(expiry, datetime) or expiry.replace(tzinfo=timezone.utc) <= now:
        raise ValueError("The provisioning profile has expired.")
    if certificate.public_bytes(serialization.Encoding.DER) not in profile.get("DeveloperCertificates", []):
        raise ValueError("The selected certificate does not match this provisioning profile.")
    if not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", bundle):
        raise ValueError("Enter a valid bundle identifier, such as com.yourname.app.")
    app_id = profile.get("Entitlements", {}).get("application-identifier", "")
    allowed = app_id.split(".", 1)[1] if "." in app_id else ""
    if not allowed or not fnmatch.fnmatchcase(bundle, allowed):
        raise ValueError(f"Profile allows {allowed or 'no app ID'}; it does not cover {bundle}.")
    devices = profile.get("ProvisionedDevices", [])
    if not devices and not profile.get("ProvisionsAllDevices", False):
        raise ValueError("An App Store profile cannot install over USB. Use development or ad hoc provisioning.")
    if udid and not profile.get("ProvisionsAllDevices", False) and udid.lower() not in [d.lower() for d in devices]:
        raise ValueError("The selected iPad is not registered in this provisioning profile.")
    return key, certificate, chain


def sign_ipa(source: Path, destination: Path, p12: Path, password: str,
             profile_path: Path, bundle_override: str, udid: str | None,
             zsign: Path, scratch: Path) -> dict:
    metadata = inspect_ipa(source)
    bundle = bundle_override.strip() or metadata["bundle"]
    profile = read_profile(profile_path)
    key, certificate, chain = validate_identity(p12, password, profile, bundle, udid)
    if not zsign.is_file():
        raise ValueError("The bundled zsign tool is missing. Extract the entire Windows ZIP again.")
    with tempfile.TemporaryDirectory(dir=scratch, prefix="sign-") as tmp:
        folder = Path(tmp)
        # No password is exposed in process arguments. The private key lives only in
        # this per-user protected temporary directory and is removed after signing.
        key_path = folder / "identity.p12"
        key_path.write_bytes(pkcs12.serialize_key_and_certificates(
            b"SideBridge", key, certificate, chain, serialization.NoEncryption()))
        signed = folder / "signed.ipa"
        result = subprocess.run([str(zsign), "-k", str(key_path),
                                 "-m", str(profile_path.resolve()), "-b", bundle, "-f", "-z", "6",
                                 "-t", str(folder), "-o", str(signed), str(source.resolve())],
                                capture_output=True, text=True, errors="replace", timeout=600,
                                cwd=folder, creationflags=CREATE_NO_WINDOW)
        if result.returncode != 0 or not signed.is_file():
            # zsign logs may include local file paths; only show them locally.
            raise ValueError("Signing failed: " + (result.stderr or result.stdout)[-2000:])
        metadata = inspect_ipa(signed)
        if metadata["bundle"] != bundle:
            raise ValueError("Signer produced an unexpected bundle identifier.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(signed, destination)
    metadata["expires"] = profile["ExpirationDate"].isoformat() + "Z"
    return metadata


async def usb_devices() -> list[dict]:
    from pymobiledevice3.usbmux import list_devices
    from pymobiledevice3.lockdown import create_using_usbmux
    devices = []
    for device in await list_devices():
        if device.connection_type != "USB":
            continue
        async with await create_using_usbmux(serial=device.serial, connection_type="USB", pair_timeout=20) as client:
            devices.append({"id": device.serial, "name": client.all_values.get("DeviceName", device.serial)})
    return devices


async def install_ipa(path: Path, udid: str, progress):
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    async with await create_using_usbmux(serial=udid, connection_type="USB", pair_timeout=30) as client:
        async with InstallationProxyService(client) as service:
            await service.install_from_local(path, handler=lambda value, *args: progress(int(value)))


def resource_path(name: str) -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / name
