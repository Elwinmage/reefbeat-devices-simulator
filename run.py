#!/usr/bin/env python3
"""ReefBeat Devices Simulator fixture exporter.

This script snapshots ReefBeat device endpoints from:
    - The local device HTTP API (by IP), and
    - Optionally the ReefBeat cloud API (account-level endpoints).

Outputs are written as a fixture tree under ``devices/`` where each endpoint is
stored as a ``data`` file. Payloads are sanitized to remove secrets/PII while
preserving stable relationships (e.g. aquarium/device linkage).

Key entrypoints:
    - ``python run.py scan``: Discover devices (cloud-fast listing or LAN CIDR scan).
    - ``python run.py --ip <ip>``: Snapshot a local device (type auto-detected).
    - ``python run.py --cloud``: Export cloud fixtures only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Mapping, Union, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from xml.dom import minidom
from xml.parsers.expat import ExpatError

try:
    import colorlog  # type: ignore[import]

    has_colorlog = True
except Exception:
    colorlog = None
    has_colorlog = False

handler = logging.StreamHandler()
if has_colorlog:
    formatter = colorlog.ColoredFormatter(  # type: ignore[call-arg]
        "%(log_color)s%(levelname)-8s%(reset)s %(blue)s:%(reset)s %(message)s",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red,bg_white",
        },
    )
    handler.setFormatter(formatter)  # type: ignore[arg-type]
else:
    handler.setFormatter(logging.Formatter("%(levelname)-8s: %(message)s"))

root = logging.getLogger()
root.setLevel(logging.INFO)
root.handlers[:] = []
root.addHandler(handler)

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

CLOUD_SERVER_ADDR: Final[str] = "cloud.reef-beat.com"

# This Basic auth value is what the component uses for the OAuth token exchange.
# (It is not your username/password.)
CLOUD_BASIC_AUTH: Final[str] = "Basic Z0ZqSHRKcGE6Qzlmb2d3cmpEV09SVDJHWQ=="

HTTP_TIMEOUT_SECS_DEFAULT: Final[int] = 10

ENV_USERNAME: Final[str] = "REEFBEAT_USERNAME"
ENV_PASSWORD: Final[str] = "REEFBEAT_PASSWORD"

# Local device endpoints
BASE_URLS: Final[list[str]] = [
    "/",
    "/time",
    "/description.xml",
    "/cloud",
    "/connectivity",
    "/connectivity/events",
    "/device-info",
    "/device-settings",
    "/dashboard",
    "/mode",
    "/firmware",
    "/logging",
    "/wifi",
    "/wifi/scan",
]

ATO_URLS: Final[list[str]] = [
    "/",
    "/cloud",
    "/dashboard",
    "/device-info",
    "/firmware",
    "/logging",
    "/mode",
    "/time",
    "/wifi",
    "/description.xml",
    "/configuration",
    "/water-level",
    "/temperature",
    "/temperature-log",
]

DOSE2_URLS: Final[list[str]] = [
    "/head/1/settings",
    "/head/2/settings",
    "/daily-log",
    "/dosing-queue",
    "/supplement",
    "/head/1/supplement-volume",
    "/head/2/supplement-volume",
    "/export-log",
]

DOSE4_URLS: Final[list[str]] = [
    *DOSE2_URLS,
    "/head/3/settings",
    "/head/4/settings",
    "/head/3/supplement-volume",
    "/head/4/supplement-volume",
]


MAT_URLS: Final[list[str]] = [
    "/configuration",
]

LED_URLS: Final[list[str]] = [
    "/manual",
    "/acclimation",
    "/moonphase",
    "/current",
    "/timer",
    "/auto/1",
    "/auto/2",
    "/auto/3",
    "/auto/4",
    "/auto/5",
    "/auto/6",
    "/auto/7",
    "/preset_name",
    "/preset_name/1",
    "/preset_name/2",
    "/preset_name/3",
    "/preset_name/4",
    "/preset_name/5",
    "/preset_name/6",
    "/preset_name/7",
    "/clouds/1",
    "/clouds/2",
    "/clouds/3",
    "/clouds/4",
    "/clouds/5",
    "/clouds/6",
    "/clouds/7",
]

RUN_URLS: Final[list[str]] = [
    "/pump/settings",
]

WAVE_URLS: Final[list[str]] = [
    "/controlling-mode",
    "/feeding/schedule",
]

TYPE_MAP: Final[dict[str, list[str]]] = {
    "ATO": ATO_URLS,
    "DOSE": DOSE4_URLS,  # alias
    "DOSE2": DOSE2_URLS,
    "DOSE4": DOSE4_URLS,
    "MAT": MAT_URLS,
    "LED": LED_URLS,
    "RUN": RUN_URLS,
    "WAVE": WAVE_URLS,
}

# Cloud endpoints (account-level). Keep this simple; add more later as needed.
CLOUD_URLS: Final[list[str]] = [
    "/user",
    "/aquarium",
    "/device",
]


JsonScalar = Union[str, int, float, bool, None]
JsonValue = Union[JsonScalar, "JsonObject", "JsonArray"]
JsonObject = dict[str, JsonValue]
JsonArray = list[JsonValue]

SANITIZED_USER: Final[JsonObject] = {
    "backup_email": "user@example.com",
    "country": "United States",
    "country_code": "US",
    "created_at": "2025-01-01T00:00:00Z",
    "email": "user@example.com",
    "first_name": "User",
    "id": 123456,
    "language": "en",
    "last_name": "User",
    "mobile_number": "+10000000000",
    "onboarding_complete": True,
    "uid": "00000000-0000-0000-0000-000000000000",
    "zip_code": "00000",
}

# Keep relationships stable across cloud fixtures
SANITIZED_AQUARIUM_ID: Final[int] = 111111
SANITIZED_AQUARIUM_UID: Final[str] = "00000000-0000-0000-0000-000000000001"

# Device/network identifiers in /device payloads
SANITIZED_IP_ADDRESS: Final[str] = "10.0.0.10"
SANITIZED_MAC: Final[str] = "00:11:22:33:44:55"
SANITIZED_BSSID: Final[str] = "66:55:44:33:22:11"
SANITIZED_HWID: Final[str] = "000000000000"
SANITIZED_SERIAL_CODE: Final[str] = "cf00000000000000"
SANITIZED_SSID: Final[str] = "REDACTED_SSID"
SANITIZED_GATEWAY: Final[str] = "10.0.0.1"
SANITIZED_SECRET: Final[str] = "REDACTED_SECRET"

# Aquarium naming can contain personal context; keep it generic
SANITIZED_AQUARIUM_NAME: Final[str] = "Aquarium"
SANITIZED_SYSTEM_MODEL: Final[str] = "Aquarium System"

# Hidden, local-only mapping used to keep sanitized IDs stable/unique across runs.
# Add this filename to your .gitignore.
SANITIZE_MAP_FILENAME: Final[str] = ".reefbeat_sanitize_map.json"

# Debugging aid:
# - When True, sanitize-map keys are SHA256 digests of raw values.
# - When False (default), sanitize-map keys are the raw values themselves (easier to debug, contains PII).
SANITIZE_MAP_USE_HASH_KEYS: Final[bool] = os.getenv("REEFBEAT_SANITIZE_MAP_USE_HASH_KEYS", "0") in {
    "1",
    "true",
    "True",
    "yes",
    "YES",
}

_UUID_RE: Final[re.Pattern[str]] = re.compile(r"uuid:[0-9a-zA-Z\-]+")

_EMAIL_RE: Final[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE: Final[re.Pattern[str]] = re.compile(r"\+\d{7,15}")
_RAW_UUID_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


# =============================================================================
# Sanitization mapping (local-only; should be gitignored)
# =============================================================================


@dataclass
class SanitizeMap:
    """Persistent mapping for stable, unique sanitized identifiers.

    This file is intended to be gitignored. To avoid storing personal values
    directly, map keys can be SHA256 digests of the original values.
    (In the current debugging mode, keys are stored as raw values.)
    """

    user_uid: dict[str, str]
    aquarium_id: dict[str, int]
    aquarium_uid: dict[str, str]
    device_hwid: dict[str, str]
    device_name: dict[str, str]
    mac: dict[str, str]
    bssid: dict[str, str]
    ip_address: dict[str, str]
    ssid: dict[str, str]
    serial_code: dict[str, str]

    next_aquarium_id: int
    next_ip_host: int
    next_ssid_suffix: int
    next_device_suffix: int
    next_device_suffix_by_prefix: dict[str, int]


def _hash_key(kind: str, raw: str) -> str:
    """Return the sanitize-map key for a raw identifier.

    Args:
        kind: Identifier kind (namespaces the key to reduce collisions).
        raw: Raw identifier value.

    Returns:
        A stable key string. In debug mode this is the raw value; otherwise it is a
        SHA256 digest.
    """
    if not SANITIZE_MAP_USE_HASH_KEYS:
        return raw
    h = hashlib.sha256()
    h.update(kind.encode("utf-8"))
    h.update(b"\x00")
    h.update(raw.encode("utf-8", errors="replace"))
    return h.hexdigest()


def _sanitize_map_default() -> SanitizeMap:
    """Create an empty sanitize map with initial counters.

    Returns:
        A fresh `SanitizeMap` instance suitable for first-run initialization.
    """
    return SanitizeMap(
        user_uid={},
        aquarium_id={},
        aquarium_uid={},
        device_hwid={},
        device_name={},
        mac={},
        bssid={},
        ip_address={},
        ssid={},
        serial_code={},
        next_aquarium_id=111111,
        next_ip_host=10,
        next_ssid_suffix=1,
        next_device_suffix=1,
        next_device_suffix_by_prefix={},
    )


def load_sanitize_map(path: Path) -> SanitizeMap:
    """Load the persistent sanitize map from disk.

    Args:
        path: Path to the JSON mapping file.

    Returns:
        A populated `SanitizeMap`. If the file is missing or invalid, returns a
        default empty map.
    """
    if not path.exists():
        return _sanitize_map_default()
    try:
        obj_any: Any = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _sanitize_map_default()
    if not isinstance(obj_any, dict):
        return _sanitize_map_default()
    obj = cast(dict[str, Any], obj_any)

    def _d_str(val: Any) -> dict[str, str]:
        if isinstance(val, dict):
            out: dict[str, str] = {}
            for k, v in cast(dict[str, Any], val).items():
                if isinstance(v, str):
                    out[k] = v
            return out
        return {}

    def _d_int(val: Any) -> dict[str, int]:
        if isinstance(val, dict):
            out2: dict[str, int] = {}
            for k, v in cast(dict[str, Any], val).items():
                if isinstance(v, int):
                    out2[k] = v
            return out2
        return {}

    def _d_int_str_keys(val: Any) -> dict[str, int]:
        if isinstance(val, dict):
            out3: dict[str, int] = {}
            for k, v in cast(dict[str, Any], val).items():
                if isinstance(v, int):
                    out3[k] = v
            return out3
        return {}

    return SanitizeMap(
        user_uid=_d_str(obj.get("user_uid")),
        aquarium_id=_d_int(obj.get("aquarium_id")),
        aquarium_uid=_d_str(obj.get("aquarium_uid")),
        device_hwid=_d_str(obj.get("device_hwid")),
        device_name=_d_str(obj.get("device_name")),
        mac=_d_str(obj.get("mac")),
        bssid=_d_str(obj.get("bssid")),
        ip_address=_d_str(obj.get("ip_address")),
        ssid=_d_str(obj.get("ssid")),
        serial_code=_d_str(obj.get("serial_code")),
        next_aquarium_id=int(obj.get("next_aquarium_id") or 111111),
        next_ip_host=int(obj.get("next_ip_host") or 10),
        next_ssid_suffix=int(obj.get("next_ssid_suffix") or 1),
        next_device_suffix=int(obj.get("next_device_suffix") or 1),
        next_device_suffix_by_prefix=_d_int_str_keys(obj.get("next_device_suffix_by_prefix")),
    )


def save_sanitize_map(path: Path, smap: SanitizeMap) -> None:
    """Persist the sanitize map to disk atomically.

    Args:
        path: Output path for the map JSON file.
        smap: Map object to serialize.

    Returns:
        None
    """
    payload: dict[str, Any] = {
        "user_uid": smap.user_uid,
        "aquarium_id": smap.aquarium_id,
        "aquarium_uid": smap.aquarium_uid,
        "device_hwid": smap.device_hwid,
        "device_name": smap.device_name,
        "mac": smap.mac,
        "bssid": smap.bssid,
        "ip_address": smap.ip_address,
        "ssid": smap.ssid,
        "serial_code": smap.serial_code,
        "next_aquarium_id": smap.next_aquarium_id,
        "next_ip_host": smap.next_ip_host,
        "next_ssid_suffix": smap.next_ssid_suffix,
        "next_device_suffix": smap.next_device_suffix,
        "next_device_suffix_by_prefix": smap.next_device_suffix_by_prefix,
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _alloc_fake_uuid(counter: int) -> str:
    """Return a stable, readable UUID-like value.

    Args:
        counter: 1-based counter.

    Returns:
        A valid UUID string derived from the counter.
    """
    return f"00000000-0000-0000-0000-{counter:012d}"[-36:]


def map_user_uid(raw_uid: str, smap: SanitizeMap) -> str:
    """Map a raw user UID to a stable sanitized value.

    Args:
        raw_uid: Raw user UUID.
        smap: Persistent mapping.

    Returns:
        Sanitized user UUID.
    """
    key = _hash_key("user_uid", raw_uid)
    if key in smap.user_uid:
        return smap.user_uid[key]
    smap.user_uid[key] = "00000000-0000-0000-0000-000000000000"
    return smap.user_uid[key]


def map_aquarium_id(raw_id: int, smap: SanitizeMap) -> int:
    """Map a raw aquarium numeric ID to a stable sanitized integer.

    Args:
        raw_id: Raw aquarium numeric ID.
        smap: Persistent mapping.

    Returns:
        Sanitized aquarium numeric ID.
    """
    key = _hash_key("aquarium_id", str(raw_id))
    if key in smap.aquarium_id:
        return smap.aquarium_id[key]
    smap.aquarium_id[key] = smap.next_aquarium_id
    smap.next_aquarium_id += 1
    return smap.aquarium_id[key]


def map_aquarium_uid(raw_uid: str, smap: SanitizeMap) -> str:
    """Map a raw aquarium UUID to a stable fake UUID.

    Args:
        raw_uid: Raw aquarium UUID.
        smap: Persistent mapping.

    Returns:
        Sanitized aquarium UUID.
    """
    key = _hash_key("aquarium_uid", raw_uid)
    if key in smap.aquarium_uid:
        return smap.aquarium_uid[key]
    fake = _alloc_fake_uuid(len(smap.aquarium_uid) + 1)
    smap.aquarium_uid[key] = fake
    return fake


def _rand_hex(n_bytes: int) -> str:
    """Return a random lowercase hex string.

    Args:
        n_bytes: Number of random bytes to generate.

    Returns:
        Hex string of length ``2 * n_bytes``.
    """
    return "".join(f"{random.randint(0, 255):02x}" for _ in range(n_bytes))


def map_device_hwid(raw_hwid: str, smap: SanitizeMap) -> str:
    """Map a device HWID to a stable sanitized HWID.

    Args:
        raw_hwid: Raw HWID string.
        smap: Persistent mapping.

    Returns:
        Sanitized HWID (12 hex chars) or the constant sanitized placeholder if the
        input does not look like a HWID.
    """
    # Only map real-looking HWIDs to prevent mapping growth.
    norm = raw_hwid.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{12}", norm):
        return SANITIZED_HWID

    # Idempotence: if we already produced this value, don't re-map it.
    if norm in (v.lower() for v in smap.device_hwid.values()):
        return norm

    key = _hash_key("device_hwid", norm)
    if key in smap.device_hwid:
        return smap.device_hwid[key]
    smap.device_hwid[key] = _rand_hex(6)
    return smap.device_hwid[key]


def map_device_name(raw_name: str, smap: SanitizeMap) -> str:
    """Map a raw device name to a stable sanitized device name.

    Preserves the prefix when the input matches the standard format.

    Args:
        raw_name: Raw device name (e.g. ``RSATO+2487379135``).
        smap: Persistent mapping.

    Returns:
        Sanitized device name (e.g. ``RSATO+0000000001``).
    """
    # Idempotence: if the caller passes an already-sanitized name, do not re-map.
    if raw_name in smap.device_name.values():
        return raw_name

    key = _hash_key("device_name", raw_name)
    if key in smap.device_name:
        return smap.device_name[key]

    # Preserve the device type prefix; replace only the numeric suffix.
    m = re.fullmatch(r"([A-Za-z0-9]+[+\-])(\d+)", raw_name)
    if m:
        prefix = m.group(1)
        width = len(m.group(2))
        n = smap.next_device_suffix_by_prefix.get(prefix, 1)
        smap.next_device_suffix_by_prefix[prefix] = n + 1
        smap.device_name[key] = f"{prefix}{n:0{width}d}"
        return smap.device_name[key]

    # Fallback for unexpected formats.
    n2 = smap.next_device_suffix
    smap.next_device_suffix += 1
    smap.device_name[key] = f"DEVICE_{n2}"
    return smap.device_name[key]


def _rand_mac(prefix: str | None = None) -> str:
    """Generate a random MAC address, optionally with a fixed prefix.

    Args:
        prefix: Optional MAC prefix like ``"02:00:00"``.

    Returns:
        Uppercase MAC address string.
    """
    parts: list[str] = []
    if prefix:
        parts.extend(prefix.split(":"))
    while len(parts) < 6:
        parts.append(f"{random.randint(0, 255):02x}")
    return ":".join(parts[:6]).upper()


def map_mac(raw_mac: str, smap: SanitizeMap) -> str:
    """Map a raw MAC to a stable sanitized MAC.

    Args:
        raw_mac: Raw MAC address.
        smap: Persistent mapping.

    Returns:
        Sanitized MAC address.
    """
    # Idempotence: if we already produced this value, don't re-map it.
    norm = raw_mac.strip().upper()
    if norm in (v.upper() for v in smap.mac.values()):
        return norm

    key = _hash_key("mac", raw_mac.lower())
    if key in smap.mac:
        return smap.mac[key]
    smap.mac[key] = _rand_mac("02:00:00")
    return smap.mac[key]


def map_bssid(raw_bssid: str, smap: SanitizeMap) -> str:
    """Map a raw BSSID to a stable sanitized BSSID.

    Args:
        raw_bssid: Raw BSSID.
        smap: Persistent mapping.

    Returns:
        Sanitized BSSID.
    """
    # Idempotence: if we already produced this value, don't re-map it.
    norm = raw_bssid.strip().upper()
    if norm in (v.upper() for v in smap.bssid.values()):
        return norm

    key = _hash_key("bssid", raw_bssid.lower())
    if key in smap.bssid:
        return smap.bssid[key]
    smap.bssid[key] = _rand_mac("02:00:01")
    return smap.bssid[key]


def map_ip_address(raw_ip: str, smap: SanitizeMap) -> str:
    """Map a raw IP address to a stable sanitized IP (10.0.0.x).

    Args:
        raw_ip: Raw IPv4 address string.
        smap: Persistent mapping.

    Returns:
        Sanitized IPv4 address string.
    """
    # If the caller accidentally passes an already-sanitized IP (e.g. from a prior run),
    # keep mapping idempotent and avoid polluting the sanitize map with synthetic values.
    norm = raw_ip.strip()
    if re.fullmatch(r"10\.0\.0\.(?:[0-9]{1,3})", norm):
        return norm

    # Idempotence: if we already produced this value, don't re-map it.
    if norm in smap.ip_address.values():
        return norm

    key = _hash_key("ip_address", norm)
    if key in smap.ip_address:
        return smap.ip_address[key]
    host = smap.next_ip_host
    smap.next_ip_host += 1
    smap.ip_address[key] = f"10.0.0.{host}"
    return smap.ip_address[key]


def map_ssid(raw_ssid: str, smap: SanitizeMap) -> str:
    """Return the constant sanitized SSID.

    WiFi scan payloads may include many nearby SSIDs; we intentionally do not preserve
    uniqueness to avoid growing the mapping file.

    Args:
        raw_ssid: Raw SSID (ignored).
        smap: Persistent mapping (unused).

    Returns:
        Constant sanitized SSID.
    """
    _ = raw_ssid
    __ = smap
    return SANITIZED_SSID


def stable_device_uuid(raw_hwid: str) -> str:
    """Return a deterministic UUID derived from a device identifier.

    Args:
        raw_hwid: Device identifier used as the seed.

    Returns:
        Deterministic UUID string.
    """
    h = hashlib.sha256()
    h.update(b"device_uuid\x00")
    h.update(raw_hwid.lower().encode("utf-8", errors="replace"))
    b = bytearray(h.digest()[:16])
    # Set RFC4122 variant and a stable UUID version nibble.
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def map_serial_code(raw_code: str, smap: SanitizeMap) -> str:
    """Map a raw serial code to a stable sanitized serial-like value.

    Args:
        raw_code: Raw serial code.
        smap: Persistent mapping.

    Returns:
        Sanitized serial code.
    """
    key = _hash_key("serial_code", raw_code)
    if key in smap.serial_code:
        return smap.serial_code[key]
    # Preserve the 'cf' prefix pattern if present.
    prefix = "cf" if raw_code.lower().startswith("cf") else "sc"
    smap.serial_code[key] = f"{prefix}{_rand_hex(7)}"
    return smap.serial_code[key]


# =============================================================================
# Types / Data
# =============================================================================


@dataclass(frozen=True)
class DeviceIdentity:
    hwid: str
    name: str


# =============================================================================
# Helpers: env
# =============================================================================


def load_dotenv_simple(dotenv_path: Path) -> dict[str, str]:
    """Load a simple `.env` file.

    Args:
        dotenv_path: Path to the `.env` file.

    Returns:
        Mapping of keys to values. Missing files return an empty dict.
    """
    if not dotenv_path.exists():
        return {}

    env: dict[str, str] = {}
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            env[key] = val
    return env


# =============================================================================
# Helpers: scan (LAN + optional cloud)
# =============================================================================


def _as_str(val: Any) -> str:
    """Convert an arbitrary value into a printable string.

    Args:
        val: Any value.

    Returns:
        Empty string for ``None``, otherwise a string representation.
    """
    if val is None:
        return ""
    return val if isinstance(val, str) else str(val)


def print_devices_table(rows: list[dict[str, Any]]) -> None:
    """Print a human-readable device table.

    Supports both cloud-style rows (``aquarium_name``, ``ip_address``, etc.) and LAN
    scan rows (``aquarium``, ``ip``, etc.).

    Args:
        rows: List of row dictionaries.

    Returns:
        None
    """
    table: list[tuple[str, str, str, str, str, str, str]] = []
    for r in rows:
        source = _as_str(r.get("_source"))
        if not source:
            if "ip_address" in r or "aquarium_name" in r:
                source = "CLOUD"
            elif "ip" in r:
                source = "LAN"

        aquarium = _as_str(r.get("aquarium") or r.get("aquarium_name"))
        device = _as_str(r.get("device") or r.get("name"))
        dtype = _as_str(r.get("type"))
        ip = _as_str(r.get("ip") or r.get("ip_address"))
        model = _as_str(r.get("model"))
        fw = _as_str(r.get("fw") or r.get("firmware_version"))
        table.append((source, aquarium, device, dtype, ip, model, fw))

    table.sort(key=lambda t: (t[1].lower(), t[3].lower(), t[2].lower(), t[4]))

    headers = ("From", "Aquarium", "Device", "Type", "IP", "Model", "FW")
    widths = [len(h) for h in headers]
    for row in table:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(val))

    def fmt_row(row: tuple[str, ...]) -> str:
        return "  ".join(val.ljust(widths[i]) for i, val in enumerate(row))

    print(fmt_row(headers))
    print("  ".join("-" * w for w in widths))
    for row in table:
        print(fmt_row(row))


def cloud_list_devices(username: str, password: str, *, timeout_s: int) -> list[dict[str, Any]]:
    """List devices from the ReefBeat cloud.

    Args:
        username: Cloud username.
        password: Cloud password.
        timeout_s: HTTP timeout seconds.

    Returns:
        List of cloud device dicts, each enriched with an aquarium name when possible.
    """
    token = cloud_auth_token(username, password, timeout=timeout_s)
    if not token:
        return []

    aquariums_any = cloud_get_json("/aquarium", token, timeout=timeout_s)
    devices_any = cloud_get_json("/device", token, timeout=timeout_s)

    aq_name_by_id: dict[str, str] = {}
    if isinstance(aquariums_any, list):
        for aq_any in cast(list[Any], aquariums_any):
            if not isinstance(aq_any, dict):
                continue
            aq = cast(dict[str, Any], aq_any)
            aq_id = aq.get("id")
            aq_name = aq.get("name")
            if aq_id is not None and isinstance(aq_name, str):
                aq_name_by_id[str(aq_id)] = aq_name

    out: list[dict[str, Any]] = []
    if isinstance(devices_any, list):
        for dev_any in cast(list[Any], devices_any):
            if not isinstance(dev_any, dict):
                continue
            dev = cast(dict[str, Any], dev_any)
            aq_id = dev.get("aquarium_id")
            row = dict(dev)
            row["_source"] = "CLOUD"
            if aq_id is not None:
                row["aquarium_name"] = aq_name_by_id.get(str(aq_id), "")
            out.append(row)
    return out


def _safe_json_loads(raw: bytes) -> Any:
    """Parse JSON bytes safely.

    Args:
        raw: Raw bytes from an HTTP response.

    Returns:
        Parsed JSON value, or ``None`` if parsing fails.
    """
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


def _normalize_fw(val: Any) -> str:
    """Normalize a firmware version field to a string.

    Args:
        val: Raw firmware version value.

    Returns:
        Firmware version string.
    """
    if isinstance(val, str):
        return val
    if val is None:
        return ""
    return str(val)


def scan_network_for_devices(
    cidr: str,
    *,
    timeout_s: float = HTTP_TIMEOUT_SECS_DEFAULT,
    workers: int = 128,
    max_hosts: int = 4096,
    allow_large: bool = False,
) -> list[dict[str, str]]:
    """Scan a CIDR and return detected ReefBeat devices.

    This probes ``/device-info`` on each host in the CIDR.

    Args:
        cidr: CIDR string to scan.
        timeout_s: Per-host HTTP timeout.
        workers: Thread pool size.
        max_hosts: Refuse scanning networks larger than this many hosts unless overridden.
        allow_large: If True, allow scanning very large networks.

    Returns:
        List of device rows, one per detected host.

    Raises:
        ValueError: If the CIDR is larger than ``max_hosts`` and ``allow_large`` is False.
    """

    net = ipaddress.ip_network(cidr, strict=False)
    # Guard against accidentally scanning huge networks (docker /16, etc.).
    host_count = int(max(0, net.num_addresses - 2)) if getattr(net, "version", 4) == 4 else int(net.num_addresses)
    if host_count > max_hosts and not allow_large:
        raise ValueError(
            f"Refusing to scan {net} ({host_count} hosts). "
            f"Pass --scan-max-hosts {host_count} or --scan-allow-large to override."
        )

    ips_iter = (str(ip) for ip in net.hosts())

    def probe_one(ip: str) -> dict[str, str] | None:
        try:
            raw = fetch_url_http(ip, "/device-info", timeout=timeout_s)
            if not raw:
                return None

            payload_any = _safe_json_loads(raw)
            if not isinstance(payload_any, dict):
                return None

            payload = cast(dict[str, Any], payload_any)
            name = payload.get("name")
            hwid = payload.get("hwid")
            model = payload.get("model")
            fw = payload.get("firmware_version")
            dtype = payload.get("type")

            if not isinstance(name, str) or not name:
                return None
            if not isinstance(hwid, str) or not hwid:
                return None

            return {
                "_source": "LAN",
                "aquarium": "",
                "device": name,
                "type": str(dtype or ""),
                "ip": ip,
                "model": str(model or ""),
                "fw": _normalize_fw(fw),
                "hwid": hwid,
            }
        except Exception:
            return None

    found: list[dict[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for res in ex.map(probe_one, ips_iter, chunksize=32):
            if res:
                found.append(res)
    return found


def scan_network_for_devices_multi(
    cidrs: list[str],
    *,
    timeout_s: float,
    workers: int,
    max_hosts: int,
    allow_large: bool,
) -> list[dict[str, str]]:
    """Scan multiple CIDRs and return a de-duplicated device list.

    Args:
        cidrs: List of CIDRs to scan.
        timeout_s: Per-request timeout.
        workers: Thread pool size used for each CIDR.
        max_hosts: Refuse scanning CIDRs larger than this, unless overridden.
        allow_large: Allow scanning very large CIDRs.

    Returns:
        A list of device rows (one per unique IP).
    """
    by_ip: dict[str, dict[str, str]] = {}
    for cidr in cidrs:
        found = scan_network_for_devices(
            cidr,
            timeout_s=timeout_s,
            workers=workers,
            max_hosts=max_hosts,
            allow_large=allow_large,
        )
        for row in found:
            ip = row.get("ip") or ""
            if ip and ip not in by_ip:
                by_ip[ip] = row
    return list(by_ip.values())


def build_scan_parser() -> argparse.ArgumentParser:
    """Build an argument parser for the `scan` subcommand.

    Returns:
        Configured argument parser.
    """
    p = argparse.ArgumentParser(
        prog="run.py scan",
        description=(
            "Scan for ReefBeat devices and print a table. "
            "If --cidr is omitted, this uses the cloud (fast) and therefore requires creds."
        ),
    )
    p.add_argument(
        "--cidr",
        action="append",
        help="CIDR to LAN-scan (repeatable). If omitted, use cloud listing (requires creds).",
    )
    p.add_argument(
        "--scan-workers",
        type=int,
        default=128,
        help="Concurrent workers (default: 128)",
    )
    p.add_argument(
        "--scan-timeout",
        type=float,
        default=HTTP_TIMEOUT_SECS_DEFAULT,
        help=f"LAN scan timeout seconds for /device-info (default: {HTTP_TIMEOUT_SECS_DEFAULT})",
    )
    p.add_argument(
        "--scan-max-hosts",
        type=int,
        default=4096,
        help="Refuse to LAN-scan CIDRs larger than this many hosts (default: 4096)",
    )
    p.add_argument(
        "--scan-allow-large",
        action="store_true",
        help="Allow scanning very large CIDRs (use with care)",
    )
    p.add_argument("--username", help=f"Cloud username (optional; overrides .env {ENV_USERNAME})")
    p.add_argument("--password", help=f"Cloud password (optional; overrides .env {ENV_PASSWORD})")
    p.add_argument(
        "--timeout",
        type=int,
        default=HTTP_TIMEOUT_SECS_DEFAULT,
        help=f"Cloud HTTP timeout seconds (default: {HTTP_TIMEOUT_SECS_DEFAULT})",
    )
    p.add_argument(
        "--no-cloud",
        action="store_true",
        help="Do not call the cloud (disables cloud listing + enrichment)",
    )
    return p


def cmd_scan(argv: list[str]) -> int:
    """Entry point for `python run.py scan ...`.

    Args:
        argv: Argument list excluding the leading `scan` token.

    Returns:
        Process-style exit code (0 success, non-zero on user/IO errors).
    """
    p = build_scan_parser()
    args = p.parse_args(argv)

    cidrs = list(args.cidr or [])
    creds = None if args.no_cloud else resolve_cloud_creds(args.username, args.password, Path(".env"))

    if not cidrs:
        if not creds:
            logger.info("Provide --cidr for LAN scan, or set cloud creds in .env / --username/--password")
            return 2
        logger.info("Cloud listing (from cloud; does not probe LAN)")
        devices = cloud_list_devices(creds[0], creds[1], timeout_s=int(args.timeout))
        print_devices_table(devices)
        return 0

    logger.info(f"LAN scanning {', '.join(cidrs)}...")
    try:
        rows = scan_network_for_devices_multi(
            cidrs,
            timeout_s=float(args.scan_timeout),
            workers=int(args.scan_workers),
            max_hosts=int(args.scan_max_hosts),
            allow_large=bool(args.scan_allow_large),
        )
    except ValueError as e:
        logger.info(str(e))
        return 2

    if creds:
        logger.info("Enriching scan results from cloud...")
        enrich_devices_from_cloud(rows, username=creds[0], password=creds[1], timeout_s=int(args.timeout))

    print_devices_table(rows)
    return 0


def enrich_devices_from_cloud(
    devices: list[dict[str, str]],
    *,
    username: str,
    password: str,
    timeout_s: int,
) -> None:
    """Enrich scanned device rows with cloud metadata.

    Args:
        devices: Device rows to mutate in-place.
        username: Cloud username.
        password: Cloud password.
        timeout_s: HTTP timeout seconds.

    Returns:
        None
    """
    token = cloud_auth_token(username, password, timeout=timeout_s)
    if not token:
        return

    aquariums_any = cloud_get_json("/aquarium", token, timeout=timeout_s)
    devices_any = cloud_get_json("/device", token, timeout=timeout_s)

    aq_name_by_id: dict[str, str] = {}
    if isinstance(aquariums_any, list):
        aquariums_list = cast(list[Any], aquariums_any)
        for aq_any in aquariums_list:
            if isinstance(aq_any, dict):
                aq = cast(dict[str, Any], aq_any)
                aq_id: Any = aq.get("id")
                aq_name: Any = aq.get("name")
                if aq_id is not None and isinstance(aq_name, str):
                    aq_name_by_id[str(aq_id)] = aq_name

    cloud_by_ip: dict[str, dict[str, Any]] = {}
    if isinstance(devices_any, list):
        devices_list = cast(list[Any], devices_any)
        for dev_any in devices_list:
            if not isinstance(dev_any, dict):
                continue
            d = cast(dict[str, Any], dev_any)
            ip: Any = d.get("ip_address")
            if isinstance(ip, str) and ip:
                cloud_by_ip[ip] = d

    for row in devices:
        ip = row.get("ip") or ""
        cloud = cloud_by_ip.get(ip)
        if not cloud:
            continue

        row["_source"] = "LAN+CLOUD"
        name = cloud.get("name")
        dtype = cloud.get("type")
        model = cloud.get("model")
        fw = cloud.get("firmware_version")
        aq_id = cloud.get("aquarium_id")

        if isinstance(name, str) and name:
            row["device"] = name
        if isinstance(dtype, str) and dtype:
            row["type"] = dtype
        if isinstance(model, str) and model:
            row["model"] = model
        if fw is not None:
            row["fw"] = _normalize_fw(fw)
        if aq_id is not None:
            row["aquarium"] = aq_name_by_id.get(str(aq_id), row.get("aquarium", ""))


# =============================================================================
# Helpers: local device snapshot
# =============================================================================


def format_xml_bytes(data: bytes) -> bytes:
    """Pretty-format XML bytes.

    Args:
        data: Raw XML bytes.

    Returns:
        Pretty-formatted XML bytes (ending with a newline). If parsing fails, returns
        the original bytes.
    """
    try:
        text = data.decode("utf-8", errors="replace")
        dom = minidom.parseString(text)
        pretty = dom.toprettyxml(indent="  ", newl="\n")
        # minidom adds a bunch of blank lines; strip them for stable output
        lines = [ln for ln in pretty.splitlines() if ln.strip()]
        out = "\n".join(lines) + "\n"
        return out.encode("utf-8")
    except (ExpatError, ValueError):
        return data


def ping_host(ip: str, timeout_seconds: int = 2) -> bool:
    """Check whether a host responds to a ping.

    Args:
        ip: Target host IP.
        timeout_seconds: Ping timeout in seconds.

    Returns:
        True if the host responds, otherwise False. If `ping` is unavailable, returns
        True as a best-effort fallback.
    """
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_seconds), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return res.returncode == 0
    except FileNotFoundError:
        return True


def iter_urls(device_type: str) -> list[str]:
    """Return the endpoint list to snapshot for a device type.

    Prefers reading endpoints from an existing fixture tree (so snapshots are
    config-driven), and falls back to built-in endpoint lists.

    Args:
        device_type: Device type token (e.g. ``ATO``).

    Returns:
        List of endpoint paths.

    Raises:
        ValueError: If ``device_type`` is not supported and no fixture tree exists to
            derive endpoints from.
    """
    fixture_urls = _iter_urls_from_fixture_tree(Path("devices") / device_type)
    if fixture_urls:
        return fixture_urls

    if device_type not in TYPE_MAP:
        raise ValueError(f"Unsupported TYPE {device_type!r}. Use one of {sorted(available_device_types())}")
    return [*BASE_URLS, *TYPE_MAP[device_type]]


def dest_dir_for_url(url: str, root: Path) -> Path:
    """Convert an endpoint path into its fixture directory.

    Args:
        url: Endpoint path (e.g. ``/wifi``). The root endpoint ``/`` maps to
            ``root`` directly.
        root: Base directory for the fixture tree.

    Returns:
        Directory path where this endpoint's fixture should be written.
    """
    if url == "/":
        return root
    return root / url.lstrip("/")


def fetch_url_http(ip: str, url: str, timeout: float) -> bytes:
    """Fetch a local device endpoint and return raw bytes.

    Args:
        ip: Device IP address.
        url: Endpoint path (e.g. ``/device-info``).
        timeout: Socket timeout in seconds.

    Returns:
        Response bytes, or ``b""`` on any connection/HTTP error.
    """
    full = f"http://{ip}{url}"
    try:
        with urlopen(full, timeout=timeout) as resp:
            return resp.read()
    except (HTTPError, URLError, TimeoutError, OSError):
        return b""


def detect_device_type(ip: str, *, timeout: int) -> str:
    """Detect fixture device type from the device's ``/device-info`` endpoint.

    The devices expose both a hardware type (``hw_type``) and a model
    (``hw_model``). We map those into our fixture folder names.

    Args:
        ip: Device IP address.
        timeout: HTTP timeout in seconds.

    Returns:
        Fixture type string (e.g. ``ATO``, ``DOSE4``, ``LED``).

    Raises:
        RuntimeError: If the device-info payload is missing/invalid or cannot be mapped.
    """
    raw = fetch_url_http(ip, "/device-info", timeout=timeout)
    payload_any = _safe_json_loads(raw)
    if not isinstance(payload_any, dict):
        raise RuntimeError("Could not parse /device-info JSON")

    payload = cast(dict[str, Any], payload_any)
    hw_type = payload.get("hw_type")
    hw_model = payload.get("hw_model")

    hw_type_s = hw_type.strip().lower() if isinstance(hw_type, str) else ""
    hw_model_s = hw_model.strip().upper() if isinstance(hw_model, str) else ""

    if hw_type_s == "reef-ato":
        return "ATO"
    if hw_type_s == "reef-lights":
        return "LED"
    if hw_type_s == "reef-run":
        return "RUN"
    if hw_type_s == "reef-wave":
        return "WAVE"
    if hw_type_s == "reef-mat":
        return "MAT"

    if hw_type_s == "reef-dosing":
        if "DOSE2" in hw_model_s:
            return "DOSE2"
        if "DOSE4" in hw_model_s:
            return "DOSE4"
        return "DOSE4"

    if "DOSE2" in hw_model_s:
        return "DOSE2"
    if "DOSE4" in hw_model_s:
        return "DOSE4"
    if "ATO" in hw_model_s:
        return "ATO"
    if "LED" in hw_model_s:
        return "LED"
    if "RUN" in hw_model_s:
        return "RUN"
    if "WAVE" in hw_model_s:
        return "WAVE"
    if "MAT" in hw_model_s:
        return "MAT"

    raise RuntimeError(f"Could not detect type (hw_type={hw_type!r}, hw_model={hw_model!r})")


def format_json_bytes(data: bytes) -> bytes:
    """Pretty-format JSON bytes.

    Args:
        data: Raw bytes (usually an HTTP response body).

    Returns:
        Pretty-printed JSON bytes ending with a newline, or the original bytes if
        the payload is not valid UTF-8 JSON.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data

    try:
        obj = json.loads(text)
    except Exception:
        return data

    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _iter_urls_from_fixture_tree(type_root: Path) -> list[str]:
    """Derive endpoint URLs from an existing ``devices/<TYPE>`` fixture tree.

    This lets local snapshots follow the endpoints already captured on disk.
    Hidden directories (e.g. ``.raw``) are ignored.

    Args:
        type_root: Directory like ``devices/ATO``.

    Returns:
        A stable, de-duplicated list of endpoint paths.
    """
    urls: list[str] = []
    if not type_root.exists() or not type_root.is_dir():
        return urls

    for data_file in sorted(type_root.rglob("data")):
        if not data_file.is_file():
            continue
        rel_dir = data_file.parent.relative_to(type_root)
        if any(p.startswith(".") for p in rel_dir.parts):
            continue
        if str(rel_dir) == ".":
            urls.append("/")
        else:
            urls.append("/" + "/".join(rel_dir.parts))

    urls = sorted(set(urls), key=lambda u: (u.count("/"), u))
    return urls


def _device_types_from_config(config_path: Path) -> list[str]:
    """Best-effort parse of ``config.json`` to discover device fixture folders.

    Args:
        config_path: Path to ``config.json``.

    Returns:
        Sorted list of device type folder names referenced by the config.
    """
    try:
        obj_any: Any = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(obj_any, dict):
        return []
    obj = cast(dict[str, Any], obj_any)
    devices_any = obj.get("devices")
    if not isinstance(devices_any, list):
        return []
    out: set[str] = set()
    for dev_any in cast(list[Any], devices_any):
        if not isinstance(dev_any, dict):
            continue
        dev = cast(dict[str, Any], dev_any)
        base_url = dev.get("base_url")
        if isinstance(base_url, str) and base_url:
            out.add(Path(base_url).name)
    return sorted(out)


def available_device_types() -> list[str]:
    """Return known device fixture types.

    Sources:
        - Hardcoded type map (supported endpoint sets)
        - Existing fixture directories under ``devices/``
        - Best-effort parse of ``config.json``

    Returns:
        Sorted list of type names (e.g. ``["ATO", "DOSE4", ...]``).
    """
    out: set[str] = set(TYPE_MAP.keys())
    devices_dir = Path("devices")
    if devices_dir.exists() and devices_dir.is_dir():
        for child in devices_dir.iterdir():
            if not child.is_dir() or child.name.startswith("."):
                continue
            if (child / "device-info" / "data").exists():
                out.add(child.name)
    out.update(_device_types_from_config(Path("config.json")))
    return sorted(out)


def sanitize_local_payload(url: str, payload: JsonValue, smap: SanitizeMap) -> JsonValue:
    """Sanitize a local-device JSON payload.

    Args:
        url: Endpoint path used to apply endpoint-specific rules.
        payload: Parsed JSON payload.
        smap: Persistent mapping used for stable anonymization.

    Returns:
        Sanitized JSON payload.
    """
    if url == "/device-info" and isinstance(payload, dict):
        name_val = payload.get("name")
        if isinstance(name_val, str) and name_val:
            payload = dict(payload)
            payload["name"] = map_device_name(name_val, smap)
    return _deep_key_sanitize(_deep_redact(payload), smap)


def rewrite_local_download(
    data: bytes,
    ip: str,
    url: str,
    *,
    smap: SanitizeMap | None = None,
    device_hwid: str | None = None,
) -> bytes:
    """Rewrite a local endpoint response into a stable fixture payload.

    This performs a few stability/sanitization steps:
    - Replaces the real IP with the mapped IP in text payloads.
    - Pretty-formats JSON and applies sanitization rules when a map is provided.
    - Rewrites the UUID in ``/description.xml`` deterministically and pretty-formats XML.

    Args:
        data: Raw response bytes.
        ip: Device IP address.
        url: Endpoint path.
        smap: Optional sanitize map for stable anonymization.
        device_hwid: Optional HWID used to derive deterministic XML UUIDs.

    Returns:
        Rewritten bytes suitable for writing to the fixture tree.
    """
    if not data:
        return data

    # Avoid corrupting binary responses.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data

    if smap is not None:
        mapped_ip = map_ip_address(ip, smap)
        text = text.replace(ip, mapped_ip)

    if url == "/description.xml":
        if device_hwid:
            new_uuid = stable_device_uuid(device_hwid)
        else:
            new_uuid = stable_device_uuid(ip)
        text = _UUID_RE.sub(f"uuid:{new_uuid}", text)

        return format_xml_bytes(text.encode("utf-8"))

    try:
        obj_any: Any = json.loads(text)
    except Exception:
        return text.encode("utf-8")

    json_payload: JsonValue = cast(JsonValue, obj_any)
    if smap is not None:
        json_payload = sanitize_local_payload(url, json_payload, smap)

    return (json.dumps(json_payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def snapshot_local_device(ip: str, device_type: str, out_root: Path, timeout: int, *, save_raw: bool = False) -> None:
    """Snapshot a local device to a fixture tree.

    Args:
        ip: Device IP address.
        device_type: Device type token (e.g. ``ATO``).
        out_root: Output directory root (e.g. ``devices/ATO``).
        timeout: HTTP timeout in seconds.
        save_raw: If True, also write raw payloads under ``<out_root>/.raw``.

    Returns:
        None

    Raises:
        RuntimeError: If the host is not reachable.
    """
    if not ping_host(ip):
        raise RuntimeError(f"{ip} not alive")

    urls = iter_urls(device_type)
    # Fetch /device-info first to derive deterministic IDs for XML, etc.
    if "/device-info" in urls:
        urls = ["/device-info", *[u for u in urls if u != "/device-info"]]

    map_path = Path(SANITIZE_MAP_FILENAME)
    smap = load_sanitize_map(map_path)

    raw_root = out_root / ".raw" if save_raw else None

    old_id: DeviceIdentity | None = None

    for url in urls:
        logger.info(url)
        d = dest_dir_for_url(url, out_root)
        d.mkdir(parents=True, exist_ok=True)

        data = fetch_url_http(ip, url, timeout=timeout)

        if raw_root is not None:
            raw_dest = dest_dir_for_url(url, raw_root)
            raw_dest.mkdir(parents=True, exist_ok=True)
            raw_bytes = data
            if url == "/description.xml":
                raw_bytes = format_xml_bytes(raw_bytes)
            else:
                raw_bytes = format_json_bytes(raw_bytes)
            (raw_dest / "data").write_bytes(raw_bytes)

        if url == "/device-info" and data and old_id is None:
            payload_any = _safe_json_loads(data)
            if isinstance(payload_any, dict):
                payload = cast(dict[str, Any], payload_any)
                hwid = payload.get("hwid")
                name = payload.get("name")
                if isinstance(hwid, str) and hwid and isinstance(name, str) and name:
                    old_id = DeviceIdentity(hwid=hwid.lower(), name=name)

        data = rewrite_local_download(data, ip, url, smap=smap, device_hwid=(old_id.hwid if old_id else None))

        data_path = d / "data"
        data_path.write_bytes(data)

        # Remove empty endpoints to keep the fixture tree tight.
        if data_path.stat().st_size == 0:
            if d != out_root:
                for child in sorted(d.rglob("*"), reverse=True):
                    if child.is_file():
                        child.unlink(missing_ok=True)
                    else:
                        child.rmdir()
                d.rmdir()
            else:
                data_path.unlink(missing_ok=True)

    save_sanitize_map(map_path, smap)


# =============================================================================
# Helpers: cloud sanitization
# =============================================================================


def _redact_string(value: str, *, allow_uuid: bool = True) -> str:
    """Redact PII-like patterns inside a string.

    Args:
        value: Input string.
        allow_uuid: If False, skip UUID redaction (used for linkage UUIDs that
            must remain consistent across payloads).

    Returns:
        Redacted string.
    """
    s = _EMAIL_RE.sub("user@example.com", value)
    s = _PHONE_RE.sub("+10000000000", s)
    if allow_uuid:
        s = _UUID_RE.sub("uuid:00000000-0000-0000-0000-000000000000", s)
        s = _RAW_UUID_RE.sub("00000000-0000-0000-0000-000000000000", s)
    return s


def _deep_redact(value: JsonValue, path: tuple[str, ...] = ()) -> JsonValue:
    """Recursively redact strings in a JSON-like structure.

    Args:
        value: JSON-like input.
        path: Key path used to enforce special-case invariants.

    Returns:
        Redacted JSON-like output.
    """
    if isinstance(value, dict):
        return {k: _deep_redact(v, path + (k,)) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_redact(v, path) for v in value]
    if isinstance(value, str):
        redact_uuid = True

        # Invariant: supplement.uid must remain unchanged.
        if len(path) >= 2 and path[-2] == "supplement" and path[-1] == "uid":
            redact_uuid = False

        # Invariant: preserve linkage UUIDs so relationships remain consistent.
        if path and path[-1] in {"uid", "user_uid", "aquarium_uid"}:
            redact_uuid = False

        return _redact_string(value, allow_uuid=redact_uuid)
    return value


def _deep_key_sanitize(value: JsonValue, smap: SanitizeMap) -> JsonValue:
    """Key-aware sanitization for known fields across arbitrary payloads.

    Args:
        value: JSON-like input.
        smap: Persistent mapping used for stable anonymization.

    Returns:
        Sanitized JSON-like output.
    """
    if isinstance(value, list):
        return [_deep_key_sanitize(v, smap) for v in value]
    if isinstance(value, dict):
        out: JsonObject = {}
        for k, v in value.items():
            # Never keep API keys/secrets in fixtures (even partially masked).
            k_lower = k.lower()
            if k_lower in {
                "api_key",
                "api_secret",
                "secret",
                "client_secret",
                "access_token",
                "refresh_token",
                "token",
            }:
                out[k] = SANITIZED_SECRET
                continue

            # Keep local WiFi gateway consistent with the sanitized subnet.
            if k in {"gateway", "gateway_ip", "default_gateway"}:
                out[k] = SANITIZED_GATEWAY
                continue

            if k in {"mac", "bssid"}:
                if isinstance(v, str) and v:
                    out[k] = map_mac(v, smap) if k == "mac" else map_bssid(v, smap)
                else:
                    out[k] = SANITIZED_MAC if k == "mac" else SANITIZED_BSSID
                continue
            if k == "ip_address":
                out[k] = map_ip_address(v, smap) if isinstance(v, str) and v else SANITIZED_IP_ADDRESS
                continue
            if k == "ssid":
                out[k] = map_ssid(v, smap) if isinstance(v, str) and v else SANITIZED_SSID
                continue
            if k == "hwid":
                out[k] = map_device_hwid(v, smap) if isinstance(v, str) and v else SANITIZED_HWID
                continue
            if k == "serial_code":
                out[k] = map_serial_code(v, smap) if isinstance(v, str) and v else SANITIZED_SERIAL_CODE
                continue
            out[k] = _deep_key_sanitize(v, smap)
        return out
    return value


def _sanitize_cloud_aquarium(payload: JsonValue, smap: SanitizeMap) -> JsonValue:
    """Sanitize a `/aquarium` payload while preserving internal relationships.

    Args:
        payload: Raw parsed payload.
        smap: Persistent mapping.

    Returns:
        Sanitized payload.
    """
    if isinstance(payload, list):
        out_list: JsonArray = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            obj_in = item
            obj: JsonObject = dict(obj_in)
            raw_id = obj_in.get("id")
            raw_uid = obj_in.get("uid")
            raw_user_uid = obj_in.get("user_uid")
            if isinstance(raw_id, int):
                mapped_id = map_aquarium_id(raw_id, smap)
            else:
                mapped_id = SANITIZED_AQUARIUM_ID
            obj["id"] = mapped_id
            if isinstance(raw_uid, str) and raw_uid:
                obj["uid"] = map_aquarium_uid(raw_uid, smap)
            else:
                obj["uid"] = SANITIZED_AQUARIUM_UID
            if isinstance(raw_user_uid, str) and raw_user_uid:
                obj["user_uid"] = map_user_uid(raw_user_uid, smap)
            else:
                obj["user_uid"] = cast(str, SANITIZED_USER["uid"])
            obj["name"] = f"{SANITIZED_AQUARIUM_NAME} {max(1, int(mapped_id) - (SANITIZED_AQUARIUM_ID - 1))}"
            obj["system_model"] = SANITIZED_SYSTEM_MODEL
            out_list.append(_deep_key_sanitize(_deep_redact(obj), smap))
        return out_list

    if isinstance(payload, dict):
        obj2 = dict(payload)
        obj = dict(obj2)
        raw_id2 = obj2.get("id")
        raw_uid2 = obj2.get("uid")
        raw_user_uid2 = obj2.get("user_uid")
        if isinstance(raw_id2, int):
            mapped_id2 = map_aquarium_id(raw_id2, smap)
        else:
            mapped_id2 = SANITIZED_AQUARIUM_ID
        obj["id"] = mapped_id2
        if isinstance(raw_uid2, str) and raw_uid2:
            obj["uid"] = map_aquarium_uid(raw_uid2, smap)
        else:
            obj["uid"] = SANITIZED_AQUARIUM_UID
        if isinstance(raw_user_uid2, str) and raw_user_uid2:
            obj["user_uid"] = map_user_uid(raw_user_uid2, smap)
        else:
            obj["user_uid"] = cast(str, SANITIZED_USER["uid"])
        obj["name"] = f"{SANITIZED_AQUARIUM_NAME} {max(1, int(mapped_id2) - (SANITIZED_AQUARIUM_ID - 1))}"
        obj["system_model"] = SANITIZED_SYSTEM_MODEL
        return _deep_key_sanitize(_deep_redact(cast(JsonValue, obj)), smap)

    return payload


def _sanitize_cloud_device(payload: JsonValue, smap: SanitizeMap) -> JsonValue:
    """Sanitize a `/device` payload while preserving aquarium linkage.

    Args:
        payload: Raw parsed payload.
        smap: Persistent mapping.

    Returns:
        Sanitized payload.
    """
    if isinstance(payload, list):
        out_list2: JsonArray = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            obj_in = item
            obj: JsonObject = dict(obj_in)
            raw_name = obj_in.get("name")
            if isinstance(raw_name, str) and raw_name:
                obj["name"] = map_device_name(raw_name, smap)
            raw_aq_id = obj_in.get("aquarium_id")
            raw_aq_uid = obj_in.get("aquarium_uid")
            if isinstance(raw_aq_id, int):
                obj["aquarium_id"] = map_aquarium_id(raw_aq_id, smap)
            else:
                obj["aquarium_id"] = SANITIZED_AQUARIUM_ID
            if isinstance(raw_aq_uid, str) and raw_aq_uid:
                obj["aquarium_uid"] = map_aquarium_uid(raw_aq_uid, smap)
            else:
                obj["aquarium_uid"] = SANITIZED_AQUARIUM_UID
            bssid = obj_in.get("bssid")
            hwid = obj_in.get("hwid")
            ip_addr = obj_in.get("ip_address")
            mac = obj_in.get("mac")
            ssid = obj_in.get("ssid")

            obj["bssid"] = map_bssid(bssid, smap) if isinstance(bssid, str) and bssid else SANITIZED_BSSID
            obj["hwid"] = map_device_hwid(hwid, smap) if isinstance(hwid, str) and hwid else SANITIZED_HWID
            obj["ip_address"] = (
                map_ip_address(ip_addr, smap) if isinstance(ip_addr, str) and ip_addr else SANITIZED_IP_ADDRESS
            )
            obj["mac"] = map_mac(mac, smap) if isinstance(mac, str) and mac else SANITIZED_MAC
            obj["ssid"] = map_ssid(ssid, smap) if isinstance(ssid, str) and ssid else SANITIZED_SSID
            out_list2.append(_deep_key_sanitize(_deep_redact(obj), smap))
        return out_list2

    if isinstance(payload, dict):
        obj_in2 = payload
        obj = dict(obj_in2)
        raw_name2 = obj_in2.get("name")
        if isinstance(raw_name2, str) and raw_name2:
            obj["name"] = map_device_name(raw_name2, smap)
        raw_aq_id2 = obj_in2.get("aquarium_id")
        raw_aq_uid2 = obj_in2.get("aquarium_uid")
        if isinstance(raw_aq_id2, int):
            obj["aquarium_id"] = map_aquarium_id(raw_aq_id2, smap)
        else:
            obj["aquarium_id"] = SANITIZED_AQUARIUM_ID
        if isinstance(raw_aq_uid2, str) and raw_aq_uid2:
            obj["aquarium_uid"] = map_aquarium_uid(raw_aq_uid2, smap)
        else:
            obj["aquarium_uid"] = SANITIZED_AQUARIUM_UID

        bssid2 = obj_in2.get("bssid")
        hwid2 = obj_in2.get("hwid")
        ip_addr2 = obj_in2.get("ip_address")
        mac2 = obj_in2.get("mac")
        ssid2 = obj_in2.get("ssid")

        obj["bssid"] = map_bssid(bssid2, smap) if isinstance(bssid2, str) and bssid2 else SANITIZED_BSSID
        obj["hwid"] = map_device_hwid(hwid2, smap) if isinstance(hwid2, str) and hwid2 else SANITIZED_HWID
        obj["ip_address"] = (
            map_ip_address(ip_addr2, smap) if isinstance(ip_addr2, str) and ip_addr2 else SANITIZED_IP_ADDRESS
        )
        obj["mac"] = map_mac(mac2, smap) if isinstance(mac2, str) and mac2 else SANITIZED_MAC
        obj["ssid"] = map_ssid(ssid2, smap) if isinstance(ssid2, str) and ssid2 else SANITIZED_SSID

        return _deep_key_sanitize(_deep_redact(cast(JsonValue, obj)), smap)

    return payload


def sanitize_cloud_payload(path: str, payload: JsonValue, smap: SanitizeMap) -> JsonValue:
    """Sanitize a cloud payload.

    Args:
        path: Cloud endpoint path (e.g. ``/device``).
        payload: Parsed JSON payload.
        smap: Persistent mapping used for stable anonymization.

    Returns:
        Sanitized payload.
    """
    if path == "/user":
        out = dict(SANITIZED_USER)
        if isinstance(payload, dict):
            raw_uid = payload.get("uid")
            if isinstance(raw_uid, str) and raw_uid:
                out["uid"] = map_user_uid(raw_uid, smap)
        return out

    if path == "/aquarium":
        return _sanitize_cloud_aquarium(payload, smap)

    if path == "/device":
        return _sanitize_cloud_device(payload, smap)

    return _deep_key_sanitize(_deep_redact(payload), smap)


# =============================================================================
# Helpers: cloud snapshot
# =============================================================================


def http_request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = HTTP_TIMEOUT_SECS_DEFAULT,
) -> tuple[int, bytes]:
    """Perform an HTTP request with urllib.

    Args:
        method: HTTP method (e.g. ``GET``).
        url: Absolute URL.
        headers: Optional request headers.
        body: Optional request body.
        timeout: Socket timeout seconds.

    Returns:
        Tuple of ``(status_code, response_bytes)``. On connection errors, returns
        ``(0, b"")``.
    """
    req = Request(url=url, method=method.upper(), data=body)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    try:
        with urlopen(req, timeout=timeout) as resp:
            status = int(getattr(resp, "status", 200))
            return status, resp.read()
    except URLError as e:
        # urllib wraps status in HTTPError, which is a URLError subclass that is also file-like
        # Keep it simple and return 0 for "no status / connect error"
        _ = e
        return 0, b""


def cloud_auth_token(username: str, password: str, timeout: int) -> str | None:
    """Authenticate to the ReefBeat cloud and return an access token.

    Args:
        username: Cloud username.
        password: Cloud password.
        timeout: HTTP timeout seconds.

    Returns:
        Access token string, or ``None`` on auth/error.
    """
    url = f"https://{CLOUD_SERVER_ADDR}/oauth/token"

    headers = {
        "Authorization": CLOUD_BASIC_AUTH,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    body = urlencode(
        {
            "grant_type": "password",
            "username": username,
            "password": password,
        }
    ).encode("utf-8")

    status, raw = http_request("POST", url, headers=headers, body=body, timeout=timeout)
    if status != 200 or not raw:
        return None

    try:
        payload_any: Any = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None

    if not isinstance(payload_any, dict):
        return None

    payload = cast(dict[str, Any], payload_any)
    token_val: Any = payload.get("access_token")
    return token_val if isinstance(token_val, str) and token_val else None


def cloud_get_json(path: str, token: str, timeout: int) -> Any:
    """GET a cloud endpoint and parse JSON.

    Args:
        path: Cloud API path (e.g. ``/device``).
        token: Bearer token.
        timeout: HTTP timeout seconds.

    Returns:
        Parsed JSON, or an empty dict on errors.
    """
    url = f"https://{CLOUD_SERVER_ADDR}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    status, raw = http_request("GET", url, headers=headers, timeout=timeout)
    if status != 200 or not raw:
        return {}

    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}


def cloud_get_raw(path: str, token: str, timeout: int) -> tuple[int, bytes]:
    """GET a cloud endpoint and return raw bytes.

    Args:
        path: Cloud API path.
        token: Bearer token.
        timeout: HTTP timeout seconds.

    Returns:
        ``(status_code, response_bytes)``.
    """
    url = f"https://{CLOUD_SERVER_ADDR}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    return http_request("GET", url, headers=headers, timeout=timeout)


def resolve_cloud_creds(
    cli_username: str | None,
    cli_password: str | None,
    dotenv_path: Path,
) -> tuple[str, str] | None:
    """Resolve cloud credentials from CLI args or a `.env` file.

    Args:
        cli_username: Username passed via CLI.
        cli_password: Password passed via CLI.
        dotenv_path: Path to a `.env` file.

    Returns:
        ``(username, password)`` if found, otherwise ``None``.
    """
    if cli_username and cli_password:
        return cli_username, cli_password

    env = load_dotenv_simple(dotenv_path)
    username = env.get(ENV_USERNAME) or ""
    password = env.get(ENV_PASSWORD) or ""
    if username and password:
        return username, password
    return None


def snapshot_cloud(out_root: Path, timeout: int, username: str, password: str, *, save_raw: bool = False) -> bool:
    """Export cloud endpoints into a fixture tree.

    Args:
        out_root: Output directory (e.g. ``devices/CLOUD``).
        timeout: HTTP timeout seconds.
        username: Cloud username.
        password: Cloud password.
        save_raw: If True, also write raw payloads under ``<out_root>/.raw``.

    Returns:
        True on success, False if authentication fails.
    """
    logger.info("Authenticating to ReefBeat cloud...")
    token = cloud_auth_token(username, password, timeout=timeout)
    if not token:
        logger.info("Cloud auth failed.")
        return False

    out_root.mkdir(parents=True, exist_ok=True)

    map_path = Path(SANITIZE_MAP_FILENAME)
    smap = load_sanitize_map(map_path)

    raw_root = out_root / ".raw" if save_raw else None

    logger.info("Exporting cloud endpoints...")
    for path in CLOUD_URLS:
        logger.info(path)
        status, raw_bytes = cloud_get_raw(path, token, timeout=timeout)
        payload: Any = {}
        if status == 200 and raw_bytes:
            try:
                payload = json.loads(raw_bytes.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                payload = {}

        dest = dest_dir_for_url(path, out_root)
        dest.mkdir(parents=True, exist_ok=True)

        if raw_root is not None:
            raw_dest = dest_dir_for_url(path, raw_root)
            raw_dest.mkdir(parents=True, exist_ok=True)
            (raw_dest / "data").write_bytes(format_json_bytes(raw_bytes))

        json_payload: JsonValue = cast(JsonValue, payload)
        sanitized: JsonValue = sanitize_cloud_payload(path, json_payload, smap)

        (dest / "data").write_text(
            json.dumps(sanitized, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    save_sanitize_map(map_path, smap)

    meta: dict[str, Any] = {"exported_at": int(time.time()), "server": CLOUD_SERVER_ADDR, "endpoints": CLOUD_URLS}
    (out_root / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return True


def infer_out_dir(out_root: Path, device_type: str | None, cloud: bool) -> Path:
    """Infer the output directory based on CLI flags.

    Args:
        out_root: Base output directory.
        device_type: Device type for local snapshots.
        cloud: Whether this is a cloud export.

    Returns:
        Output directory path.

    Raises:
        ValueError: If `cloud` is False and `device_type` is not provided.
    """
    if cloud:
        return out_root / "CLOUD"
    if not device_type:
        raise ValueError("device_type is required unless cloud=True")
    return out_root / device_type


# =============================================================================
# CLI
# =============================================================================


def main() -> int:
    """CLI entry point.

    Returns:
        Process-style exit code.
    """
    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        return cmd_scan(sys.argv[2:])

    ap = argparse.ArgumentParser(description="Create simulator fixture tree from a ReefBeat device (+ optional cloud).")
    ap.add_argument("--ip", help="Device IP address (required unless --cloud)")
    ap.add_argument(
        "--type",
        choices=available_device_types(),
        help="Device type (optional; auto-detected from /device-info when omitted)",
    )
    ap.add_argument("--cloud", action="store_true", help="Only export cloud data (skip local)")
    ap.add_argument("--out-root", default="devices", help="Base output directory (default: ./devices)")
    ap.add_argument("--username", help=f"Cloud username (optional; overrides .env {ENV_USERNAME})")
    ap.add_argument("--password", help=f"Cloud password (optional; overrides .env {ENV_PASSWORD})")
    ap.add_argument(
        "--timeout",
        type=int,
        default=HTTP_TIMEOUT_SECS_DEFAULT,
        help=f"HTTP timeout seconds (default: {HTTP_TIMEOUT_SECS_DEFAULT})",
    )
    ap.add_argument(
        "--save-raw",
        action="store_true",
        help="Also save raw (unsanitized) endpoint payloads under <out>/.raw (recommended to gitignore)",
    )
    args = ap.parse_args()

    out_root = Path(args.out_root).resolve()

    if args.cloud:
        out_dir = infer_out_dir(out_root, None, cloud=True)
        out_dir.mkdir(parents=True, exist_ok=True)
        creds = resolve_cloud_creds(args.username, args.password, Path(".env"))
        if not creds:
            logger.info(
                "No cloud credentials provided (use --username/--password or .env). Cloud requested; nothing to do."
            )
            return 2
        snapshot_cloud(
            out_dir,
            timeout=int(args.timeout),
            username=creds[0],
            password=creds[1],
            save_raw=bool(args.save_raw),
        )
        return 0

    if not args.ip:
        logger.info("Missing --ip (required unless --cloud).")
        return 2

    device_type = args.type
    if not device_type:
        try:
            device_type = detect_device_type(args.ip, timeout=int(args.timeout))
        except Exception as e:
            logger.info(f"Could not detect device type from {args.ip}: {e}")
            return 2
        logger.info(f"Detected device type: {device_type}")

    out_dir = infer_out_dir(out_root, device_type, cloud=False)
    out_dir.mkdir(parents=True, exist_ok=True)

    snapshot_local_device(args.ip, device_type, out_dir, timeout=int(args.timeout), save_raw=bool(args.save_raw))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
