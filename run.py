#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import logging
import random
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterable, Mapping, Union, cast
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
    # fmt = "%(log_color)s%(levelname)s:%(name)s:%(message)s"

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
root.handlers[:] = []  # optional: clear existing handlers
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

# Aquarium naming can contain personal context; keep it generic
SANITIZED_AQUARIUM_NAME: Final[str] = "Aquarium"
SANITIZED_SYSTEM_MODEL: Final[str] = "Aquarium System"

# Hidden, local-only mapping used to keep sanitized IDs stable/unique across runs.
# Add this filename to your .gitignore.
SANITIZE_MAP_FILENAME: Final[str] = ".reefbeat_sanitize_map.json"

# Already defined in your codebase; keep as-is:
_UUID_RE: Final[re.Pattern[str]] = re.compile(r"uuid:[0-9a-zA-Z\-]+")

_EMAIL_RE: Final[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE: Final[re.Pattern[str]] = re.compile(r"\+\d{7,15}")
# This catches raw UUIDs like "f4c322ba-8f16-4316-8382-5e5a0cf6c88d"
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
    directly, map keys are SHA256 digests of the original values.
    """

    # hashed-original -> sanitized
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

    # counters / allocators
    next_aquarium_id: int
    next_ip_host: int
    next_ssid_suffix: int
    next_device_suffix: int


def _hash_key(kind: str, raw: str) -> str:
    """Return a stable, non-reversible key for a raw identifier."""
    h = hashlib.sha256()
    h.update(kind.encode("utf-8"))
    h.update(b"\x00")
    h.update(raw.encode("utf-8", errors="replace"))
    return h.hexdigest()


def _sanitize_map_default() -> SanitizeMap:
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
        next_ip_host=10,  # 10.0.0.<host>
        next_ssid_suffix=1,
        next_device_suffix=1,
    )


def load_sanitize_map(path: Path) -> SanitizeMap:
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
    )


def save_sanitize_map(path: Path, smap: SanitizeMap) -> None:
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
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _alloc_fake_uuid(counter: int) -> str:
    # Stable, readable UUID-like values that remain valid UUID strings.
    return f"00000000-0000-0000-0000-{counter:012d}"[-36:]


def map_user_uid(raw_uid: str, smap: SanitizeMap) -> str:
    key = _hash_key("user_uid", raw_uid)
    if key in smap.user_uid:
        return smap.user_uid[key]
    smap.user_uid[key] = "00000000-0000-0000-0000-000000000000"
    return smap.user_uid[key]


def map_aquarium_id(raw_id: int, smap: SanitizeMap) -> int:
    key = _hash_key("aquarium_id", str(raw_id))
    if key in smap.aquarium_id:
        return smap.aquarium_id[key]
    smap.aquarium_id[key] = smap.next_aquarium_id
    smap.next_aquarium_id += 1
    return smap.aquarium_id[key]


def map_aquarium_uid(raw_uid: str, smap: SanitizeMap) -> str:
    key = _hash_key("aquarium_uid", raw_uid)
    if key in smap.aquarium_uid:
        return smap.aquarium_uid[key]
    # use counter-based fake uuid to keep uniqueness without leaking source
    fake = _alloc_fake_uuid(len(smap.aquarium_uid) + 1)
    smap.aquarium_uid[key] = fake
    return fake


def _rand_hex(n_bytes: int) -> str:
    # Not crypto, just stable-ish uniqueness.
    return "".join(f"{random.randint(0, 255):02x}" for _ in range(n_bytes))


def map_device_hwid(raw_hwid: str, smap: SanitizeMap) -> str:
    key = _hash_key("device_hwid", raw_hwid.lower())
    if key in smap.device_hwid:
        return smap.device_hwid[key]
    # ReefBeat hwid is typically 12 hex chars
    smap.device_hwid[key] = _rand_hex(6)
    return smap.device_hwid[key]


def map_device_name(raw_name: str, smap: SanitizeMap) -> str:
    key = _hash_key("device_name", raw_name)
    if key in smap.device_name:
        return smap.device_name[key]
    n = smap.next_device_suffix
    smap.next_device_suffix += 1
    smap.device_name[key] = f"DEVICE_{n}"
    return smap.device_name[key]


def _rand_mac(prefix: str | None = None) -> str:
    parts: list[str] = []
    if prefix:
        parts.extend(prefix.split(":"))
    while len(parts) < 6:
        parts.append(f"{random.randint(0, 255):02x}")
    return ":".join(parts[:6]).upper()


def map_mac(raw_mac: str, smap: SanitizeMap) -> str:
    key = _hash_key("mac", raw_mac.lower())
    if key in smap.mac:
        return smap.mac[key]
    smap.mac[key] = _rand_mac("02:00:00")
    return smap.mac[key]


def map_bssid(raw_bssid: str, smap: SanitizeMap) -> str:
    key = _hash_key("bssid", raw_bssid.lower())
    if key in smap.bssid:
        return smap.bssid[key]
    smap.bssid[key] = _rand_mac("02:00:01")
    return smap.bssid[key]


def map_ip_address(raw_ip: str, smap: SanitizeMap) -> str:
    key = _hash_key("ip_address", raw_ip)
    if key in smap.ip_address:
        return smap.ip_address[key]
    host = smap.next_ip_host
    smap.next_ip_host += 1
    # Keep it in RFC1918-ish 10.0.0.0/24
    smap.ip_address[key] = f"10.0.0.{host}"
    return smap.ip_address[key]


def map_ssid(raw_ssid: str, smap: SanitizeMap) -> str:
    key = _hash_key("ssid", raw_ssid)
    if key in smap.ssid:
        return smap.ssid[key]
    n = smap.next_ssid_suffix
    smap.next_ssid_suffix += 1
    smap.ssid[key] = f"REDACTED_SSID_{n}"
    return smap.ssid[key]


def map_serial_code(raw_code: str, smap: SanitizeMap) -> str:
    key = _hash_key("serial_code", raw_code)
    if key in smap.serial_code:
        return smap.serial_code[key]
    # preserve the 'cf' prefix pattern if present
    prefix = "cf" if raw_code.lower().startswith("cf") else "sc"
    smap.serial_code[key] = f"{prefix}{_rand_hex(7)}"  # 2 + 14 = 16 chars
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
    """Minimal .env parser (no external dependency)."""
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

# TODO scan code starts here


def _as_str(val: Any) -> str:
    if val is None:
        return ""
    return val if isinstance(val, str) else str(val)


def print_devices_table(rows: list[dict[str, Any]]) -> None:
    """Print a human-readable table of devices.

    Supports both:
    - cloud-style dicts (aquarium_name, name, type, ip_address, model, firmware_version)
    - lan-scan dicts (aquarium, device, type, ip, model, fw)
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
    """Fast device listing using the ReefBeat cloud (like cli_v3 list)."""
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


def probe_http_status(ip: str, url: str, timeout: float) -> int:
    """Return HTTP status code for a GET, or 0 on connect errors."""
    full = f"http://{ip}{url}"
    req = Request(url=full, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            return int(getattr(resp, "status", 200))
    except HTTPError as e:
        try:
            return int(getattr(e, "code", 0) or 0)
        except Exception:
            return 0
    except URLError:
        return 0


def _safe_json_loads(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


def _normalize_fw(val: Any) -> str:
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
    """Scan a CIDR and return a list of detected ReefBeat devices.

    Detection strategy:
    - GET /device-info and parse JSON
    """

    net = ipaddress.ip_network(cidr, strict=False)
    # guard against accidental huge scans (docker /16, etc.)
    host_count = int(max(0, net.num_addresses - 2)) if getattr(net, "version", 4) == 4 else int(net.num_addresses)
    if host_count > max_hosts and not allow_large:
        raise ValueError(
            f"Refusing to scan {net} ({host_count} hosts). "
            f"Pass --scan-max-hosts {host_count} or --scan-allow-large to override."
        )

    ips_iter = (str(ip) for ip in net.hosts())

    def probe_one(ip: str) -> dict[str, str] | None:
        try:
            # /device-info is the canonical endpoint on these devices
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

            # weak but practical signature
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
            # Never let a single host's bad behavior abort the scan.
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
    p = build_scan_parser()
    args = p.parse_args(argv)

    cidrs = list(args.cidr or [])
    creds = None if args.no_cloud else resolve_cloud_creds(args.username, args.password, Path(".env"))

    # No CIDR => use cloud listing (fast), but requires creds
    if not cidrs:
        if not creds:
            logger.info("Provide --cidr for LAN scan, or set cloud creds in .env / --username/--password")
            return 2
        logger.info("Cloud listing (from cloud; does not probe LAN)")
        devices = cloud_list_devices(creds[0], creds[1], timeout_s=int(args.timeout))
        print_devices_table(devices)
        return 0

    # CIDR provided => LAN scan
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
    """Mutate scanned devices in-place with aquarium/type/name/model/fw from cloud when possible."""
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

        # Prefer cloud-provided fields
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
    """Pretty-format XML bytes. If parsing fails, return original bytes."""
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
    """Return True if host responds to a single ping."""
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_seconds), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return res.returncode == 0
    except FileNotFoundError:
        # ping not available; best-effort fallback
        return True


def iter_urls(device_type: str) -> list[str]:
    fixture_urls = _iter_urls_from_fixture_tree(Path("devices") / device_type)
    if fixture_urls:
        return fixture_urls

    if device_type not in TYPE_MAP:
        raise ValueError(f"Unsupported TYPE {device_type!r}. Use one of {sorted(available_device_types())}")
    return [*BASE_URLS, *TYPE_MAP[device_type]]


def dest_dir_for_url(url: str, root: Path) -> Path:
    """Match simulator tree: '/' -> root, else root/<path-without-leading-slash>."""
    if url == "/":
        return root
    return root / url.lstrip("/")


def fetch_url_http(ip: str, url: str, timeout: float) -> bytes:
    """Fetch local device HTTP endpoint and return bytes; errors => empty bytes."""
    full = f"http://{ip}{url}"
    try:
        with urlopen(full, timeout=timeout) as resp:
            return resp.read()
    except (HTTPError, URLError, TimeoutError, OSError):
        return b""


def format_json_bytes(data: bytes) -> bytes:
    """Pretty-format JSON bytes; return original bytes if not JSON."""
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
    """Derive endpoint URLs from an existing devices/<TYPE> fixture tree."""
    urls: list[str] = []
    if not type_root.exists() or not type_root.is_dir():
        return urls

    for data_file in sorted(type_root.rglob("data")):
        if not data_file.is_file():
            continue
        rel_dir = data_file.parent.relative_to(type_root)
        if str(rel_dir) == ".":
            urls.append("/")
        else:
            urls.append("/" + "/".join(rel_dir.parts))

    # stable + human-friendly ordering
    urls = sorted(set(urls), key=lambda u: (u.count("/"), u))
    return urls


def _device_types_from_config(config_path: Path) -> list[str]:
    """Best-effort parse of config.json to discover device fixture folders."""
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
    out: set[str] = set(TYPE_MAP.keys())
    devices_dir = Path("devices")
    if devices_dir.exists() and devices_dir.is_dir():
        for child in devices_dir.iterdir():
            if not child.is_dir() or child.name.startswith("."):
                continue
            # Only treat directories that look like local-device fixtures as device types.
            if (child / "device-info" / "data").exists():
                out.add(child.name)
    out.update(_device_types_from_config(Path("config.json")))
    return sorted(out)


def sanitize_local_payload(url: str, payload: JsonValue, smap: SanitizeMap) -> JsonValue:
    """Sanitize local-device payloads using the same mapping strategy as cloud."""
    # Device name is often a serial-like value; sanitize it when it looks like a device identity.
    if url == "/device-info" and isinstance(payload, dict):
        name_val = payload.get("name")
        if isinstance(name_val, str) and name_val:
            payload = dict(payload)
            payload["name"] = map_device_name(name_val, smap)
    return _deep_key_sanitize(_deep_redact(payload), smap)


def rewrite_local_download(data: bytes, ip: str, url: str, *, smap: SanitizeMap | None = None) -> bytes:
    """Rewrite a local download so it is safe + stable in fixtures.

    - Replaces real IP with __REEFBEAT_DEVICE_IP__ for text payloads
    - Pretty-formats JSON (and sanitizes with smap when provided)
    - Rotates UUID in description.xml and pretty-formats XML
    """
    if not data:
        return data

    # Avoid corrupting binary responses.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data

    text = text.replace(ip, "__REEFBEAT_DEVICE_IP__")

    if url == "/description.xml":
        new_uuid = str(uuid.uuid4())
        text = _UUID_RE.sub(f"uuid:{new_uuid}", text)

        return format_xml_bytes(text.encode("utf-8"))

    # Try JSON pretty/sanitize. If not JSON, return as UTF-8 text.
    try:
        obj_any: Any = json.loads(text)
    except Exception:
        return text.encode("utf-8")

    json_payload: JsonValue = cast(JsonValue, obj_any)
    if smap is not None:
        json_payload = sanitize_local_payload(url, json_payload, smap)

    return (json.dumps(json_payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def read_identity(root: Path) -> DeviceIdentity:
    """Extract hwid and name from device-info/data (JSON)."""
    p = root / "device-info" / "data"
    raw = p.read_text(encoding="utf-8")
    try:
        obj_any: Any = json.loads(raw)
    except json.JSONDecodeError:
        hwid_m = re.search(r'"hwid"\s*:\s*"([0-9a-fA-F]+)"', raw)
        name_m = re.search(r'"name"\s*:\s*"([^"]+)"', raw)
        if not hwid_m or not name_m:
            raise RuntimeError("Could not parse hwid/name from device-info/data")
        return DeviceIdentity(hwid=hwid_m.group(1).lower(), name=name_m.group(1))

    if not isinstance(obj_any, dict):
        raise RuntimeError("device-info/data JSON is not an object")

    obj = cast(dict[str, Any], obj_any)
    hwid_val = obj.get("hwid")
    name_val = obj.get("name")
    hwid = str(hwid_val).lower() if isinstance(hwid_val, str) else ""
    name = str(name_val) if isinstance(name_val, str) else ""

    if not hwid or not name:
        raise RuntimeError("device-info/data missing hwid or name")
    return DeviceIdentity(hwid=hwid, name=name)


def random_48bit_hex() -> str:
    n = random.randint(1, (1 << 48) - 1)
    return f"{n:x}"


def new_sim_name(old_name: str) -> str:
    rand = random.randint(1, 9_999_999_999)
    replaced = re.sub(r"-[0-9]*", f"-{rand}", old_name, count=1)
    return f"SIMU-{replaced}"


def replace_in_all_data_files(root: Path, urls: Iterable[str], old: DeviceIdentity, new: DeviceIdentity) -> None:
    for url in urls:
        d = dest_dir_for_url(url, root)
        data_path = d / "data"
        if not data_path.exists() or data_path.stat().st_size == 0:
            continue

        text = data_path.read_text(encoding="utf-8", errors="replace")
        text = text.replace(old.hwid, new.hwid)
        text = text.replace(old.name, new.name)
        data_path.write_text(text, encoding="utf-8")


def snapshot_local_device(ip: str, device_type: str, out_root: Path, timeout: int) -> None:
    if not ping_host(ip):
        raise RuntimeError(f"{ip} not alive")

    urls = iter_urls(device_type)

    # Reuse the same local-only mapping file as cloud export for stable sanitization.
    map_path = Path(SANITIZE_MAP_FILENAME)
    smap = load_sanitize_map(map_path)

    old_id: DeviceIdentity | None = None

    for url in urls:
        logger.info(url)
        d = dest_dir_for_url(url, out_root)
        d.mkdir(parents=True, exist_ok=True)

        data = fetch_url_http(ip, url, timeout=timeout)

        # Capture raw identity before sanitizing /device-info
        if url == "/device-info" and data and old_id is None:
            payload_any = _safe_json_loads(data)
            if isinstance(payload_any, dict):
                payload = cast(dict[str, Any], payload_any)
                hwid = payload.get("hwid")
                name = payload.get("name")
                if isinstance(hwid, str) and hwid and isinstance(name, str) and name:
                    old_id = DeviceIdentity(hwid=hwid.lower(), name=name)

        data = rewrite_local_download(data, ip, url, smap=smap)

        data_path = d / "data"
        data_path.write_bytes(data)

        # remove empty endpoints (keeps tree tight, like your bash)
        if data_path.stat().st_size == 0:
            if d != out_root:
                # delete directory tree
                for child in sorted(d.rglob("*"), reverse=True):
                    if child.is_file():
                        child.unlink(missing_ok=True)
                    else:
                        child.rmdir()
                d.rmdir()
            else:
                data_path.unlink(missing_ok=True)

    # Rewrite identity (hwid + name) across the downloaded files using stable mapping.
    if old_id is not None:
        new_id = DeviceIdentity(hwid=map_device_hwid(old_id.hwid, smap), name=map_device_name(old_id.name, smap))
        logger.info(f"Changing name from {old_id.name} to {new_id.name}")
        logger.info(f"Changing serial from {old_id.hwid} to {new_id.hwid}")
        replace_in_all_data_files(out_root, urls, old_id, new_id)

    # Persist mapping after successful export.
    save_sanitize_map(map_path, smap)


# =============================================================================
# Helpers: cloud sanitization
# =============================================================================


def _redact_string(value: str) -> str:
    s = _EMAIL_RE.sub("user@example.com", value)
    s = _PHONE_RE.sub("+10000000000", s)
    s = _UUID_RE.sub("uuid:00000000-0000-0000-0000-000000000000", s)  # your existing pattern
    s = _RAW_UUID_RE.sub("00000000-0000-0000-0000-000000000000", s)
    return s


def _deep_redact(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        # recurse while preserving JSON types
        return {k: _deep_redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_redact(v) for v in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


def _deep_key_sanitize(value: JsonValue, smap: SanitizeMap) -> JsonValue:
    """Key-aware sanitization for known PII fields across arbitrary payload shapes."""
    if isinstance(value, list):
        return [_deep_key_sanitize(v, smap) for v in value]
    if isinstance(value, dict):
        out: JsonObject = {}
        for k, v in value.items():
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
    """Sanitize /aquarium payload while preserving internal relationships."""
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
                obj["id"] = map_aquarium_id(raw_id, smap)
            else:
                obj["id"] = SANITIZED_AQUARIUM_ID
            if isinstance(raw_uid, str) and raw_uid:
                obj["uid"] = map_aquarium_uid(raw_uid, smap)
            else:
                obj["uid"] = SANITIZED_AQUARIUM_UID
            if isinstance(raw_user_uid, str) and raw_user_uid:
                obj["user_uid"] = map_user_uid(raw_user_uid, smap)
            else:
                obj["user_uid"] = cast(str, SANITIZED_USER["uid"])
            obj["name"] = SANITIZED_AQUARIUM_NAME
            obj["system_model"] = SANITIZED_SYSTEM_MODEL
            # scrub any remaining embedded PII
            out_list.append(_deep_key_sanitize(_deep_redact(obj), smap))
        return out_list

    if isinstance(payload, dict):
        obj2 = dict(payload)
        obj = dict(obj2)
        raw_id2 = obj2.get("id")
        raw_uid2 = obj2.get("uid")
        raw_user_uid2 = obj2.get("user_uid")
        if isinstance(raw_id2, int):
            obj["id"] = map_aquarium_id(raw_id2, smap)
        else:
            obj["id"] = SANITIZED_AQUARIUM_ID
        if isinstance(raw_uid2, str) and raw_uid2:
            obj["uid"] = map_aquarium_uid(raw_uid2, smap)
        else:
            obj["uid"] = SANITIZED_AQUARIUM_UID
        if isinstance(raw_user_uid2, str) and raw_user_uid2:
            obj["user_uid"] = map_user_uid(raw_user_uid2, smap)
        else:
            obj["user_uid"] = cast(str, SANITIZED_USER["uid"])
        obj["name"] = SANITIZED_AQUARIUM_NAME
        obj["system_model"] = SANITIZED_SYSTEM_MODEL
        return _deep_key_sanitize(_deep_redact(cast(JsonValue, obj)), smap)

    return payload


def _sanitize_cloud_device(payload: JsonValue, smap: SanitizeMap) -> JsonValue:
    """Sanitize /device payload while preserving aquarium linkage and removing PII."""
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

            # common identifiers (unique + stable)
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
            # scrub any remaining embedded PII (incl nested serial_code)
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
    # safest: for /user, replace entirely (prevents “new field leaked” surprises)
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

    # otherwise, scrub strings everywhere (cheap insurance)
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


def resolve_cloud_creds(
    cli_username: str | None,
    cli_password: str | None,
    dotenv_path: Path,
) -> tuple[str, str] | None:
    # CLI overrides .env
    if cli_username and cli_password:
        return cli_username, cli_password

    env = load_dotenv_simple(dotenv_path)
    username = env.get(ENV_USERNAME) or ""
    password = env.get(ENV_PASSWORD) or ""
    if username and password:
        return username, password
    return None


def snapshot_cloud(out_root: Path, timeout: int, username: str, password: str) -> bool:
    logger.info("Authenticating to ReefBeat cloud...")
    token = cloud_auth_token(username, password, timeout=timeout)
    if not token:
        logger.info("Cloud auth failed.")
        return False

    out_root.mkdir(parents=True, exist_ok=True)

    # Local-only mapping file (gitignore). Keeps sanitized IDs stable/unique.
    map_path = Path(SANITIZE_MAP_FILENAME)
    smap = load_sanitize_map(map_path)

    logger.info("Exporting cloud endpoints...")
    for path in CLOUD_URLS:
        logger.info(path)
        payload = cloud_get_json(path, token, timeout=timeout)

        dest = dest_dir_for_url(path, out_root)
        dest.mkdir(parents=True, exist_ok=True)
        # (dest / "data").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

        json_payload: JsonValue = cast(JsonValue, payload)
        sanitized: JsonValue = sanitize_cloud_payload(path, json_payload, smap)

        (dest / "data").write_text(
            json.dumps(sanitized, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    # Persist mapping after successful export.
    save_sanitize_map(map_path, smap)

    meta: dict[str, Any] = {"exported_at": int(time.time()), "server": CLOUD_SERVER_ADDR, "endpoints": CLOUD_URLS}
    (out_root / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return True


def infer_out_dir(out_root: Path, device_type: str | None, cloud_only: bool) -> Path:
    if cloud_only:
        return out_root / "CLOUD"
    if not device_type:
        raise ValueError("device_type is required unless cloud_only=True")
    return out_root / device_type


# =============================================================================
# CLI
# =============================================================================


def main() -> int:
    # Special entrypoint: `python run.py scan ...`
    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        return cmd_scan(sys.argv[2:])

    ap = argparse.ArgumentParser(description="Create simulator fixture tree from a ReefBeat device (+ optional cloud).")
    ap.add_argument("--ip", help="Device IP address (required unless --cloud-only)")
    ap.add_argument("--type", choices=available_device_types(), help="Device type (required unless --cloud-only)")
    ap.add_argument("--cloud-only", action="store_true", help="Only export cloud data (skip local)")
    ap.add_argument("--local-only", action="store_true", help="Only export local data (skip cloud)")
    ap.add_argument("--out-root", default="devices", help="Base output directory (default: ./devices)")
    ap.add_argument("--username", help=f"Cloud username (optional; overrides .env {ENV_USERNAME})")
    ap.add_argument("--password", help=f"Cloud password (optional; overrides .env {ENV_PASSWORD})")
    ap.add_argument(
        "--timeout",
        type=int,
        default=HTTP_TIMEOUT_SECS_DEFAULT,
        help=f"HTTP timeout seconds (default: {HTTP_TIMEOUT_SECS_DEFAULT})",
    )
    args = ap.parse_args()

    if args.ip and not args.type and not args.cloud_only:
        logger.error("When --ip is provided, --type is also required.")
        return 2

    out_root = Path(args.out_root).resolve()
    out_dir = infer_out_dir(out_root, args.type, cloud_only=bool(args.cloud_only))
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.cloud_only and args.local_only:
        logger.info("Choose only one of --cloud-only or --local-only.")
        return 2

    # Cloud-only
    if args.cloud_only:
        creds = resolve_cloud_creds(args.username, args.password, Path(".env"))
        if not creds:
            logger.info(
                "No cloud credentials provided (use --username/--password or .env). Cloud-only requested; nothing to do."
            )
            return 2
        snapshot_cloud(out_dir, timeout=int(args.timeout), username=creds[0], password=creds[1])
        return 0

    # Local requires ip + type
    if not args.ip or not args.type:
        logger.info("Missing --ip and/or --type (required unless --cloud-only).")
        return 2

    snapshot_local_device(args.ip, args.type, out_dir, timeout=int(args.timeout))

    # Optional cloud (writes under <out_dir>/cloud)
    if not args.local_only:
        creds = resolve_cloud_creds(args.username, args.password, Path(".env"))
        if not creds:
            logger.info("No .env or CLI creds found; skipping cloud export.")
        else:
            snapshot_cloud(out_dir / "cloud", timeout=int(args.timeout), username=creds[0], password=creds[1])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
