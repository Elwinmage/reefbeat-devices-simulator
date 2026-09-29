"""ReefBeat cloud account: what the integration reads and writes of it.

A simulated account served over HTTPS like ``cloud.reef-beat.com`` (the
integration asks for it in advanced mode, under the name of the cloud
server), holding one aquarium and the simulated lamps:

- ``POST /oauth/token``: any credentials get a bearer token (the account is
  a simulation), unless ``username``/``password`` are set in the device's
  config;
- ``GET /user``, ``/aquarium``: fixtures;
- ``GET /device``: the simulated devices of this process, built from their
  ``/device-info`` (by default the ReefLEDs; ``devices`` in the config lists
  the names to show instead), all in the account's aquarium;
- the light programs library, as the ReefBeat app uses it:

  - G1: ``/reef-lights/library`` (``?include=all``), entries
    ``{id, uid, aquarium_id, aquarium_uid, name, program, clouds}``;
  - G2: ``/v2/reef-lights/library``, entries
    ``{id, name, color, moon, clouds}``;
  - ``POST`` adds a program (a new uid/id is given), ``PUT <library>/<uid>``
    updates one, ``DELETE <library>/<uid>`` removes one;

- ``/reef-wave/library`` and ``/reef-dosing/supplement``: fixtures;
- ``GET /firmware/api/<type>/latest``: the firmware the simulated devices
  of that type run (no update offered).
"""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Any, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from . import registry

Response = Tuple[int, Any]

G1_LIBRARY = "/reef-lights/library"
G2_LIBRARY = "/v2/reef-lights/library"
LIBRARIES = (G1_LIBRARY, G2_LIBRARY)

TOKEN_LIFETIME_S = 3600


def is_cloud(server: Any) -> bool:
    """Whether the device is the simulated cloud account."""
    return str(getattr(getattr(server, "actions", None), "type", "")) == "CLOUD"


def _data(server: Any, path: str) -> Any:
    entry = server._db.get(path)
    return None if entry is None else entry.get("data")


def _store(server: Any, path: str, data: Any) -> None:
    server._db.setdefault(path, {"access": {"rights": ["GET"]}})["data"] = data


def aquarium(server: Any) -> dict[str, Any]:
    """The account's aquarium, where every simulated device is set up."""
    aquariums = _data(server, "/aquarium")
    if isinstance(aquariums, list) and aquariums and isinstance(aquariums[0], dict):
        return aquariums[0]
    return {"id": 0, "uid": ""}


# --------------------------------------------------------------------------
# Devices
# --------------------------------------------------------------------------
def _device_info(device: Any) -> Optional[dict[str, Any]]:
    for path in ("/device-info", "/"):
        info = _data(device, path)
        if isinstance(info, dict) and info.get("hw_type"):
            return info
    return None


def _hwid(device: Any, info: dict[str, Any]) -> Any:
    """Hardware id of a device, as the integration reads it: a RSLED90
    reports "null" on /device-info, its uuid on / stands for it."""
    hwid = info.get("hwid")
    if hwid in (None, "null"):
        root = _data(device, "/")
        if isinstance(root, dict) and root.get("uuid"):
            return root["uuid"]
    return hwid


def _listed(server: Any, device: Any, info: dict[str, Any]) -> bool:
    names = getattr(server.config, "devices", None)
    if names:
        return device.config.name in names
    return info.get("hw_type") == "reef-lights"


def devices(server: Any) -> list[dict[str, Any]]:
    """``/device``: the simulated devices, as the account lists them."""
    aq = aquarium(server)
    out: list[dict[str, Any]] = []
    for n, device in enumerate(sorted(registry.servers(), key=lambda s: s.config.name)):
        if device is server:
            continue
        info = _device_info(device)
        if info is None or not _listed(server, device, info):
            continue
        firmware = _data(device, "/firmware") or {}
        wifi = _data(device, "/wifi") or {}
        out.append(
            {
                "id": 900001 + n,
                "aquarium_id": aq.get("id"),
                "aquarium_uid": aq.get("uid"),
                "name": info.get("name"),
                "hwid": _hwid(device, info),
                "type": info.get("hw_type"),
                "model": info.get("hw_model"),
                "mac": wifi.get("mac", ""),
                "ssid": wifi.get("ssid", ""),
                "ip_address": device.config.ip,
                "firmware_version": firmware.get("version", ""),
                "board": "esp32",
                "framework": "i",
                "hw_revision": info.get("hw_revision", ""),
                "connected": True,
                "in_service": True,
                "grouped": False,
                "previously_grouped": False,
                "group_index": 0,
                "offset": 0,
                "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "onboarding_date": "2025-01-01T00:00:00Z",
                "properties": {},
            }
        )
    return out


def latest_firmware(server: Any, device_type: str) -> dict[str, Any]:
    """Latest firmware of a device type: the one its simulated devices run."""
    versions = [
        d["firmware_version"]
        for d in devices(server)
        if d["type"] == device_type and d["firmware_version"]
    ]
    return {"version": max(versions) if versions else "0.0.0"}


# --------------------------------------------------------------------------
# Light programs library
# --------------------------------------------------------------------------
def _key(library: str) -> str:
    """Identifier field of a library's entries."""
    return "id" if library == G2_LIBRARY else "uid"


def _split(path: str) -> Optional[Tuple[str, Optional[str]]]:
    """Library and entry uid of a path, None outside the libraries."""
    for library in LIBRARIES:
        if path == library:
            return library, None
        if path.startswith(library + "/"):
            return library, path[len(library) + 1 :]
    return None


def _entries(server: Any, library: str) -> list[dict[str, Any]]:
    data = _data(server, library)
    return [e for e in data if isinstance(e, dict)] if isinstance(data, list) else []


def add_program(server: Any, library: str, body: dict[str, Any]) -> dict[str, Any]:
    """New program of a library, with the identifiers the cloud gives."""
    entries = _entries(server, library)
    entry = dict(body)
    if library == G2_LIBRARY:
        entry["id"] = str(uuid.uuid4())
    else:
        aq = aquarium(server)
        numbers = [int(e["id"]) for e in entries if isinstance(e.get("id"), int)]
        entry = {
            "id": max(numbers, default=1000000) + 1,
            "uid": str(uuid.uuid4()),
            "aquarium_id": aq.get("id"),
            "aquarium_uid": body.get("aquarium_uid", aq.get("uid")),
            "name": body.get("name", ""),
            "program": body.get("program"),
            "clouds": body.get("clouds"),
        }
    entry.setdefault("clouds", None)
    _store(server, library, entries + [entry])
    return entry


def _find(entries: list, key: str, uid: str) -> Optional[int]:
    for n, entry in enumerate(entries):
        if str(entry.get(key)) == uid:
            return n
    return None


def _library_request(
    server: Any, method: str, library: str, uid: Optional[str], body: Any
) -> Optional[Response]:
    entries = _entries(server, library)
    if uid is None:
        if method == "GET":
            return 200, entries
        if method == "POST":
            if not isinstance(body, dict) or not body.get("name"):
                return 400, {"message": "name required"}
            return 201, add_program(server, library, body)
        return None
    n = _find(entries, _key(library), uid)
    if n is None:
        return 404, {"message": "program not found"}
    if method == "GET":
        return 200, entries[n]
    if method == "PUT":
        if not isinstance(body, dict):
            return 400, {"message": "program required"}
        # The whole program is sent: clouds left out are removed
        updated = {**entries[n], "clouds": None, **body}
        updated[_key(library)] = entries[n][_key(library)]
        entries[n] = updated
        _store(server, library, entries)
        return 200, updated
    if method == "DELETE":
        del entries[n]
        _store(server, library, entries)
        return 200, {"success": True}
    return None


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------
def _token(server: Any, body: Any) -> Response:
    expected = (
        getattr(server.config, "username", ""),
        getattr(server.config, "password", ""),
    )
    if any(expected):
        form = body if isinstance(body, dict) else {}
        if (form.get("username"), form.get("password")) != expected:
            return 401, {"error": "invalid_grant"}
    return 200, {
        "access_token": secrets.token_hex(16),
        "token_type": "bearer",
        "refresh_token": secrets.token_hex(16),
        "expires_in": TOKEN_LIFETIME_S,
        "scope": "all",
    }


def parse_form(raw: bytes) -> dict[str, str]:
    """Fields of an ``application/x-www-form-urlencoded`` body."""
    fields = parse_qs(raw.decode("utf8", "replace"))
    return {k: v[0] for k, v in fields.items() if v}


def handle(server: Any, method: str, raw_path: str, body: Any) -> Optional[Response]:
    """Handle a cloud request.

    Returns ``(status, json_value)`` when this module owns the request, else
    ``None`` so the caller falls back to the generic machinery.
    """
    if not is_cloud(server):
        return None
    path = urlparse(raw_path).path.rstrip("/") or "/"
    with registry.LOCK:
        if path == "/oauth/token" and method == "POST":
            return _token(server, body)
        library = _split(path)
        if library is not None:
            return _library_request(server, method, library[0], library[1], body)
        if method == "GET":
            if path == "/device":
                return 200, devices(server)
            if path.startswith("/firmware/api/") and path.endswith("/latest"):
                return 200, latest_firmware(server, path.split("/")[3])
            data = _data(server, path)
            if data is not None:
                return 200, data
            return 404, {"message": "not found"}
    return None
