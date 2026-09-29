"""RSCONTROL (Pro / Lite) hub subsystem for the ReefBeat device simulator.

Reproduces what the ReefControl hub does, from packet captures and from the
ReefBeat app, as far as the Home Assistant integration and the reef card use
it:

- ReefSense probes on ``/dashboard``'s ``probes`` list (temperature, ec,
  ph, orp, ato level, leak) and their life cycle: ``POST /probe/install``,
  ``POST /ble/off``, ``PUT /probe/config`` (body is an *array*), ``GET
  /probe`` (fresh reading), ``/probe/info``, ``POST|DELETE /probe/disable``,
  ``DELETE /probe``, ``DELETE /setup-probes``;
- single-point calibration: ``/probe/offset`` (GET, POST, DELETE), for the
  reading of temperature and ORP probes and for the embedded temperature of
  pH, EC and ATO probes. ``POST`` *adds* to the current offset, and every
  reading includes it, as captured on a real hub;
- multi-point calibration of pH and EC probes: ``calibration-enter``,
  ``calibration-point-start``, ``calibration-status`` (polled; the hub
  waits for the reading to settle), ``calibration-exit``, plus the
  calibration log, restore and factory reset;
- leak probes: ``GET /probe?type=leak`` tells where the water comes from
  (``leak_status``), ``/leak/config``, the hub-wide ``leak_detector`` of
  ``/configuration`` and the buzzer;
- 12V ports: ``PUT /ports/config``, ``POST /port/<n>/install``, ``DELETE
  /port/<n>``, ``GET|PUT /port/<n>/schedule``, ``POST /port/<n>/toggle``,
  their probe rules (``PUT /ports/subscribe``) and their state (schedule,
  probe rule);
- the link with an RSPower strip: ``POST /power/discover``, ``POST
  /power/unpair``, the strip socket rules (``PUT /socket/<n>/subscribe`` and
  ``/unsubscribe``) mirrored into ``/subscription-info``;
- ``POST /setup-finish``, synthetic ``/sensor-log`` and ``/temperature-log``.

Simulator-only endpoints, to play a scenario without hardware:

- ``PUT /sim/probe?type=<t>&uid=<u>``: set what a probe measures (``value``,
  ``temp``, ``water_level``, ``leak_status``) or plug / unplug it
  (``status``: ``"connected"`` or ``"disconnected"``);
- ``PUT /sim/buzzer``: ``{"dismissed": true}`` as when the hub button is
  pressed;
- ``GET /sim/probes``: the raw readings of every probe (before offsets),
  what a scenario reads back and restores;
- ``GET|PUT /sim/clock``: ``{"minute": <0-1439>}`` pins the clock the
  schedules follow, for every simulated device; ``{"minute": null}`` goes
  back to the real time;
- ``PUT /sim/watts``: ``{"watts": {"<port number>": <W>}}``, what a 12V
  port draws while powered (its ``consumption`` on ``/dashboard``).

The whole probe state lives in ``/dashboard``'s ``probes`` list as canonical
records (raw readings, config and book-keeping under ``_``-prefixed keys);
every GET projects the subset the firmware exposes.
"""

from __future__ import annotations

import time
from typing import Any, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from . import probe_rules, registry

Response = Tuple[int, Any]

# Endpoints owned by this module (query string stripped). Anything else is
# left to the generic simulator machinery.
_GET_PATHS = frozenset(
    {
        "/probe",
        "/probe/config",
        "/probe/info",
        "/probe/offset",
        "/probe/calibration-status",
        "/probe/calibration-log",
        "/sensor-log",
        "/temperature-log",
        "/leak/config",
        "/subscription-info",
        "/sim/probes",
        "/sim/clock",
    }
)

# --------------------------------------------------------------------------
# Probe catalogue — defaults per type at install time
# --------------------------------------------------------------------------
# ``ranges`` is ``[acceptable_low, desired_low, desired_high, acceptable_high]``.
# ``value`` / ``temp`` are the raw readings (before any offset).
_CATALOG: dict[str, dict[str, Any]] = {
    "temperature": {
        "name": "Temperature",
        "value": 25.0,
        "ranges": [21, 23, 26, 28],
        "has_temp": False,
        "has_primary": True,
        "buzzer": True,
        "hw_revision": "1.2_25A",
    },
    "ec": {
        "name": "EC",
        "value": 53.0,
        "ranges": [46.2, 49, 54.4, 59.7],
        "temp": 25.0,
        "temp_ranges": [21, 23, 26, 28],
        "unit": "ec",
        "has_temp": True,
        "has_primary": True,
        "buzzer": True,
        "hw_revision": "1.0.0",
    },
    "ph": {
        "name": "pH",
        "value": 8.15,
        "ranges": [7.6, 7.9, 8.4, 8.6],
        "temp": 25.0,
        "temp_ranges": [21, 23, 26, 28],
        "has_temp": True,
        "has_primary": True,
        "buzzer": False,
        "hw_revision": "2.3.0",
    },
    "orp": {
        "name": "ORP",
        "value": 250,
        "ranges": [100, 200, 400, 480],
        "has_temp": False,
        "has_primary": True,
        "buzzer": False,
        "hw_revision": "1.0.0",
    },
    "ato": {
        "name": "ATO",
        "water_level": "below",
        "temp": 25.0,
        "temp_ranges": [21, 23, 26, 28],
        "has_temp": True,
        "has_primary": False,
        "buzzer": False,
        "hw_revision": "1.0.0",
    },
    "leak": {
        "name": "Leak",
        "detected": False,
        "has_temp": False,
        "has_primary": False,
        "buzzer": True,
        "hw_revision": "1.0.0",
    },
}

# Which raw reading an offset moves, per probe type: the reading itself for
# temperature and ORP probes, the embedded temperature for the others.
_OFFSET_FIELD: dict[str, str] = {
    "temperature": "value",
    "orp": "value",
    "ph": "temp",
    "ec": "temp",
    "ato": "temp",
}
# Decimals an offset and its reading are kept with (ORP: whole millivolts).
_DIGITS: dict[str, int] = {"orp": 0}

# Multi-point calibration: the points each type takes, and the solutions the
# hub accepts for them (outside, the point fails like a wrong solution).
_CALIBRATION_POINTS: dict[str, tuple[str, ...]] = {
    "ph": ("LOW", "MID", "HIGH"),
    "ec": ("MID",),
}
_PH_SOLUTIONS: dict[str, tuple[float, float]] = {
    "LOW": (3.5, 4.5),
    "MID": (6.5, 7.5),
    "HIGH": (9.0, 10.5),
}
_EC_SOLUTIONS: tuple[float, float] = (20.0, 99.0)
# How long the hub waits for a calibration reading to settle. The ReefBeat
# app starts its progress bar at 180 s (3 min) until the hub's first
# ``time_left``; ``calibration_seconds`` in the device config overrides it
# (the tests use a few seconds).
DEFAULT_CALIBRATION_SECONDS = 180

# What a leak probe measures, per origin of the water (conductivity).
_LEAK_EC: dict[str, int] = {
    "dry": 2,
    "aquarium_water_leak": 1540,
    "rodi_water_leak": 40,
}

# Probe statuses meaning unplugged: the hub answers 503 about it.
_UNPLUGGED = frozenset({"disconnected", "not_connected", "offline"})

# Rolling uid allocator (0x000F7-style, 5 hex digits), per server.
_UID_SEED = 0x00100


def _now() -> int:
    return int(time.time())


def _clock() -> float:
    """Time used by the calibration waits (patched by the tests)."""
    return time.time()


def _query(q: dict[str, list[str]], key: str) -> str:
    """One query parameter, "" when absent."""
    values = q.get(key)
    return values[0] if values else ""


def _error(status: int, message: str) -> Response:
    return status, {"success": False, "message": message}


def _ok(message: str) -> Response:
    return 200, {"success": True, "message": message}


# --------------------------------------------------------------------------
# State access
# --------------------------------------------------------------------------
def _dashboard(server: Any) -> Optional[dict[str, Any]]:
    entry = server._db.get("/dashboard")
    if not entry:
        return None
    data = entry.get("data")
    return data if isinstance(data, dict) else None


def is_control(server: Any) -> bool:
    """Recognise an RSCONTROL device from the shape of its dashboard.

    A ``probes`` list (or ``leak_detector`` flag) marks the hub, so a
    hand-written or renamed fixture still routes here.
    """
    dash = _dashboard(server)
    if dash is None:
        return False
    return "probes" in dash or "leak_detector" in dash


def _probes(server: Any) -> list[dict[str, Any]]:
    dash = _dashboard(server)
    if dash is None:
        return []
    probes = dash.setdefault("probes", [])
    return probes if isinstance(probes, list) else []


def _find(server: Any, ptype: str, uid: str) -> Optional[dict[str, Any]]:
    for p in _probes(server):
        if p.get("type") == ptype and p.get("uid") == uid:
            return p
    return None


def _unplugged(rec: dict[str, Any]) -> bool:
    return rec.get("status") in _UNPLUGGED


def _data(server: Any, path: str, default: Any) -> Any:
    """The stored payload of a fixture endpoint, created when missing."""
    entry = server._db.setdefault(path, {"access": {"rights": ["GET"]}})
    data = entry.get("data")
    if data is None or type(data) is not type(default):
        entry["data"] = default
        data = default
    return data


def _configuration(server: Any) -> dict[str, Any]:
    return _data(server, "/configuration", {})


def _alloc_uid(server: Any) -> str:
    counter = getattr(server, "_probe_uid_counter", None)
    if counter is None:
        existing = []
        for p in _probes(server):
            try:
                existing.append(int(str(p.get("uid", "0x0")), 16))
            except (TypeError, ValueError):
                pass
        counter = max([_UID_SEED, *[e + 1 for e in existing]])
    uid = "0x%05X" % counter
    server._probe_uid_counter = counter + 1
    return uid


def _level(value: Any, ranges: Any) -> str:
    """Map a value onto desired / acceptable / danger from a 4-point range."""
    if not probe_rules.is_number(value):
        return "sensor_data_error"
    try:
        al, dl, dh, ah = (float(r) for r in ranges)
    except (TypeError, ValueError):
        return "acceptable"
    if value < al or value > ah:
        return "danger"
    if dl <= value <= dh:
        return "desired"
    return "acceptable"


# --------------------------------------------------------------------------
# Readings and offsets
# --------------------------------------------------------------------------
def _offset(rec: dict[str, Any]) -> float:
    off = rec.get("_offset")
    value = off.get("offset") if isinstance(off, dict) else 0
    return probe_rules.as_float(value) or 0.0


def _reported(rec: dict[str, Any], field: str) -> Any:
    """A reading as the hub reports it: the raw value plus its offset."""
    raw = rec.get(field)
    ptype = str(rec.get("type"))
    number = probe_rules.as_float(raw)
    if number is None or _OFFSET_FIELD.get(ptype) != field:
        return raw
    digits = _DIGITS.get(ptype, 2)
    value = round(number + _offset(rec), digits)
    return int(value) if digits == 0 else value


def _leak_status(rec: dict[str, Any]) -> str:
    status = rec.get("leak_status")
    if status in _LEAK_EC:
        return str(status)
    return "aquarium_water_leak" if rec.get("detected") else "dry"


def probe_reading(server: Any, ptype: str, uid: str, sensor: str = "primary") -> Any:
    """What a probe reports for a rule, None when it cannot be read.

    ``sensor`` is ``primary`` (the probe's own reading) or ``temperature``
    (its embedded temperature). A leak probe reads whether it is wet, an ATO
    probe its water level.
    """
    rec = _find(server, ptype, uid)
    if rec is None or _unplugged(rec) or rec.get("_disabled"):
        return None
    if sensor == "temperature":
        return _reported(rec, "temp")
    if ptype == "leak":
        return _leak_status(rec) != "dry"
    if ptype == "ato":
        return rec.get("water_level")
    return _reported(rec, "value")


# --------------------------------------------------------------------------
# Dashboard projection
# --------------------------------------------------------------------------
def project_dashboard_probes(dash: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the ``probes`` list as the firmware exposes it on ``/dashboard``.

    Strips the private keys, applies the offsets and derives the per-type
    shape (levels, temp_value / temp_level, water_level, detected, ...).
    """
    out: list[dict[str, Any]] = []
    for rec in dash.get("probes", []):
        if not isinstance(rec, dict):
            continue
        ptype = str(rec.get("type"))
        spec = _CATALOG.get(ptype, {})
        base: dict[str, Any] = {
            "type": ptype,
            "uid": rec.get("uid"),
            "name": rec.get("name", spec.get("name", ptype)),
            "status": rec.get("status", "auto"),
            "last_installation_date": rec.get("last_installation_date", 0),
        }
        if rec.get("_disabled"):
            base["status"] = "disabled"

        if ptype == "leak":
            base["detected"] = _leak_status(rec) != "dry"
        elif ptype == "ato":
            base["water_level"] = rec.get("water_level", "below")
        else:
            val = _reported(rec, "value")
            base["value"] = val
            base["level"] = _level(val, rec.get("ranges", []))
            if ptype == "ec":
                base["measurement_unit"] = rec.get("unit", "ec")
                base["ec"] = val
                base["ppt"] = rec.get("ppt", 0)
                base["sg"] = rec.get("sg", 0)
        if spec.get("has_temp"):
            tval = _reported(rec, "temp")
            base["temp_value"] = tval
            base["temp_level"] = _level(tval, rec.get("temp_ranges", []))
        if ptype in ("ec", "ph"):
            # The date of the last (multi-point) calibration, null until then
            base["last_adjustment_date"] = rec.get("last_adjustment_date")
        out.append(base)
    return out


def _buzzer(server: Any, dash: dict[str, Any]) -> dict[str, Any]:
    """The hub buzzer: sounding for a leak, or for a probe in danger.

    ``cause`` is ``leak``, ``danger`` or ``none`` (the names the hub gives
    are not captured yet). Pressing the hub button dismisses it until the
    cause clears.
    """
    stored = dash.get("buzzer")
    if not isinstance(stored, dict):
        stored = {"active": False, "cause": "none", "dismissed": False}
        dash["buzzer"] = stored
    conf = _configuration(server)
    leak_conf = _leak_config(server)
    detector = bool(conf.get("leak_detector", True)) and bool(
        leak_conf.get("leak_detector", True)
    )
    leak = detector and any(
        rec.get("type") == "leak"
        and not rec.get("_disabled")
        and not _unplugged(rec)
        and _leak_status(rec) != "dry"
        for rec in _probes(server)
    )
    danger = False
    for rec in _probes(server):
        if rec.get("_disabled") or _unplugged(rec) or rec.get("type") == "leak":
            continue
        cfg = rec.get("_config") or {}
        spec = _CATALOG.get(str(rec.get("type")), {})
        if spec.get("has_primary") and cfg.get("buzzer", spec.get("buzzer")):
            if _level(_reported(rec, "value"), rec.get("ranges")) == "danger":
                danger = True
        if spec.get("has_temp") and cfg.get("temp_buzzer", False):
            if _level(_reported(rec, "temp"), rec.get("temp_ranges")) == "danger":
                danger = True
    leak_config = conf.get("leak_buzzer_config") or {}
    danger_config = conf.get("danger_buzzer_config") or {}
    sounding = (
        leak
        and bool(leak_conf.get("buzzer", True))
        and leak_config.get("enabled", True)
    ) or (danger and danger_config.get("enabled", True))
    cause = "leak" if leak else "danger" if danger else "none"
    if cause == "none":
        stored["dismissed"] = False
    dismissed = bool(stored.get("dismissed", False))
    return {
        "active": bool(sounding) and not dismissed,
        "cause": cause,
        "dismissed": dismissed,
    }


def _port_state(server: Any, port: dict[str, Any]) -> Any:
    """State of a 12V port: from its schedule or its probe rule when it
    follows one, else what is stored (``unknown`` under manual on / off)."""
    number = port.get("number")
    mode = port.get("mode")
    if mode == "schedule":
        schedule = _schedules(server).get(number, {})
        powered = probe_rules.is_within(
            schedule.get("intervals"), probe_rules.minutes_now()
        )
        return "on" if powered else "standby"
    if mode == "sensor":
        rule = _rule(_subscription_info(server)["internal"], number)
        if rule is None:
            return "standby"
        return "on" if _apply_rule(server, rule) else "standby"
    return port.get("state", "unknown")


def _apply_rule(server: Any, rule: dict[str, Any]) -> bool:
    """Evaluate a probe rule of this hub and remember its last output."""
    reading = probe_reading(
        server, str(rule.get("type")), str(rule.get("uid")), str(rule.get("sensor"))
    )
    last = rule.get("last_sock_op")
    previous = None if last not in ("on", "off") else last == "on"
    powered = probe_rules.evaluate(rule, reading, previous)
    rule["last_sock_op"] = "on" if powered else "off"
    return powered


def rule_for_socket(server: Any, number: int) -> Optional[dict[str, Any]]:
    """The rule this hub keeps for a socket of its paired strip."""
    return _rule(_subscription_info(server)["external"], number)


def socket_powered(server: Any, number: int) -> Optional[bool]:
    """Whether a strip socket following this hub's probe is powered.

    None when the hub keeps no rule for that socket.
    """
    with registry.LOCK:
        rule = rule_for_socket(server, number)
        if rule is None:
            return None
        return _apply_rule(server, rule)


# --------------------------------------------------------------------------
# Probe life cycle
# --------------------------------------------------------------------------
def _install(server: Any, ptype: str) -> Response:
    spec = _CATALOG.get(ptype)
    if spec is None:
        return _error(400, "Unknown probe type")
    uid = _alloc_uid(server)
    rec: dict[str, Any] = {
        "type": ptype,
        "uid": uid,
        "name": spec.get("name", ptype),
        "status": "setup",  # stays in setup until configured
        "last_installation_date": _now(),
        "last_adjustment_date": None,
        "_config": {},
        "_offset": {"offset": 0, "last_adjustment_date": 0},
        "_disabled": False,
        "_info": {
            "hwid": "%012x" % (abs(hash(uid)) % (1 << 48)),
            "hw_revision": spec.get("hw_revision", "1.0.0"),
            "version": "1.1.8",
            "last_fota_time": _now(),
        },
    }
    if spec.get("has_primary"):
        rec["value"] = spec.get("value")
        rec["ranges"] = list(spec.get("ranges", []))
    if ptype == "ec":
        rec["unit"] = spec.get("unit", "ec")
        rec["ppt"] = 34.7
        rec["sg"] = 1.0264
    if spec.get("has_temp"):
        rec["temp"] = spec.get("temp")
        rec["temp_ranges"] = list(spec.get("temp_ranges", []))
    if ptype == "ato":
        rec["water_level"] = spec.get("water_level", "below")
    if ptype == "leak":
        rec["leak_status"] = "dry"
    _probes(server).append(rec)
    return 200, {
        "uid": uid,
        "success": True,
        "message": "Found new sensor - installed successfully",
    }


def _configure(server: Any, body: Any) -> Response:
    """Apply ``PUT /probe/config`` — body is an array of probe config objects.

    Partial entries are merged, as on the hub. A leak probe only takes its
    name here: its buzzer / notify live in ``/leak/config``.
    """
    entries = body if isinstance(body, list) else [body]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rec = _find(server, str(entry.get("type")), str(entry.get("uid")))
        if rec is None:
            continue
        if rec.get("type") == "leak" and set(entry) - {"name", "type", "uid"}:
            return _error(503, "Failed to update probe configuration")
        if "name" in entry:
            rec["name"] = entry["name"]
        for key in ("buzzer", "notify", "unit"):
            if key in entry:
                rec.setdefault("_config", {})[key] = entry[key]
        if "unit" in entry:
            rec["unit"] = entry["unit"]
        if "ranges" in entry:
            rec["ranges"] = list(entry["ranges"])
        if isinstance(entry.get("temp"), dict):
            temp = entry["temp"]
            if "ranges" in temp:
                rec["temp_ranges"] = list(temp["ranges"])
            if "notify" in temp:
                rec.setdefault("_config", {})["temp_notify"] = temp["notify"]
            if "buzzer" in temp:
                rec.setdefault("_config", {})["temp_buzzer"] = temp["buzzer"]
        # A configured probe leaves setup and starts reporting.
        if rec.get("status") == "setup":
            rec["status"] = "auto"
    return _ok("Update probe configuration success")


def _plugged(
    server: Any, ptype: str, uid: str
) -> Tuple[Optional[dict[str, Any]], Optional[Response]]:
    """The probe, or the answer the hub gives when it cannot talk to it."""
    rec = _find(server, ptype, uid)
    if rec is None:
        return None, _error(404, "Probe not found")
    if _unplugged(rec):
        return None, _error(503, "Failed to communicate with the sensor")
    return rec, None


def _detail(server: Any, ptype: str, uid: str) -> Response:
    """``GET /probe`` — a fresh reading (shape depends on type)."""
    rec, failure = _plugged(server, ptype, uid)
    if rec is None:
        return failure or _error(404, "Probe not found")
    status = "connected"
    name = rec.get("name")
    temperature = {"value": _reported(rec, "temp")}
    if ptype == "leak":
        leak_status = _leak_status(rec)
        return 200, {
            "name": name,
            "ec": rec.get("ec", _LEAK_EC[leak_status]),
            "status": status,
            "leak_status": leak_status,
        }
    if ptype == "ato":
        return 200, {
            "name": name,
            "ato_sensor_status": rec.get("water_level", "below"),
            "status": status,
            "temperature": temperature,
        }
    value = _reported(rec, "value")
    if ptype == "ec":
        return 200, {
            "name": name,
            "status": status,
            "ec": value,
            "ppt": rec.get("ppt", 0),
            "sg": rec.get("sg", 0),
            "temperature": temperature,
        }
    if ptype == "ph":
        return 200, {
            "name": name,
            "status": status,
            "value": value,
            "temperature": temperature,
        }
    # temperature / orp
    return 200, {"name": name, "status": status, "value": value}


def _info(server: Any, ptype: str, uid: str) -> Response:
    rec, failure = _plugged(server, ptype, uid)
    if rec is None:
        return failure or _error(404, "Probe not found")
    return 200, dict(rec.get("_info", {}))


def _offset_get(server: Any, ptype: str, uid: str) -> Response:
    if ptype not in _OFFSET_FIELD:
        return _error(400, "No offset for this sensor type")
    rec, failure = _plugged(server, ptype, uid)
    if rec is None:
        if failure is not None and failure[0] == 503:
            return _error(503, "Failed to get offset")
        return failure or _error(404, "Probe not found")
    off = rec.get("_offset") or {"offset": 0, "last_adjustment_date": 0}
    return 200, dict(off)


def _offset_set(server: Any, ptype: str, uid: str, body: Any) -> Response:
    """``POST /probe/offset`` — *adds* the posted value to the offset."""
    if ptype not in _OFFSET_FIELD:
        return _error(400, "No offset for this sensor type")
    rec, failure = _plugged(server, ptype, uid)
    if rec is None:
        return failure or _error(404, "Probe not found")
    delta = probe_rules.as_float(body.get("offset") if isinstance(body, dict) else None)
    if delta is None:
        return _error(400, "Missing offset")
    digits = _DIGITS.get(ptype, 3)
    total = round(_offset(rec) + delta, digits)
    rec["_offset"] = {
        "offset": int(total) if digits == 0 else total,
        "last_adjustment_date": _now(),
    }
    return _ok("Calibration point set successfully")


def _offset_delete(server: Any, ptype: str, uid: str) -> Response:
    if ptype not in _OFFSET_FIELD:
        return _error(400, "No offset for this sensor type")
    rec, failure = _plugged(server, ptype, uid)
    if rec is None:
        return failure or _error(404, "Probe not found")
    rec["_offset"] = {"offset": 0, "last_adjustment_date": _now()}
    return _ok("Offset reset successfully")


def _disable(server: Any, ptype: str, uid: str, disabled: bool) -> Response:
    rec = _find(server, ptype, uid)
    if rec is None:
        return _error(404, "Probe not found")
    rec["_disabled"] = disabled
    return _ok(
        "Probe disabled successfully" if disabled else "Probe enabled successfully"
    )


def _delete(server: Any, ptype: str, uid: str) -> Response:
    probes = _probes(server)
    for i, p in enumerate(probes):
        if p.get("type") == ptype and p.get("uid") == uid:
            probes.pop(i)
            _drop_subscriptions(server, uid)
            _sessions(server).pop("%s:%s" % (ptype, uid), None)
            return _ok("Probe removed successfully")
    return _error(404, "Probe not found")


def _delete_setup(server: Any) -> Response:
    probes = _probes(server)
    deleted = [
        {"type": p.get("type"), "uid": p.get("uid")}
        for p in probes
        if p.get("status") == "setup"
    ]
    dash = _dashboard(server)
    if dash is not None:
        dash["probes"] = [p for p in probes if p.get("status") != "setup"]
    return 200, {"deleted_probes": deleted}


def _config_list(server: Any) -> Response:
    """Project ``GET /probe/config`` — full per-probe config, shaped per type.

    Leak carries only name/type/uid (its buzzer/notify live in /leak/config);
    ec/ph/ato expose a nested ``temp`` block; ato has no top-level buzzer or
    ranges.
    """
    out: list[dict[str, Any]] = []
    for rec in _probes(server):
        ptype = str(rec.get("type"))
        cfg = rec.get("_config", {})
        base = {"name": rec.get("name"), "type": ptype, "uid": rec.get("uid")}
        if ptype == "leak":
            out.append(base)
            continue
        spec = _CATALOG.get(ptype, {})
        entry: dict[str, Any] = {}
        if spec.get("has_primary") and "ranges" in rec:
            entry["ranges"] = rec.get("ranges")
        if ptype == "ec":
            entry["unit"] = rec.get("unit", "ec")
        if ptype != "ato":
            entry["buzzer"] = cfg.get("buzzer", spec.get("buzzer", False))
        entry["notify"] = cfg.get("notify", True)
        if spec.get("has_temp"):
            entry["temp"] = {
                "ranges": rec.get("temp_ranges", []),
                "buzzer": cfg.get("temp_buzzer", False),
                "notify": cfg.get("temp_notify", True),
            }
        entry.update(base)
        out.append(entry)
    return 200, out


# --------------------------------------------------------------------------
# Multi-point calibration (pH, EC)
# --------------------------------------------------------------------------
def _sessions(server: Any) -> dict[str, dict[str, Any]]:
    sessions = getattr(server, "_calibrations", None)
    if sessions is None:
        sessions = {}
        server._calibrations = sessions
    return sessions


def _calibration_seconds(server: Any) -> float:
    value = getattr(server.config, "calibration_seconds", DEFAULT_CALIBRATION_SECONDS)
    return float(value) if probe_rules.is_number(value) else DEFAULT_CALIBRATION_SECONDS


def _calibratable(
    server: Any, ptype: str, uid: str
) -> Tuple[Optional[dict[str, Any]], Optional[Response]]:
    if ptype not in _CALIBRATION_POINTS:
        return None, _error(400, "This sensor type cannot be calibrated")
    return _plugged(server, ptype, uid)


def _cal_enter(server: Any, ptype: str, uid: str) -> Response:
    rec, failure = _calibratable(server, ptype, uid)
    if rec is None:
        return failure or _error(404, "Probe not found")
    _sessions(server)["%s:%s" % (ptype, uid)] = {"status": "idle", "done": []}
    return _ok("Calibration mode entered")


def _expected_outcome(ptype: str, point: str, value: float) -> str:
    """How the hub ends a point: a solution out of its range fails."""
    if ptype == "ph":
        low, high = _PH_SOLUTIONS[point]
        return "success" if low <= value <= high else "fail_check_solution"
    low, high = _EC_SOLUTIONS
    return "success" if low <= value <= high else "fail_value_error"


def _cal_point(server: Any, ptype: str, uid: str, body: Any) -> Response:
    rec, failure = _calibratable(server, ptype, uid)
    if rec is None:
        return failure or _error(404, "Probe not found")
    session = _sessions(server).get("%s:%s" % (ptype, uid))
    if session is None:
        return _error(503, "Calibration mode is not active")
    point = str(body.get("point", "")).upper() if isinstance(body, dict) else ""
    value = probe_rules.as_float(
        body.get("solution_value") if isinstance(body, dict) else None
    )
    if point not in _CALIBRATION_POINTS[ptype] or value is None:
        return _error(400, "Invalid calibration point")
    rated = body.get("solution_rated_temp")
    session.update(
        {
            "status": "in_progress",
            "point": point,
            "solution_value": value,
            "solution_rated_temp": rated if probe_rules.is_number(rated) else None,
            "started": _clock(),
            "outcome": _expected_outcome(ptype, point, value),
        }
    )
    return _ok("Calibration point started")


def _cal_progress(
    server: Any, rec: dict[str, Any], session: dict[str, Any]
) -> dict[str, Any]:
    """Where a point stands; settles it once the wait is over."""
    duration = _calibration_seconds(server)
    if session.get("status") == "in_progress":
        elapsed = _clock() - float(session.get("started", 0))
        if elapsed >= duration:
            session["status"] = session.get("outcome", "success")
            if session["status"] == "success":
                session["done"].append(
                    {
                        "point": session.get("point"),
                        "solution_value": session.get("solution_value"),
                        "solution_temperature": session.get("solution_rated_temp"),
                        "temperature_value": _reported(rec, "temp"),
                        "utc_time": _now(),
                        "local_time": _now(),
                    }
                )
        else:
            return {
                "calibration_status": "in_progress",
                "time_left": int(round(duration - elapsed)),
                "stability_progress": str(int(100 * elapsed / duration)),
            }
    return {
        "calibration_status": session.get("status", "idle"),
        "time_left": 0,
        "stability_progress": "100" if session.get("status") == "success" else "0",
    }


def _cal_status(server: Any, ptype: str, uid: str) -> Response:
    rec, failure = _calibratable(server, ptype, uid)
    if rec is None:
        return failure or _error(404, "Probe not found")
    session = _sessions(server).get("%s:%s" % (ptype, uid))
    if session is None:
        return 200, {
            "calibration_status": "idle",
            "time_left": 0,
            "stability_progress": "0",
        }
    return 200, _cal_progress(server, rec, session)


def _cal_exit(server: Any, ptype: str, uid: str) -> Response:
    rec, failure = _calibratable(server, ptype, uid)
    if rec is None:
        return failure or _error(404, "Probe not found")
    session = _sessions(server).pop("%s:%s" % (ptype, uid), None)
    if session is not None:
        _cal_progress(server, rec, session)
        if session["done"]:
            rec["last_adjustment_date"] = _now()
            log = rec.setdefault("_calibration_log", [])
            log.extend(session["done"])
    return _ok("Calibration mode exited")


def _cal_log(server: Any, ptype: str, uid: str, point: str) -> Response:
    rec = _find(server, ptype, uid)
    if rec is None:
        return _error(404, "Probe not found")
    entries = rec.get("_calibration_log", [])
    if point:
        entries = [
            e for e in entries if str(e.get("point", "")).upper() == point.upper()
        ]
    return 200, list(entries)


def _cal_restore(server: Any, ptype: str, uid: str) -> Response:
    rec, failure = _calibratable(server, ptype, uid)
    if rec is None:
        return failure or _error(404, "Probe not found")
    return _ok("Previous calibration restored")


def _cal_factory_reset(server: Any, ptype: str, uid: str) -> Response:
    rec, failure = _calibratable(server, ptype, uid)
    if rec is None:
        return failure or _error(404, "Probe not found")
    rec["last_adjustment_date"] = None
    rec["_calibration_log"] = []
    return _ok("Factory calibration restored")


# --------------------------------------------------------------------------
# Logs (synthetic)
# --------------------------------------------------------------------------
def _log(server: Any, ptype: str, uid: str, temperature: bool) -> Response:
    rec = _find(server, ptype, uid)
    base = 25.0
    if rec is not None:
        reading = _reported(rec, "temp" if temperature else "value")
        base = probe_rules.as_float(reading) or 0.0
    n = 4
    avg = [round(base, 2)] * n
    kind = "temperature" if temperature else "sensor"
    return 200, {
        "type": ptype,
        "uid": uid,
        "interval": 15,
        "date": (_now() // 900) * 900,
        "avg": avg,
        "min": [round(v - 0.1, 2) for v in avg],
        "max": [round(v + 0.1, 2) for v in avg],
        "count": [30] * n,
        "success": True,
        "message": "Get %s log success" % kind,
    }


# --------------------------------------------------------------------------
# Rules — /subscription-info, /ports/subscribe, /socket/<n>/subscribe
# --------------------------------------------------------------------------
def _subscription_info(server: Any) -> dict[str, Any]:
    data = _data(server, "/subscription-info", {"external": [], "internal": []})
    if not isinstance(data.get("external"), list):
        data["external"] = []
    if not isinstance(data.get("internal"), list):
        data["internal"] = []
    return data


def _rule(entries: list[dict[str, Any]], number: Any) -> Optional[dict[str, Any]]:
    for entry in entries:
        if isinstance(entry, dict) and entry.get("number") == number:
            return entry
    return None


def _binding(body: dict[str, Any], *, internal: bool) -> dict[str, Any]:
    """Normalise a subscribe body into a /subscription-info entry."""
    out: dict[str, Any] = {
        "number": body.get("number"),
        "type": body.get("type"),
        "uid": body.get("uid"),
        "trigger_op": body.get("trigger_op", False),
        "last_sock_op": "default",
        "sensor": body.get("sensor", "primary"),
    }
    for key in ("value", "is_above", "hysteresis"):
        if key in body:
            out[key] = body[key]
    if internal or "default_state" in body:
        out["default_state"] = body.get("default_state", False)
    return out


def _upsert(entries: list[dict[str, Any]], entry: dict[str, Any]) -> None:
    for i, e in enumerate(entries):
        if e.get("number") == entry.get("number"):
            entries[i] = entry
            return
    entries.append(entry)


def _drop_subscriptions(server: Any, uid: str) -> None:
    info = _subscription_info(server)
    info["external"] = [e for e in info["external"] if e.get("uid") != uid]
    info["internal"] = [e for e in info["internal"] if e.get("uid") != uid]


def _ports_subscribe(server: Any, body: Any) -> Response:
    ports = body.get("ports", []) if isinstance(body, dict) else []
    info = _subscription_info(server)
    for p in ports:
        if not isinstance(p, dict):
            continue
        _upsert(info["internal"], _binding(p, internal=True))
        entry = _port_entry(server, p.get("number"))
        if entry is not None:
            entry["sensor"] = {
                "default_state": p.get("default_state", False),
                "app_cache": None,
            }
    return _ok("Ports subscribed successfully")


def _socket_subscribe(server: Any, number: int, body: Any) -> Response:
    if not isinstance(body, dict):
        return _error(400, "Bad body")
    entry = _binding({**body, "number": number}, internal=False)
    _upsert(_subscription_info(server)["external"], entry)
    return _ok("Socket was subscribed successfully")


def _socket_unsubscribe(server: Any, number: int) -> Response:
    info = _subscription_info(server)
    info["external"] = [e for e in info["external"] if e.get("number") != number]
    return _ok("Socket was unsubscribed successfully")


# --------------------------------------------------------------------------
# 12V ports
# --------------------------------------------------------------------------
def _ports_config(server: Any) -> list[dict[str, Any]]:
    return _data(server, "/ports/config", [])


def _port_entry(server: Any, number: Any) -> Optional[dict[str, Any]]:
    for entry in _ports_config(server):
        if isinstance(entry, dict) and entry.get("number") == number:
            return entry
    return None


def _dash_port(server: Any, number: Any) -> Optional[dict[str, Any]]:
    dash = _dashboard(server) or {}
    for port in dash.get("ports", []) or []:
        if isinstance(port, dict) and port.get("number") == number:
            return port
    return None


def _installed(entry: dict[str, Any]) -> bool:
    return entry.get("type") not in (None, "unknown")


def _schedules(server: Any) -> dict[Any, dict[str, Any]]:
    schedules = getattr(server, "_port_schedules", None)
    if schedules is None:
        schedules = {}
        server._port_schedules = schedules
    return schedules


def _set_port(server: Any, number: Any, fields: dict[str, Any]) -> None:
    """Update a port in ``/ports/config`` and ``/dashboard``."""
    entry = _port_entry(server, number)
    if entry is not None:
        if "mode" in fields and fields["mode"] != entry.get("mode"):
            entry["_prev_mode"] = entry.get("mode")
        entry.update(fields)
        if "mode" in fields:
            entry["user_config_mode"] = fields["mode"]
    port = _dash_port(server, number)
    if port is not None:
        for key in ("mode", "type", "name"):
            if key in fields:
                port[key] = fields[key]
        if "mode" in fields:
            port["user_config_mode"] = fields["mode"]
            if fields["mode"] in ("on", "off", "setup"):
                port["state"] = "unknown"


def _ports_config_put(server: Any, body: Any) -> Response:
    """``PUT /ports/config`` — a bare array of (partial) port entries."""
    entries = body if isinstance(body, list) else [body]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        current = _port_entry(server, entry.get("number"))
        if current is None:
            continue
        if not _installed(current) and entry.get("type") in (None, "unknown"):
            return _error(503, "Failed configuring ports - port not installed")
        _set_port(
            server, entry["number"], {k: v for k, v in entry.items() if k != "number"}
        )
    return _ok("Ports configured successfully")


def _port_number(path: str) -> Optional[int]:
    try:
        return int(path.split("/")[2])
    except (IndexError, ValueError):
        return None


def _port_install(server: Any, number: int, body: Any) -> Response:
    if _port_entry(server, number) is None:
        return _error(404, "Port not found")
    ptype = body.get("type", "other") if isinstance(body, dict) else "other"
    _set_port(server, number, {"type": ptype})
    return _ok("Port installed successfully")


def _port_delete(server: Any, number: int) -> Response:
    if _port_entry(server, number) is None:
        return _error(404, "Port not found")
    _set_port(
        server,
        number,
        {
            "type": "unknown",
            "mode": "setup",
            "name": "S%d" % (number + 1),
            "power_on_percent": 100,
            "sensor": None,
        },
    )
    _schedules(server).pop(number, None)
    info = _subscription_info(server)
    info["internal"] = [e for e in info["internal"] if e.get("number") != number]
    return _ok("Successfully deleted port")


def _port_schedule_get(server: Any, number: int) -> Response:
    entry = _port_entry(server, number)
    if entry is None or not _installed(entry):
        return _error(503, "Failed to get schedule - port not installed")
    return 200, dict(_schedules(server).get(number, {"intervals": []}))


def _port_schedule_put(server: Any, number: int, body: Any) -> Response:
    entry = _port_entry(server, number)
    if entry is None or not _installed(entry):
        return _error(503, "Failed to set schedule - port not installed")
    intervals = body.get("intervals", []) if isinstance(body, dict) else []
    _schedules(server)[number] = {"intervals": list(intervals)}
    return _ok("Schedule set successfully")


def _port_toggle(server: Any, number: int) -> Response:
    """Flip a port: off → its previous automatic mode (or on), else off."""
    entry = _port_entry(server, number)
    if entry is None or not _installed(entry):
        return _error(503, "Failed to toggle port")
    mode = entry.get("mode")
    previous = entry.get("_prev_mode")
    if mode == "off":
        new = previous if previous in ("schedule", "sensor") else "on"
    else:
        new = "off"
    _set_port(server, number, {"mode": new})
    return _ok("Port toggled successfully")


# --------------------------------------------------------------------------
# Hub-wide settings
# --------------------------------------------------------------------------
def _leak_config(server: Any) -> dict[str, Any]:
    dash = _dashboard(server) or {}
    return _data(
        server,
        "/leak/config",
        {
            "buzzer": True,
            "leak_detector": bool(dash.get("leak_detector", True)),
            "notify": True,
            "emergency_shutdown": False,
        },
    )


def _set_leak_detector(server: Any, enabled: bool) -> None:
    """The hub-wide leak detection, shown in three places."""
    _configuration(server)["leak_detector"] = enabled
    _leak_config(server)["leak_detector"] = enabled
    dash = _dashboard(server)
    if dash is not None:
        dash["leak_detector"] = enabled


def _leak_config_put(server: Any, body: Any) -> Response:
    if not isinstance(body, dict):
        return _error(400, "Bad body")
    _leak_config(server).update(body)
    if "leak_detector" in body:
        _set_leak_detector(server, bool(body["leak_detector"]))
    return _ok("Leak config updated")


def _configuration_put(server: Any, body: Any) -> Response:
    if not isinstance(body, dict):
        return _error(400, "Bad body")
    conf = _configuration(server)
    for key, value in body.items():
        if isinstance(value, dict) and isinstance(conf.get(key), dict):
            conf[key].update(value)
        else:
            conf[key] = value
    if "leak_detector" in body:
        _set_leak_detector(server, bool(body["leak_detector"]))
    return _ok("Configuration updated successfully")


def setup_finish(server: Any) -> Response:
    """``POST /setup-finish`` — the device leaves setup mode."""
    dash = _dashboard(server)
    if dash is not None:
        dash["mode"] = "auto"
    _data(server, "/mode", {})["mode"] = "auto"
    return _ok("Setup finished successfully")


# --------------------------------------------------------------------------
# Link with an RSPower strip
# --------------------------------------------------------------------------
def _is_power(server: Any) -> bool:
    dash = _dashboard(server)
    return isinstance(dash, dict) and "sockets" in dash


def _power_is_free(power: Any) -> bool:
    """A strip pairs only when linked to no hub and without its own probe."""
    dash = _dashboard(power) or {}
    return not dash.get("connected_device") and not dash.get("temperature")


def paired_power(server: Any) -> Optional[Any]:
    """The strip this hub is paired with, when it is running."""
    connected = (_dashboard(server) or {}).get("connected_device") or {}
    return registry.by_hwid(connected.get("hwid"))


def _pairing_candidate(server: Any) -> Optional[Any]:
    """The strip a pairing would link: the configured peer when it is free,
    else the first free strip."""
    peer = registry.by_name(getattr(server.config, "paired_with", None))
    if peer is not None and _is_power(peer) and _power_is_free(peer):
        return peer
    for other in registry.servers():
        if other is not server and _is_power(other) and _power_is_free(other):
            return other
    return None


def link(hub: Any, power: Any) -> None:
    """Pair a hub and a strip: each reports the other."""
    hub_dash = _dashboard(hub)
    power_dash = _dashboard(power)
    if hub_dash is not None:
        hub_dash["connected_device"] = {
            "state": "paired_connected",
            "hwid": registry.hwid(power),
            "internet_connected": True,
        }
    if power_dash is not None:
        power_dash["connected_device"] = {
            "type": "control",
            "hwid": registry.hwid(hub),
            "status": "connected",
            "internet_connected": True,
        }


def unlink(hub: Optional[Any], power: Optional[Any]) -> None:
    """Unpair: both forget each other, the hub drops the socket rules."""
    if hub is not None:
        dash = _dashboard(hub)
        if dash is not None:
            dash["connected_device"] = None
        _subscription_info(hub)["external"] = []
    if power is not None:
        dash = _dashboard(power)
        if dash is not None:
            dash["connected_device"] = None


def _power_discover(server: Any, body: Any) -> Response:
    pair = bool(body.get("pair")) if isinstance(body, dict) else False
    current = paired_power(server)
    if current is not None:
        return 200, {"hwid": registry.hwid(current), "paired": True, "success": True}
    candidate = _pairing_candidate(server)
    if not pair:
        return 200, {
            "hwid": registry.hwid(candidate) if candidate is not None else "",
            "pairing_status": "unpaired",
        }
    if candidate is None:
        return _error(503, "No power center found")
    link(server, candidate)
    return 200, {"hwid": registry.hwid(candidate), "paired": True, "success": True}


def _power_unpair(server: Any) -> Response:
    unlink(server, paired_power(server))
    return _ok("Power center unpaired successfully")


# --------------------------------------------------------------------------
# Simulator controls
# --------------------------------------------------------------------------
def _sim_probe(server: Any, ptype: str, uid: str, body: Any) -> Response:
    rec = _find(server, ptype, uid)
    if rec is None:
        return _error(404, "Probe not found")
    if not isinstance(body, dict):
        return _error(400, "Bad body")
    for key in ("value", "temp", "water_level", "ppt", "sg", "ec"):
        if key in body:
            rec[key] = body[key]
    if "leak_status" in body and body["leak_status"] in _LEAK_EC:
        rec["leak_status"] = body["leak_status"]
        rec.pop("ec", None)
    if "status" in body:
        rec["status"] = "disconnected" if body["status"] in _UNPLUGGED else "auto"
    return 200, {
        "success": True,
        "probe": project_dashboard_probes({"probes": [rec]})[0],
    }


# Raw fields a scenario reads back and writes with PUT /sim/probe
_SIM_FIELDS = ("value", "temp", "water_level", "leak_status", "ppt", "sg", "status")


def _sim_probes(server: Any) -> Response:
    """Raw state of every probe, offsets not applied."""
    out = []
    for rec in _probes(server):
        entry = {"type": rec.get("type"), "uid": rec.get("uid")}
        for key in _SIM_FIELDS:
            if key in rec:
                entry[key] = rec[key]
        if rec.get("type") == "leak":
            entry["leak_status"] = _leak_status(rec)
        out.append(entry)
    return 200, {"probes": out}


def sim_clock(body: Any) -> Response:
    """``PUT /sim/clock``: pin the schedules clock, or release it."""
    if not isinstance(body, dict) or "minute" not in body:
        return _error(400, "Bad body")
    minute = body["minute"]
    if minute is not None and not probe_rules.is_number(minute):
        return _error(400, "minute must be a number or null")
    probe_rules.set_clock(None if minute is None else int(minute))
    return 200, {"success": True, "minute": probe_rules.clock()}


def sim_watts(server: Any, body: Any) -> Response:
    """``PUT /sim/watts``: what each output draws while powered.

    Keys are output numbers (0-based, as the API numbers them); an empty
    mapping stops simulating the consumption.
    """
    watts = body.get("watts") if isinstance(body, dict) else None
    if not isinstance(watts, dict):
        return _error(400, "Bad body")
    table: dict[int, float] = {}
    for key, value in watts.items():
        number = probe_rules.as_float(value)
        try:
            table[int(key)] = number if number is not None else 0.0
        except (TypeError, ValueError):
            return _error(400, "Bad output number %r" % key)
    server._sim_watts = table
    return 200, {"success": True, "watts": {str(k): v for k, v in table.items()}}


def consumption(server: Any, number: Any, powered: bool, current: Any) -> Any:
    """What an output reports drawing: its simulated watts while powered,
    0 when not, or the stored value when it is not simulated."""
    table = getattr(server, "_sim_watts", None) or {}
    if number not in table:
        return current
    return table[number] if powered else 0


def _sim_buzzer(server: Any, body: Any) -> Response:
    dash = _dashboard(server)
    if dash is None or not isinstance(body, dict):
        return _error(400, "Bad body")
    buzzer = dash.setdefault(
        "buzzer", {"active": False, "cause": "none", "dismissed": False}
    )
    if "dismissed" in body:
        buzzer["dismissed"] = bool(body["dismissed"])
    return 200, {"success": True, "buzzer": _buzzer(server, dash)}


# --------------------------------------------------------------------------
# Dispatch entry point
# --------------------------------------------------------------------------
def _handle_get(server: Any, path: str, q: dict[str, list[str]]) -> Optional[Response]:
    ptype, uid = _query(q, "type"), _query(q, "uid")
    if path.startswith("/port/") and path.endswith("/schedule"):
        number = _port_number(path)
        return None if number is None else _port_schedule_get(server, number)
    if path.startswith("/probe/") and path.endswith("/calibration-log"):
        parts = path.split("/")
        if len(parts) == 5:
            return _cal_log(server, parts[2], parts[3], "")
    if path not in _GET_PATHS:
        return None
    if path == "/probe/config":
        return _config_list(server)
    if path == "/subscription-info":
        return 200, _subscription_info(server)
    if path == "/sim/probes":
        return _sim_probes(server)
    if path == "/sim/clock":
        return 200, {"minute": probe_rules.clock()}
    if path == "/leak/config":
        return 200, _leak_config(server)
    if path == "/probe":
        return _detail(server, ptype, uid)
    if path == "/probe/info":
        return _info(server, ptype, uid)
    if path == "/probe/offset":
        return _offset_get(server, ptype, uid)
    if path == "/probe/calibration-status":
        return _cal_status(server, ptype, uid)
    if path == "/probe/calibration-log":
        return _cal_log(server, ptype, uid, _query(q, "point"))
    return _log(server, ptype, uid, temperature=path == "/temperature-log")


def _handle_post(
    server: Any, path: str, q: dict[str, list[str]], body: Any
) -> Optional[Response]:
    ptype, uid = _query(q, "type"), _query(q, "uid")
    if path.startswith("/port/"):
        number = _port_number(path)
        if number is None:
            return None
        if path.endswith("/install"):
            return _port_install(server, number, body)
        if path.endswith("/toggle"):
            return _port_toggle(server, number)
        return None
    handlers = {
        "/probe/install": lambda: _install(server, ptype),
        "/ble/off": lambda: _ok("BLE advertising stopped"),
        "/probe/disable": lambda: _disable(server, ptype, uid, disabled=True),
        "/probe/offset": lambda: _offset_set(server, ptype, uid, body),
        "/probe/calibration-enter": lambda: _cal_enter(server, ptype, uid),
        "/probe/calibration-point-start": lambda: _cal_point(server, ptype, uid, body),
        "/probe/calibration-exit": lambda: _cal_exit(server, ptype, uid),
        "/probe/calibration-restore": lambda: _cal_restore(server, ptype, uid),
        "/probe/calibration-factory-reset": lambda: _cal_factory_reset(
            server, ptype, uid
        ),
        "/power/discover": lambda: _power_discover(server, body),
        "/power/unpair": lambda: _power_unpair(server),
        "/setup-finish": lambda: setup_finish(server),
    }
    handler = handlers.get(path)
    return handler() if handler else None


def _handle_put(
    server: Any, path: str, q: dict[str, list[str]], body: Any
) -> Optional[Response]:
    if path.startswith("/socket/"):
        number = _port_number(path)
        if number is None:
            return _error(400, "Bad socket number")
        if path.endswith("/subscribe"):
            return _socket_subscribe(server, number, body)
        if path.endswith("/unsubscribe"):
            return _socket_unsubscribe(server, number)
        return None
    if path.startswith("/port/") and path.endswith("/schedule"):
        number = _port_number(path)
        return None if number is None else _port_schedule_put(server, number, body)
    handlers = {
        "/probe/config": lambda: _configure(server, body),
        "/ports/subscribe": lambda: _ports_subscribe(server, body),
        "/ports/config": lambda: _ports_config_put(server, body),
        "/leak/config": lambda: _leak_config_put(server, body),
        "/configuration": lambda: _configuration_put(server, body),
        "/sim/probe": lambda: _sim_probe(
            server, _query(q, "type"), _query(q, "uid"), body
        ),
        "/sim/buzzer": lambda: _sim_buzzer(server, body),
        "/sim/clock": lambda: sim_clock(body),
        "/sim/watts": lambda: sim_watts(server, body),
    }
    handler = handlers.get(path)
    return handler() if handler else None


def _handle_delete(
    server: Any, path: str, q: dict[str, list[str]]
) -> Optional[Response]:
    ptype, uid = _query(q, "type"), _query(q, "uid")
    if path.startswith("/port/"):
        number = _port_number(path)
        if number is None or path.count("/") != 2:
            return None
        return _port_delete(server, number)
    if path == "/probe":
        return _delete(server, ptype, uid)
    if path == "/probe/disable":
        return _disable(server, ptype, uid, disabled=False)
    if path == "/probe/offset":
        return _offset_delete(server, ptype, uid)
    if path == "/setup-probes":
        return _delete_setup(server)
    return None


def handle(server: Any, method: str, raw_path: str, body: Any) -> Optional[Response]:
    """Handle an RSCONTROL request.

    Returns ``(status, json_value)`` if this module owns the path, else
    ``None`` so the caller falls back to the generic machinery.
    """
    if not is_control(server):
        return None
    parsed = urlparse(raw_path)
    path = parsed.path
    q = parse_qs(parsed.query)
    with registry.LOCK:
        if method == "GET":
            return _handle_get(server, path, q)
        if method == "POST":
            return _handle_post(server, path, q, body)
        if method == "PUT":
            return _handle_put(server, path, q, body)
        if method == "DELETE":
            return _handle_delete(server, path, q)
    return None


# --------------------------------------------------------------------------
# Dashboard projection modifier (wired via config.json "modifiers")
# --------------------------------------------------------------------------
def project_control_dashboard(
    path: str, data: dict[str, Any], params: Any, ctx: Any
) -> dict[str, Any]:
    """Project the stored hub state into the firmware ``/dashboard`` shape.

    Returns a shallow copy whose ``probes`` are the firmware-shaped records
    (offsets applied, private keys dropped), whose ports carry the state
    their schedule or probe rule gives, and whose buzzer follows the leaks
    and dangers. The stored records are left untouched.
    """
    if path != getattr(params, "path", None):
        return data
    if not isinstance(data, dict) or "probes" not in data:
        return data
    server = getattr(ctx, "server", None)
    projected = dict(data)
    projected["probes"] = project_dashboard_probes(data)
    if server is None:
        return projected
    with registry.LOCK:
        ports = []
        for port in data.get("ports", []) or []:
            if isinstance(port, dict):
                state = _port_state(server, port)
                port = dict(
                    port,
                    state=state,
                    consumption=consumption(
                        server,
                        port.get("number"),
                        state == "on",
                        port.get("consumption", 0),
                    ),
                )
            ports.append(port)
        projected["ports"] = ports
        projected["buzzer"] = _buzzer(server, data)
    return projected
