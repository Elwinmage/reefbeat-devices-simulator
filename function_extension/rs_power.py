"""Modifiers and handlers for the ReefPower smart power centers (RSPOWER6/8).

Covers what the Home Assistant integration and the reef card do with a strip,
besides the generic fixture machinery (socket config, toggles, schedules):

- sockets driven by the clock (schedule mode) or by a probe (sensor mode):
  a probe of the paired RSCONTROL hub, following the rule the hub keeps for
  that socket, or the strip's own local temperature probe;
- the local temperature probe: ``POST /sensor/install``, ``DELETE /sensor``,
  ``/temperature/config``, ``/temperature/subscribe`` and
  ``/temperature/subscriptions``, ``/temperature``, ``/temperature/log``,
  ``/temperature-probe-info`` and its offset (``/probe/offset``, which
  *adds* to the current offset). A strip takes either its own probe or a
  hub, never both;
- the link with the hub: ``DELETE /paired-device`` (the hub side pairs, see
  ``rs_control``), and the socket intent ``PUT /subscribe`` /
  ``PUT /unsubscribe``;
- ``POST /setup-finish``.

Simulator-only endpoints, to play a scenario without hardware:

- ``GET|PUT /sim/temperature``: ``{"value": <°C>}``, what the local probe
  measures (before its offset);
- ``PUT /sim/watts``: ``{"watts": {"<socket number>": <W>}}``, what a socket
  draws while powered (its ``consumption`` on ``/dashboard``);
- ``GET|PUT /sim/clock``: the schedules clock, as on the hub.
"""

from __future__ import annotations

import time as _time
from typing import Any, Optional
from urllib.parse import urlparse as _urlparse

from . import probe_rules, registry, rs_control

# Kept for callers of the former names
_minutes_now = probe_rules.minutes_now
_is_within = probe_rules.is_within


def _pw_dashboard(server: Any) -> Optional[dict[str, Any]]:
    entry = server._db.get("/dashboard")
    if not entry:
        return None
    data = entry.get("data")
    return data if isinstance(data, dict) else None


def is_power(server: Any) -> bool:
    """Recognise an RSPower strip from the shape of its dashboard."""
    dash = _pw_dashboard(server)
    return isinstance(dash, dict) and "sockets" in dash


def paired_hub(server: Any) -> Optional[Any]:
    """The RSCONTROL hub this strip is paired with, when it is running."""
    connected = (_pw_dashboard(server) or {}).get("connected_device") or {}
    hub = registry.by_hwid(connected.get("hwid"))
    return hub if hub is not None and rs_control.is_control(hub) else None


# ---------------------------------------------------------------------------
# Sockets driven by the clock or by a probe
# ---------------------------------------------------------------------------
def _socket_sensor(server: Any, number: int) -> dict[str, Any]:
    """The ``sensor`` block ``/sockets/config`` keeps for a socket."""
    entry = server._db.get("/sockets/config") or {}
    data = entry.get("data")
    sockets = data.get("sockets") if isinstance(data, dict) else None
    for socket in sockets if isinstance(sockets, list) else []:
        if isinstance(socket, dict) and socket.get("number") == number:
            sensor = socket.get("sensor")
            return sensor if isinstance(sensor, dict) else {}
    return {}


def _local_rule(server: Any, number: int) -> Optional[dict[str, Any]]:
    for rule in _pw_subs(server)["sockets"]:
        if isinstance(rule, dict) and rule.get("number") == number:
            return rule
    return None


def _local_reading(server: Any, rule: dict[str, Any]) -> Any:
    st = _pw_state(server)
    if not st["installed"]:
        return None
    return _reported(st)


def _sensor_powered(server: Any, number: int) -> bool:
    """Whether a socket in sensor mode is powered.

    The hub's rule for that socket when the strip is paired, else the rule
    of the local probe, else the socket's ``default_state``.
    """
    hub = paired_hub(server)
    if hub is not None:
        powered = rs_control.socket_powered(hub, number)
        if powered is not None:
            return powered
    rule = _local_rule(server, number)
    if rule is not None:
        last = rule.get("last_sock_op")
        previous = None if last not in ("on", "off") else last == "on"
        powered = probe_rules.evaluate(rule, _local_reading(server, rule), previous)
        rule["last_sock_op"] = "on" if powered else "off"
        return powered
    return probe_rules.is_on(_socket_sensor(server, number).get("default_state", False))


def apply_socket_schedules(
    path: str, data: dict[str, Any], params: Any, ctx: Any
) -> dict[str, Any]:
    """Drive the sockets that follow a schedule or a probe.

    A real strip decides for itself whether such a socket is powered right
    now; the simulator serves a fixture, so without this the socket stays at
    whatever state was written into it and a schedule or a probe rule can
    never be seen working. Sockets in any other mode are left as they are:
    their state is owned by the toggle actions and by what a client wrote.

    Args:
        path: the endpoint being served.
        data: the dashboard payload, modified in place.
        params: modifier parameters; ``path`` selects the endpoint.
        ctx: the request context, carrying the server and its DB.

    Returns:
        The dashboard payload.
    """
    if path != getattr(params, "path", None):
        return data
    server = getattr(ctx, "server", None)
    if server is None:
        return data
    sockets = data.get("sockets")
    if not isinstance(sockets, list):
        return data
    minute = probe_rules.minutes_now()
    with registry.LOCK:
        for index, socket in enumerate(sockets):
            if not isinstance(socket, dict):
                continue
            _drive_socket(server, index, socket, minute)
            socket["consumption"] = rs_control.consumption(
                server,
                index,
                socket.get("state") == "on",
                socket.get("consumption", 0),
            )
    return data


def _drive_socket(server: Any, index: int, socket: dict[str, Any], minute: int) -> None:
    """Set the state of a socket following a schedule or a probe.

    Sockets in any other mode keep the state their toggles wrote.
    """
    mode = socket.get("mode")
    if mode == "schedule":
        entry = server._db.get(f"/socket/{index}/config/schedule", {})
        schedule = entry.get("data")
        if not isinstance(schedule, dict):
            return
        powered = probe_rules.is_within(schedule.get("intervals"), minute)
        socket["state"] = "on" if powered else "standby"
    elif mode == "sensor":
        powered = _sensor_powered(server, index)
        socket["state"] = "on" if powered else "standby"


# ---------------------------------------------------------------------------
# Local temperature probe
# ---------------------------------------------------------------------------
# A standalone temperature probe plugged straight into the strip, distinct
# from the RSCONTROL probe hub: a single probe, its ranges carried as named
# fields (``desired_range_*`` / ``acceptable_range_*``), exposed at the top of
# ``/dashboard`` as ``temperature``.

_CONFIG_KEYS = (
    "name",
    "log_enabled",
    "notifications_enabled",
    "desired_range_low",
    "desired_range_high",
    "acceptable_range_low",
    "acceptable_range_high",
)


def _pw_state(server: Any) -> dict[str, Any]:
    """Per-server store for the local temperature probe (config/offset)."""
    st = getattr(server, "_local_temp", None)
    if st is None:
        st = {
            "uid": None,
            "name": "Temp",
            "value": 25.0,
            "log_enabled": True,
            "notifications_enabled": True,
            "desired_range_low": 25,
            "desired_range_high": 26,
            "acceptable_range_low": 24,
            "acceptable_range_high": 28,
            "offset": 0,
            "last_adjustment_date": 0,
            "installed": False,
        }
        # A fixture may carry the config of a probe installed before
        fixture = (server._db.get("/temperature/config") or {}).get("data")
        if isinstance(fixture, dict):
            for key in (*_CONFIG_KEYS, "offset", "last_adjustment_date", "uid"):
                if key in fixture:
                    st[key] = fixture[key]
        dash = _pw_dashboard(server) or {}
        st["installed"] = bool(dash.get("temperature"))
        server._local_temp = st
    return st


def _reported(st: dict[str, Any]) -> float:
    """The temperature the strip reports: the reading plus its offset."""
    return round(float(st["value"]) + float(st.get("offset", 0) or 0), 2)


def _pw_level(st: dict[str, Any], value: float) -> str:
    al = st["acceptable_range_low"]
    dl = st["desired_range_low"]
    dh = st["desired_range_high"]
    ah = st["acceptable_range_high"]
    if value < al or value > ah:
        return "danger"
    if dl <= value <= dh:
        return "desired"
    return "acceptable"


def _pw_reflect(server: Any) -> None:
    """Project the local-temp store into ``/dashboard``'s ``temperature``."""
    dash = _pw_dashboard(server)
    if dash is None:
        return
    st = _pw_state(server)
    if not st["installed"]:
        dash["temperature"] = None
        return
    value = _reported(st)
    dash["temperature"] = {
        "value": value,
        "status": "connected",
        "level": _pw_level(st, value),
        "last_installation_date": st.get("last_installation_date_iso", ""),
        "name": st["name"],
        "uid": st["uid"],
    }


def _pw_subs(server: Any) -> dict[str, Any]:
    entry = server._db.get("/temperature/subscriptions")
    if not entry:
        server._db["/temperature/subscriptions"] = {
            "access": {"rights": ["GET"]},
            "data": {"sensor_uid": None, "sockets": []},
        }
        entry = server._db["/temperature/subscriptions"]
    data = entry.get("data")
    if not isinstance(data, dict):
        data = {"sensor_uid": None, "sockets": []}
        entry["data"] = data
    if not isinstance(data.get("sockets"), list):
        data["sockets"] = []
    return data


def _pw_sub_upsert(entries: list, entry: dict) -> None:
    for i, e in enumerate(entries):
        if e.get("number") == entry.get("number"):
            entries[i] = entry
            return
    entries.append(entry)


def _sockets_config(server: Any) -> list[dict[str, Any]]:
    entry = server._db.get("/sockets/config") or {}
    data = entry.get("data")
    sockets = data.get("sockets") if isinstance(data, dict) else None
    return sockets if isinstance(sockets, list) else []


def _ok(message: str):
    return 200, {"success": True, "message": message}


def _no_probe():
    return 404, {"success": False, "message": "No temperature sensor installed"}


def _install(server: Any):
    st = _pw_state(server)
    if paired_hub(server) is not None or (_pw_dashboard(server) or {}).get(
        "connected_device"
    ):
        # A strip reads its temperature either from its own probe or from
        # the hub it is paired with, never both
        return 503, {
            "success": False,
            "message": "Failed to install sensor - device is paired with a control",
        }
    st["uid"] = st["uid"] or "0x000F7"
    st["installed"] = True
    st["last_installation_date_iso"] = _time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", _time.gmtime()
    )
    _pw_subs(server)["sensor_uid"] = st["uid"]
    _pw_reflect(server)
    return 200, {"uid": st["uid"], "success": True}


def _remove(server: Any):
    st = _pw_state(server)
    st["installed"] = False
    st["uid"] = None
    subs = _pw_subs(server)
    subs["sensor_uid"] = None
    subs["sockets"] = []
    _pw_reflect(server)
    return _ok("Temperature sensor was deleted successfully")


def _offset_add(server: Any, body: Any):
    """``POST /probe/offset`` — *adds* the posted value to the offset."""
    st = _pw_state(server)
    if not st["installed"]:
        return _no_probe()
    delta = probe_rules.as_float(body.get("offset") if isinstance(body, dict) else None)
    if delta is None:
        return 400, {"success": False, "message": "Missing offset"}
    st["offset"] = round((probe_rules.as_float(st.get("offset")) or 0.0) + delta, 3)
    st["last_adjustment_date"] = int(_time.time())
    _pw_reflect(server)
    return _ok("Calibration point set successfully")


def _subscribe(server: Any, body: Any):
    """``PUT /subscribe`` — the probe type a socket follows from the hub."""
    socks = body.get("sockets", []) if isinstance(body, dict) else []
    by_number = {
        s.get("number"): s for s in _sockets_config(server) if isinstance(s, dict)
    }
    for s in socks:
        if isinstance(s, dict) and s.get("number") in by_number:
            by_number[s["number"]]["sensor"] = {
                "app_cache": s.get("app_cache"),
                "default_state": s.get("default_state", False),
            }
    return _ok("Sockets were subscribed successfully")


def _unsubscribe(server: Any, body: Any):
    """``PUT /unsubscribe`` — sockets no longer follow a probe."""
    numbers = body.get("sockets", []) if isinstance(body, dict) else []
    subs = _pw_subs(server)
    subs["sockets"] = [s for s in subs["sockets"] if s.get("number") not in numbers]
    for socket in _sockets_config(server):
        if isinstance(socket, dict) and socket.get("number") in numbers:
            socket["sensor"] = None
    return _ok("Sockets were unsubscribed successfully")


def _socket_index(path: str) -> Optional[int]:
    try:
        return int(path.split("/")[2])
    except (IndexError, ValueError):
        return None


def _sockets_config_put(server: Any, body: Any):
    """``PUT /sockets/config`` — partial: only the sockets sent change.

    Merged socket by socket (``number``) into ``/sockets/config`` and
    mirrored onto ``/dashboard``, as the strip does: a client polling the
    dashboard sees the new name / mode at once.
    """
    incoming = body.get("sockets") if isinstance(body, dict) else None
    if not isinstance(incoming, list):
        incoming = [body] if isinstance(body, dict) and "number" in body else []
    config = {
        s.get("number"): s for s in _sockets_config(server) if isinstance(s, dict)
    }
    dash_sockets = (_pw_dashboard(server) or {}).get("sockets")
    dash_sockets = dash_sockets if isinstance(dash_sockets, list) else []
    for entry in incoming:
        number = entry.get("number") if isinstance(entry, dict) else None
        if not isinstance(entry, dict) or not isinstance(number, int):
            continue
        fields = {k: v for k, v in entry.items() if k != "number"}
        if number in config:
            config[number].update(fields)
            if "mode" in fields:
                config[number]["user_config_mode"] = fields["mode"]
        if 0 <= number < len(dash_sockets) and isinstance(dash_sockets[number], dict):
            socket = dash_sockets[number]
            if "mode" in fields and fields["mode"] != socket.get("mode"):
                socket["prev_mode"] = socket.get("mode", "setup")
            for key in ("name", "mode", "enabled"):
                if key in fields:
                    socket[key] = fields[key]
            if "mode" in fields:
                socket["user_config_mode"] = fields["mode"]
                if fields["mode"] in ("on", "off", "setup"):
                    socket["state"] = "unknown" if fields["mode"] != "on" else "on"
    return 200, {
        "success": True,
        "message": "Sockets configuration was set successfully",
    }


def _socket_delete(server: Any, number: int):
    """``DELETE /socket/<n>/config`` — the socket goes back to setup.

    Reset on ``/dashboard`` and ``/sockets/config``, and it no longer follows
    the local probe. The rule a paired hub keeps for it is the hub's
    (``PUT /socket/<n>/unsubscribe`` there).
    """
    dash_sockets = (_pw_dashboard(server) or {}).get("sockets")
    if not isinstance(dash_sockets, list) or not 0 <= number < len(dash_sockets):
        return 404, {"success": False, "message": "Socket not found"}
    name = "S%d" % (number + 1)
    socket = dash_sockets[number]
    if isinstance(socket, dict):
        socket.update(
            {
                "mode": "setup",
                "prev_mode": "setup",
                "user_config_mode": "setup",
                "name": name,
                "consumption": 0,
                "state": "unknown",
                "enabled": True,
            }
        )
    for entry in _sockets_config(server):
        if isinstance(entry, dict) and entry.get("number") == number:
            entry.update(
                {
                    "mode": "setup",
                    "user_config_mode": "setup",
                    "name": name,
                    "sensor": None,
                }
            )
    subs = _pw_subs(server)
    subs["sockets"] = [s for s in subs["sockets"] if s.get("number") != number]
    return 200, {"success": True, "message": "Successfully deleted sockets"}


def _unpair(server: Any):
    rs_control.unlink(paired_hub(server), server)
    return _ok("Paired device was deleted successfully")


def _get(server: Any, path: str):
    st = _pw_state(server)
    if path == "/temperature":
        if not st["installed"]:
            return _no_probe()
        return 200, {"temperature": _reported(st)}
    if path == "/temperature-probe-info":
        if not st["installed"]:
            return _no_probe()
        return 200, {
            "type": "temperature",
            "uid": st["uid"],
            "hwid": "383835366136",
            "hw_revision": "1.2_25A",
            "version": "1.1.8",
            "last_fota_time": int(_time.time()),
        }
    if path == "/temperature/config":
        if not st["installed"]:
            return _no_probe()
        return 200, {
            "uid": st["uid"],
            **{key: st[key] for key in _CONFIG_KEYS},
            "offset": st.get("offset", 0),
            "last_adjustment_date": st.get("last_adjustment_date", 0),
        }
    if path == "/temperature/subscriptions":
        if not st["installed"]:
            return _no_probe()
        return 200, _pw_subs(server)
    if path == "/temperature/log":
        if not st["installed"]:
            return _no_probe()
        base = _reported(st)
        return 200, {
            "interval": 15,
            "date": _time.strftime("%Y-%m-%dT%H:00:00+00:00", _time.gmtime()),
            "avg": [round(base, 2)] * 4,
            "min": [round(base - 0.1, 2)] * 4,
            "max": [round(base + 0.1, 2)] * 4,
            "count": [30] * 4,
        }
    if path == "/probe/offset":
        if not st["installed"]:
            return _no_probe()
        return 200, {
            "offset": round(float(st.get("offset", 0) or 0), 3),
            "last_adjustment_date": st.get("last_adjustment_date", 0),
            "success": True,
            "message": "Got temperature offset successfully",
        }
    return None


def _sim(server: Any, method: str, path: str, body: Any):
    """Simulator-only endpoints of a strip."""
    st = _pw_state(server)
    if path == "/sim/temperature":
        if method == "GET":
            return 200, {"installed": st["installed"], "value": st["value"]}
        if method == "PUT":
            value = probe_rules.as_float(
                body.get("value") if isinstance(body, dict) else None
            )
            if value is None:
                return 400, {"success": False, "message": "Missing value"}
            st["value"] = value
            _pw_reflect(server)
            return 200, {"success": True, "value": value}
    if path == "/sim/watts" and method == "PUT":
        return rs_control.sim_watts(server, body)
    if path == "/sim/clock":
        if method == "GET":
            return 200, {"minute": probe_rules.clock()}
        if method == "PUT":
            return rs_control.sim_clock(body)
    return None


def handle_local_temp(server: Any, method: str, raw_path: str, body: Any):
    """Handle an RSPower request this module owns.

    Returns ``(status, json_value)`` when it owns the path, else ``None``.
    """
    if not is_power(server):
        return None
    path = _urlparse(raw_path).path
    with registry.LOCK:
        st = _pw_state(server)
        if path.startswith("/sim/"):
            return _sim(server, method, path, body)
        if method == "GET":
            return _get(server, path)
        if method == "POST":
            if path == "/sensor/install":
                return _install(server)
            if path == "/ble/off":
                return _ok("BLE advertising stopped")
            if path == "/probe/offset":
                return _offset_add(server, body)
            if path == "/setup-finish":
                return rs_control.setup_finish(server)
            return None
        if method == "PUT":
            if path == "/temperature/config":
                if not st["installed"]:
                    return _no_probe()
                if isinstance(body, dict):
                    for key in _CONFIG_KEYS:
                        if key in body:
                            st[key] = body[key]
                _pw_reflect(server)
                return _ok("Temperature configuration was set successfully")
            if path == "/temperature/subscribe":
                subs = _pw_subs(server)
                socks = body.get("sockets", []) if isinstance(body, dict) else []
                for s in socks:
                    if isinstance(s, dict) and "number" in s:
                        _pw_sub_upsert(subs["sockets"], dict(s))
                return _ok("Sockets were subscribed to temperature successfully")
            if path == "/subscribe":
                return _subscribe(server, body)
            if path == "/unsubscribe":
                return _unsubscribe(server, body)
            if path == "/sockets/config":
                return _sockets_config_put(server, body)
            return None
        if method == "DELETE":
            if path == "/sensor":
                return _remove(server)
            if path == "/paired-device":
                return _unpair(server)
            if path.startswith("/socket/") and path.endswith("/config"):
                number = _socket_index(path)
                if number is not None and path.count("/") == 3:
                    return _socket_delete(server, number)
            if path == "/probe/offset":
                if not st["installed"]:
                    return _no_probe()
                st["offset"] = 0
                st["last_adjustment_date"] = int(_time.time())
                _pw_reflect(server)
                return _ok("Temperature offset deleted successfully")
            return None
    return None
