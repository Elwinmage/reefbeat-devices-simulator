#!/usr/bin/python3
"""ReefBeat device simulator HTTP servers.

This module starts one HTTP server per configured device, serving fixture data from
the local `devices/` tree and applying JSON merges for state updates.

Usage:
    Run the simulator from the repo root so it can find `config.json` and the
    fixture files under `devices/`:

        ./reefbeat-devices.py

    The script reads `config.json` and starts one HTTP server per entry in
    `devices`. Each server binds to the configured `ip`/`port` and serves
    responses from the local fixture tree.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
import traceback
import hashlib
import uuid
from collections.abc import Sequence as ABCSequence
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from types import SimpleNamespace
from typing import Any, MutableMapping, Optional, Protocol, Sequence, Union, cast

from jsonmerge import merge  # type: ignore[import]
from optparse import OptionParser

import function_extension

JSONValue = Any

# --- ReefATO+ manual fill -----------------------------------------------------
#
# `flow_rate` is reported on /dashboard without a unit. Milliliters per minute
# is the reading that makes a device self-consistent: the fixture's 1176 with a
# `daily_volume_average` of 25000 ml works out to about 21 minutes of pumping a
# day, which is what a mid-size system does. Read as ml/h the same numbers give
# 8 hours a day, which no ATO pump does. Change this single constant if a pcap
# ever settles the question.
ATO_FLOW_RATE_PERIOD_S: float = 60.0

# How long a manual fill runs before the pump stops on its own, when
# /configuration carries no `custom_pump_time` (milliseconds).
ATO_DEFAULT_PUMP_TIME_MS: int = 30000


class Object(object):
    server: "MyServer | None"


class PostActionRule(Protocol):
    """A rule that defines a post-action to evaluate and apply.

    Attributes:
        action: Python expression string evaluated via `eval()`.
        target: The API path in the in-memory DB to update.
    """

    action: str
    target: str


class RequestPostAction(Protocol):
    """Maps a request path to one or more post-actions."""

    request: str
    action: Union[PostActionRule, Sequence[PostActionRule]]


class AccessControl(Protocol):
    """Access-control configuration for endpoints."""

    no_GET: Sequence[str]


class ModifierFunction(Protocol):
    name: str
    params: Any
    # Set by the scheduler once a `only_once` / `only_startup` modifier has
    # run, so it is skipped on later ticks. Declared here because the flag
    # is written onto the function object itself; the read side uses
    # getattr() with a default, so it need not exist on the first tick.
    _fired: bool


class ServerConfig(Protocol):
    """Configuration required to run a simulated device HTTP server."""

    enabled: bool
    name: str
    ip: str
    port: int
    base_url: str
    access: AccessControl
    post_actions: Sequence[RequestPostAction]
    actions: str
    modifiers: Optional[Sequence[ModifierFunction]]


class MyServer(HTTPServer):
    """HTTP server that serves fixture data and maintains an in-memory DB.

    The DB is populated by loading all `data` files under the current working
    directory. JSON payloads are merged into existing state using `jsonmerge`.
    """

    config: ServerConfig
    _db: dict[str, dict[str, Any]]

    def __init__(
        self, handler: type[BaseHTTPRequestHandler], config: ServerConfig
    ) -> None:
        """Initialize the server and preload all fixture data.

        Args:
            handler: Request handler class (typically `HttpServer`).
            config: Device/server configuration.

        Returns:
            None
        """
        self._ctx = Object()
        self._ctx.server = self
        self.config = config
        with open(self.config.actions) as f:
            self.actions = cast(
                ServerConfig,
                json.loads(
                    json.dumps(json.load(f)), object_hook=lambda d: SimpleNamespace(**d)
                ),
            )

        self._db = {}
        # Tracks which sub-calibration (skim/cup) was performed last so that
        # DELETE /calibration only bumps the matching *last_calibration_date*
        # field, matching the real ReefRun behaviour observed in pcaps.
        self._last_calibration_type: Optional[str] = None
        # ReefATO+ manual fill in progress, `None` when the pump is idle.
        # `_ato_fill_started_at` is what the auto-stop timeout is measured
        # against, `_ato_fill_last_tick` what the volume accounting consumes,
        # and `_ato_fill_carry` holds the sub-milliliter remainder so that a
        # burst of short polls dispenses the same volume as one long one.
        self._ato_fill_started_at: Optional[float] = None
        self._ato_fill_last_tick: Optional[float] = None
        self._ato_fill_carry: float = 0.0
        # Test if local IP exists
        must_create_ip = True
        for line in (
            subprocess.Popen(
                ["ip", "addr", "show", "dev", "eth0"], stdout=subprocess.PIPE
            )
            .communicate()[0]
            .splitlines()
        ):
            if "inet " + config.ip in str(line):
                must_create_ip = False
                break
        if must_create_ip:
            subprocess.Popen(["ip", "addr", "add", config.ip + "/24", "dev", "eth0"])
            print("Creating IP: %s " % config.ip)
            time.sleep(3)
        super().__init__((self.config.ip, self.config.port), handler)
        # fetch all_data and put them in cache
        for file_p in list(pathlib.Path(self.config.base_url).rglob("data")):
            file_s = str(file_p)
            path = file_s.replace("/data", "").replace(self.config.base_url, "")
            if path == "":
                path = "/"
            self._db[path] = {}
            with open(file_s) as f:
                if file_s.endswith("description.xml/data"):
                    data = self.replace_ids(f.read())
                else:
                    data = json.loads(self.replace_ids(json.dumps(json.load(f))))

                self._db[path]["data"] = data
                rights: list[str] = []
                if path not in self.actions.access.no_GET:
                    rights += ["GET"]
                methods = ["POST", "PUT", "DELETE"]
                for method in methods:
                    if hasattr(self.actions.access, method) and path in getattr(
                        self.actions.access, method
                    ):
                        rights += [method]
                access: dict[str, list[str]] = {"rights": rights}
                self._db[path]["access"] = access
        for action in self.actions.post_actions:
            self._db[action.request] = {}
            self._db[action.request]["access"] = {"rights": ["POST"]}
            self._db[action.request]["action"] = action.action

    def replace_ids(self, data):
        new = data.replace("__REEFBEAT_DEVICE_IP__", self.config.ip)
        new = new.replace("__REEFBEAT_NAME__", self.config.name)
        new = new.replace(
            "__REEFBEAT_HW_ID__",
            str(
                int(hashlib.sha1(self.config.name.encode("utf-8")).hexdigest(), 16)
                % (10**12)
            ),
        )
        new = new.replace(
            "__REEFBEAT_UUID__", str(uuid.uuid3(uuid.NAMESPACE_X500, self.config.name))
        )
        return new

    def update_db(self, path: str, data: JSONValue) -> None:
        """Merge `data` into the DB entry for `path`.

        Args:
            path: API path key in the in-memory DB.
            data: JSON-like value to merge into existing state.

        Returns:
            None
        """

        self._db[path]["data"] = merge(self._db[path]["data"], data)

    def get_data(self, path: str) -> Optional[JSONValue]:
        """Get cached data for an API path.

        Modifiers are evaluated on each call. The scheduling logic is:
        - No ``only_once`` / ``only_startup``: modifier runs on **every** call.
        - ``only_once: N`` (int >= 0): modifier fires exactly once, on the
          N-th ``get_data`` call for its target path (0 = first call = startup).
        - Legacy ``only_startup: true`` is treated as ``only_once: 0``.

        An internal ``_call_count`` dict tracks per-path call counts.

        Args:
            path: API path.

        Returns:
            The cached data if present; an empty string if the entry exists but
            has no data; otherwise ``None``.
        """
        if path not in self._db:
            return None
        if "data" not in self._db[path]:
            return ""

        data = self._db[path]["data"]

        if hasattr(self.config, "modifiers") and self.config.modifiers:
            # Lazily initialise per-path call counter
            if not hasattr(self, "_call_count"):
                self._call_count: dict[str, int] = {}
            current_count = self._call_count.get(path, 0)

            for func in self.config.modifiers:
                # Skip if modifier doesn't target this path
                if not (
                    getattr(func.params, "path", False) and path == func.params.path
                ):
                    continue

                # Determine trigger tick
                # - only_once: N  → fire once at tick N
                # - only_startup: true  → legacy, same as only_once: 0
                # - neither → fire every tick
                trigger_tick = getattr(func, "only_once", None)
                if trigger_tick is None and getattr(func, "only_startup", False):
                    trigger_tick = 0  # legacy compat

                if trigger_tick is not None:
                    trigger_tick = int(trigger_tick)
                    # Already fired?
                    if getattr(func, "_fired", False):
                        continue
                    # Not yet the right tick?
                    if current_count != trigger_tick:
                        continue
                    # Fire and mark as done
                    func._fired = True
                # else: no scheduling constraint → run every time

                _ext = getattr(function_extension, func.name)
                data = _ext(path, data, func.params, self._ctx)

            self._call_count[path] = current_count + 1

        return data

    def get_post_action(
        self, path: str
    ) -> Optional[Union[PostActionRule, Sequence[PostActionRule]]]:
        """Get a post-action rule for a given API path.

        Args:
            path: API path.

        Returns:
            A single post-action rule, a sequence of rules, or `None` if none is
            configured.
        """

        entry = self._db.get(path)
        if not entry:
            return None
        return cast(
            Optional[Union[PostActionRule, Sequence[PostActionRule]]],
            entry.get("action"),
        )

    def is_allow(self, path: str, method: str) -> bool:
        """Check whether an HTTP method is allowed for an API path.

        Args:
            path: API path.
            method: HTTP method name (e.g., "GET", "POST").

        Returns:
            True if allowed; otherwise False.
        """

        if method in self._db[path]["access"]["rights"]:
            return True
        else:
            print("[%s] %s on %s not allowed" % (self.config.name, method, path))
            return False


class HttpServer(BaseHTTPRequestHandler):
    """HTTP request handler for the simulated device."""

    def log(self, message: str) -> None:
        """Log a server-scoped message.

        Args:
            message: Message to print.

        Returns:
            None
        """

        server = cast(MyServer, self.server)
        print("[%s] %s" % (server.config.name, message))

    def get_data(self, path: str) -> Optional[JSONValue]:
        """Resolve request path and return its cached response payload.

        Args:
            path: Request path.

        Returns:
            Cached payload, or `None` if not found.
        """
        if path == "":
            path = "/"
        return cast(MyServer, self.server).get_data(path)

    def log_message(self, format: str, *args: Any) -> None:
        """Disable default BaseHTTPRequestHandler logging.

        Args:
            format: Format string (ignored).
            *args: Format args (ignored).

        Returns:
            None
        """

        return

    def log_reqst(self, method: str, r_data: Any = "") -> None:
        """Log a request with optional request payload.

        Args:
            method: HTTP method.
            r_data: Optional request body (already parsed).

        Returns:
            None
        """

        self.log("%s %s %s" % (method, format(self.path), r_data))

    def do_GET(self) -> None:
        """Handle HTTP GET requests.

        Returns:
            None
        """

        self.log_reqst("GET")
        # A fill in progress advances on demand: the simulator has no clock of
        # its own, so the state it would have reached is computed when a client
        # asks for it. Polling more often does not dispense more water.
        if self.path == "/dashboard":
            self._advance_manual_fill(cast(MyServer, self.server))
        data = self.get_data(self.path)
        if data is not None and cast(MyServer, self.server).is_allow(self.path, "GET"):
            self.send_response(200)
            self.end_headers()
            if self.path.endswith("description.xml"):
                self.wfile.write(bytes(data, "utf8"))
            else:
                self.wfile.write(bytes(json.dumps(data), "utf8"))
        else:
            self.send_response(404)
            self.end_headers()

    def recv_with_param(self, method: str) -> None:
        """Handle POST/PUT requests with optional JSON payload.

        If the request path has a configured post-action, it is evaluated and its
        result merged into the target path.

        Args:
            method: HTTP method name ("POST" or "PUT").

        Returns:
            None
        """

        # `Content-Length: 0` is a non-empty header holding a falsy length, so
        # the length is what decides whether there is a body to parse. Reading
        # the string alone used to hand `json.loads` an empty buffer and take
        # the connection down, which is what a plain `curl -X POST` sends.
        content_length = int(self.headers.get("Content-Length") or 0)
        r_data: Any = ""
        if content_length:
            body = self.rfile.read(content_length)
            try:
                r_data = json.loads(body)
            except ValueError:
                self.log("%s %s: ignoring non-JSON body" % (method, self.path))
                r_data = ""
        self.log_reqst(method, r_data)
        data = self.get_data(self.path)
        server = cast(MyServer, self.server)
        if data is not None and server.is_allow(self.path, method):
            self.send_response(200)
            self.end_headers()
            post_action = server.get_post_action(self.path)
            if post_action:
                # Post-actions fire with or without a request body so that
                # bodyless endpoints like socket toggle work correctly.
                if isinstance(post_action, ABCSequence) and not isinstance(
                    post_action, (str, bytes, bytearray)
                ):
                    actions: list[PostActionRule] = list(post_action)
                else:
                    actions = [cast(PostActionRule, post_action)]
                for p_action in actions:
                    val = eval(p_action.action)
                    print(val)
                    server.update_db(p_action.target, val)
            elif r_data:
                server.update_db(self.path, r_data)
                self._handle_write_side_effects(server, method, r_data)
            self.wfile.write(bytes('{"success":true}', "utf8"))
        else:
            self.log("  ==>    %s %s:404" % (method, self.path))
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        """Handle HTTP POST requests.

        Returns:
            None
        """

        if self.path == "/off":
            cast(MyServer, self.server).update_db("/mode", {"mode": "off"})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}', "utf8"))
            return
        elif self.path == "/firmware":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}', "utf8"))
            return
        elif self.path == "/reset":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}', "utf8"))
            return

        # RUN calibration POST endpoints — return realistic messages
        server = cast(MyServer, self.server)
        calibration_responses: dict[str, str] = {
            "/calibration/2": "ec calibration started with success",
            "/calibration/skim": "over skimming calibration started with success",
            "/calibration/cup": "full cup calibration started with success",
        }
        if self.path in calibration_responses:
            self.log_reqst("POST")
            # Read and discard any body
            content_length_str = self.headers.get("Content-Length")
            if content_length_str:
                self.rfile.read(int(content_length_str))
            # Track which specific sub-calibration was performed so that a
            # subsequent DELETE /calibration only bumps the matching date.
            # POST /calibration/2 opens the EC session but does not by itself
            # decide which date will be updated, so we leave the tracker alone.
            if self.path == "/calibration/skim":
                server._last_calibration_type = "skim"
            elif self.path == "/calibration/cup":
                server._last_calibration_type = "cup"
            # When POST /calibration/2, update pump states to "calibration"
            if self.path == "/calibration/2" and "/dashboard" in server._db:
                for pk in ("pump_1", "pump_2"):
                    pump = (server.get_data("/dashboard") or {}).get(pk, {})
                    if isinstance(pump, dict) and pump.get("sensor_controlled"):
                        server.update_db("/dashboard", {pk: {"state": "calibration"}})
            self.send_response(200)
            self.end_headers()
            resp = {
                "success": True,
                "message": calibration_responses[self.path],
            }
            self.wfile.write(bytes(json.dumps(resp), "utf8"))
            return

        # ReefATO+ manual fill: /manual-pump starts the pump, /stop stops it.
        # Neither path has a fixture, so they are handled here rather than
        # through the generic merge, like the calibration endpoints above.
        if self.path in ("/manual-pump", "/stop") and self._is_ato(server):
            self.log_reqst("POST")
            content_length_str = self.headers.get("Content-Length")
            if content_length_str:
                self.rfile.read(int(content_length_str))
            if self.path == "/manual-pump":
                self._start_manual_fill(server)
            else:
                self._stop_manual_fill(server)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}', "utf8"))
            return

        self.recv_with_param("POST")

    def do_PUT(self) -> None:
        """Handle HTTP PUT requests.

        Returns:
            None
        """

        self.recv_with_param("PUT")

    def do_DELETE(self) -> None:
        """Handle HTTP DELETE requests.

        Supports generic DELETE on any path registered in the DB with DELETE
        access rights, plus device-specific side effects for ReefRun:
        - DELETE /calibration: update calibration timestamps
        - DELETE /pump/{n}/settings: reset pump to defaults in dashboard
        - DELETE /preview: stop pump preview mode
        - DELETE /emergency: clear emergency state
        """

        self.log_reqst("DELETE")
        server = cast(MyServer, self.server)

        # Legacy /off handler
        if self.path == "/off":
            server.update_db("/mode", {"mode": "auto"})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}', "utf8"))
            return

        # Generic DELETE: only allow if DELETE is explicitly listed in the
        # actions config for the current path. Falling back to GET rights was
        # too permissive and allowed DELETEs on any read-only endpoint.
        if self.path in server._db:
            access = server._db[self.path].get("access", {})
            rights = access.get("rights", [])
            if "DELETE" in rights:
                self._handle_delete_side_effects(server)
                self.send_response(200)
                self.end_headers()
                # /calibration returns the currently-open EC session message
                # on the real device, not the raw calibration timestamps.
                if self.path == "/calibration":
                    self.wfile.write(
                        bytes(
                            json.dumps(
                                {
                                    "success": True,
                                    "message": "ec calibration ended with success",
                                }
                            ),
                            "utf8",
                        )
                    )
                    return
                data = server.get_data(self.path)
                if isinstance(data, dict) and "message" in data:
                    self.wfile.write(bytes(json.dumps(data), "utf8"))
                else:
                    self.wfile.write(
                        bytes(
                            json.dumps(
                                {"success": True, "message": f"deleted {self.path}"}
                            ),
                            "utf8",
                        )
                    )
                return

        # Path not found or not allowed
        self.log("DELETE %s: 404" % self.path)
        self.send_response(404)
        self.end_headers()

    def _handle_write_side_effects(
        self, server: "MyServer", method: str, r_data: Any
    ) -> None:
        """Apply state side-effects after a successful PUT/POST merge.

        Dispatches to the per-device handlers below. Each of them projects a
        write onto the endpoint the real firmware also updates, so a client
        that writes a setting and then polls sees the new value where it
        expects it.

        - PUT /pump/settings (ReefRun) -> /dashboard
        - PUT /configuration (ReefATO+) -> /dashboard
        """
        if method != "PUT":
            return
        if self.path == "/pump/settings":
            self._handle_run_pump_settings_write(server, r_data)
        elif self.path == "/configuration":
            self._handle_ato_configuration_write(server, r_data)
        elif self.path == "/sockets/config":
            self._handle_power_sockets_config_write(server, r_data)

    def _handle_run_pump_settings_write(self, server: "MyServer", r_data: Any) -> None:
        """Mirror a ReefRun PUT /pump/settings onto /dashboard.

        Mirrors every field the two payloads have in common (name, type,
        model, schedule_enabled, sensor_controlled, ...). The real device
        exposes a single state that both endpoints project, so a setting
        written through /pump/settings is visible on /dashboard right away.

        The mirrored set is computed from the keys actually present in
        /dashboard rather than hardcoded, so settings-only fields (id,
        schedule) are never injected and a new shared field needs no change
        here.
        """
        if not isinstance(r_data, dict) or "/dashboard" not in server._db:
            return
        dashboard = server._db["/dashboard"].get("data")
        if not isinstance(dashboard, dict):
            return

        update: dict[str, Any] = {}

        # Top-level fields (linked, synced, ...)
        for key, value in r_data.items():
            if key.startswith("pump_"):
                continue
            if key in dashboard and not isinstance(value, (dict, list)):
                update[key] = value

        # Per-pump fields
        for pump_key in ("pump_1", "pump_2"):
            pump_body = r_data.get(pump_key)
            dash_pump = dashboard.get(pump_key)
            if not isinstance(pump_body, dict) or not isinstance(dash_pump, dict):
                continue
            mirrored = {k: v for k, v in pump_body.items() if k in dash_pump}
            if mirrored:
                update[pump_key] = mirrored

        if update:
            server.update_db("/dashboard", update)
            self.log("PUT /pump/settings: mirrored to /dashboard: %s" % update)

    def _handle_ato_configuration_write(self, server: "MyServer", r_data: Any) -> None:
        """Mirror a ReefATO+ PUT /configuration onto /dashboard.

        The RSATO+ exposes the leak probe arming flag and the leak alarm
        buzzer twice, under different names: they are written to
        /configuration as `leak.sensor_enabled` and `buzzer.enabled`, but
        reported on /dashboard as `leak_sensor.enabled` and
        `leak_sensor.buzzer_enabled`. A client that writes the setting and
        then polls /dashboard -- which is what the Home Assistant integration
        does, since /dashboard is the frequently polled source -- must see the
        new value there, so the write is projected the way the firmware does
        it.

        The merged configuration is read back rather than the request body:
        the firmware accepts a partial payload and clients only send the keys
        the user changed, so a key left out keeps its previous value.

        Other devices also serve /configuration (the ReefMat carries
        `position` there), hence the guards on the payload keys and on the
        presence of a `leak_sensor` block in the dashboard.
        """
        if not isinstance(r_data, dict):
            return
        if "buzzer" not in r_data and "leak" not in r_data:
            return
        if "/dashboard" not in server._db:
            return

        dashboard = server._db["/dashboard"].get("data")
        if not isinstance(dashboard, dict):
            return
        leak_sensor = dashboard.get("leak_sensor")
        if not isinstance(leak_sensor, dict):
            return

        config = server._db.get("/configuration", {}).get("data")
        if not isinstance(config, dict):
            config = {}

        update: dict[str, Any] = {}

        buzzer_config = config.get("buzzer")
        if isinstance(buzzer_config, dict) and "enabled" in buzzer_config:
            update["buzzer_enabled"] = bool(buzzer_config["enabled"])

        leak_config = config.get("leak")
        if isinstance(leak_config, dict) and "sensor_enabled" in leak_config:
            update["enabled"] = bool(leak_config["sensor_enabled"])

        if not update:
            return

        # The buzzer only sounds on a wet probe, and only while both the probe
        # and the buzzer are armed. Disabling either therefore silences an
        # alarm that is currently ringing, as it does on the device.
        enabled = update.get("enabled", bool(leak_sensor.get("enabled", False)))
        buzzer_enabled = update.get(
            "buzzer_enabled", bool(leak_sensor.get("buzzer_enabled", False))
        )
        is_wet = leak_sensor.get("status", "dry") != "dry"
        update["buzzer_on"] = bool(is_wet and enabled and buzzer_enabled)

        server.update_db("/dashboard", {"leak_sensor": update})
        self.log("PUT /configuration: mirrored to /dashboard: %s" % update)

    def _handle_power_sockets_config_write(
        self, server: "MyServer", r_data: Any
    ) -> None:
        """Mirror a RSPower PUT /sockets/config onto /dashboard.

        When a socket is configured (name, mode, enabled changed via the app
        or the HA integration), the real firmware also updates the matching
        entry in /dashboard/sockets so the polled state reflects the change
        immediately.

        The request body follows the same schema as /sockets/config/data:
        ``{"sockets": [{"number": N, "name": "...", "mode": "...", ...}, ...]}``.
        Only the sockets present in the payload are touched; others are left
        unchanged.
        """
        if not isinstance(r_data, dict) or "/dashboard" not in server._db:
            return
        dashboard = server._db["/dashboard"].get("data")
        if not isinstance(dashboard, dict):
            return
        dash_sockets = dashboard.get("sockets")
        if not isinstance(dash_sockets, list):
            return

        incoming = r_data.get("sockets", [])
        if not isinstance(incoming, list):
            incoming = [r_data] if "number" in r_data else []

        # Fields shared between /sockets/config and /dashboard/sockets
        MIRRORED = {"name", "mode", "user_config_mode", "enabled"}

        for entry in incoming:
            if not isinstance(entry, dict) or "number" not in entry:
                continue
            idx = entry["number"]
            if not isinstance(idx, int) or idx < 0 or idx >= len(dash_sockets):
                continue
            dash_sock = dash_sockets[idx]
            for key in MIRRORED:
                if key in entry:
                    if key == "mode" and entry[key] != dash_sock.get("mode"):
                        dash_sock["prev_mode"] = dash_sock.get("mode", "setup")
                    dash_sock[key] = entry[key]
            self.log("PUT /sockets/config: mirrored socket %d to /dashboard" % idx)

    # -------------------------------------------------------------------------
    # ReefATO+ manual fill
    # -------------------------------------------------------------------------

    @staticmethod
    def _is_ato(server: "MyServer") -> bool:
        """Tell whether this server simulates a ReefATO+.

        Recognised from the shape of its dashboard rather than from the
        configured device type, so a renamed or hand-written fixture still
        works. `/stop` is a bare path that another device could plausibly
        claim one day; this keeps the fill handlers off it.
        """
        entry = server._db.get("/dashboard")
        if not entry:
            return False
        dashboard = entry.get("data")
        return isinstance(dashboard, dict) and "is_pump_on" in dashboard

    @staticmethod
    def _ato_dashboard(server: "MyServer") -> Optional[dict[str, Any]]:
        """Return the raw dashboard dict, bypassing the modifiers."""
        entry = server._db.get("/dashboard")
        if not entry:
            return None
        dashboard = entry.get("data")
        return dashboard if isinstance(dashboard, dict) else None

    def _start_manual_fill(self, server: "MyServer") -> None:
        """Start a manual fill: run the pump and stamp the start.

        `is_pump_on` is the authoritative field, the one a client watches.
        `pump_state` and `prev_pump_state` are kept in step with it so the
        three never contradict each other -- real payloads have been seen
        reporting `is_pump_on: true` next to `pump_state: "off"`, but there is
        nothing to gain from reproducing that in a simulator.
        """
        dashboard = self._ato_dashboard(server)
        if dashboard is None:
            return

        now = time.time()
        if server._ato_fill_started_at is not None:
            # Already filling: a second press just extends nothing, the
            # timeout still runs from the original start.
            self.log("manual fill already running")
            return

        server._ato_fill_started_at = now
        server._ato_fill_last_tick = now
        server._ato_fill_carry = 0.0

        server.update_db(
            "/dashboard",
            {
                "is_pump_on": True,
                "prev_pump_state": dashboard.get("pump_state", "off"),
                "pump_state": "pump_on",
                "last_pump_on_cause": "manual",
            },
        )
        self.log("manual fill started (timeout %d ms)" % self._ato_pump_time_ms(server))

    def _stop_manual_fill(self, server: "MyServer", reason: str = "stop") -> None:
        """Stop a running fill and book it.

        Accounts the volume dispensed since the last tick, then bumps the fill
        counters and `last_fill_date` the way the firmware does at the end of a
        fill. A `/stop` with no fill running still forces `is_pump_on` off:
        that is what the button is for.
        """
        dashboard = self._ato_dashboard(server)
        if dashboard is None:
            return

        was_filling = server._ato_fill_started_at is not None
        if was_filling:
            self._advance_manual_fill(server, stopping=True)
            # `update_db` replaces the dashboard dict, so the reference taken
            # above is stale once the final tick has been accounted.
            dashboard = self._ato_dashboard(server) or dashboard

        server._ato_fill_started_at = None
        server._ato_fill_last_tick = None
        server._ato_fill_carry = 0.0

        update: dict[str, Any] = {
            "is_pump_on": False,
            "prev_pump_state": dashboard.get("pump_state", "pump_on"),
            "pump_state": "off",
        }
        if was_filling:
            update["last_fill_date"] = int(time.time())
            for counter in ("today_fills", "total_fills"):
                current = dashboard.get(counter)
                if isinstance(current, (int, float)):
                    update[counter] = int(current) + 1

        server.update_db("/dashboard", update)
        self.log("manual fill stopped (%s): %s" % (reason, update))

    @staticmethod
    def _ato_pump_time_ms(server: "MyServer") -> int:
        """Return the manual fill timeout, in milliseconds.

        Read from `/configuration`, which is where the device carries it, so a
        fixture with a different `custom_pump_time` is honoured.
        """
        entry = server._db.get("/configuration")
        config = entry.get("data") if entry else None
        if isinstance(config, dict):
            value = config.get("custom_pump_time")
            if isinstance(value, (int, float)) and value > 0:
                return int(value)
        return ATO_DEFAULT_PUMP_TIME_MS

    def _advance_manual_fill(self, server: "MyServer", stopping: bool = False) -> None:
        """Account the water dispensed since the last tick.

        Called before `/dashboard` is served and again when the fill ends, so
        the volumes a client reads are the ones the elapsed time implies.
        Nothing happens when no fill is running.

        The pump stops on its own once `custom_pump_time` has elapsed, or once
        the reservoir runs dry -- an empty container cannot dispense, whatever
        the timeout says. `days_till_empty` is deliberately left alone: the
        firmware derives it from a running average this simulator does not
        keep, so a recomputation here would fight the fixture rather than
        follow it.
        """
        if server._ato_fill_started_at is None or server._ato_fill_last_tick is None:
            return
        dashboard = self._ato_dashboard(server)
        if dashboard is None:
            return

        now = time.time()
        deadline = server._ato_fill_started_at + self._ato_pump_time_ms(server) / 1000.0
        expired = not stopping and now >= deadline
        # Only the water pumped up to the timeout counts, not the water that
        # would have been pumped had nobody polled until later. Clamping here
        # rather than in the `expired` branch alone also keeps the final tick
        # of a timed-out fill from booking the overshoot twice.
        now = min(now, deadline)

        elapsed = max(0.0, now - server._ato_fill_last_tick)
        server._ato_fill_last_tick = now

        flow_rate = dashboard.get("flow_rate")
        if not isinstance(flow_rate, (int, float)) or flow_rate <= 0:
            if expired:
                self._stop_manual_fill(server, reason="timeout")
            return

        # Carry the fraction of a milliliter across ticks: a client polling
        # every second must end up with the same volume as one polling once.
        server._ato_fill_carry += flow_rate * elapsed / ATO_FLOW_RATE_PERIOD_S
        dispensed = int(server._ato_fill_carry)
        server._ato_fill_carry -= dispensed

        volume_left = dashboard.get("volume_left")
        emptied = False
        update: dict[str, Any] = {}

        if isinstance(volume_left, (int, float)):
            # The reservoir bounds the fill: never dispense water that is not
            # there, and never report a negative level.
            dispensed = min(dispensed, int(volume_left))
            update["volume_left"] = int(volume_left) - dispensed
            emptied = update["volume_left"] <= 0

        if dispensed:
            for counter in ("today_volume_usage", "total_volume_usage"):
                current = dashboard.get(counter)
                if isinstance(current, (int, float)):
                    update[counter] = int(current) + dispensed

        if update:
            server.update_db("/dashboard", update)

        if expired:
            self._stop_manual_fill(server, reason="timeout")
        elif emptied and not stopping:
            # `stopping` means the caller is already inside _stop_manual_fill.
            self._stop_manual_fill(server, reason="reservoir empty")

    def _handle_delete_side_effects(self, server: "MyServer") -> None:
        """Apply state side-effects when a DELETE is processed.

        Handles ReefRun-specific behaviors observed on real hardware:
        - DELETE /calibration → update calibration timestamps to current epoch
        - DELETE /pump/{n}/settings → reset pump dashboard to defaults
        - DELETE /preview → set pump states back to operational
        - DELETE /emergency → clear emergency state
        """
        import time as _time

        if self.path == "/calibration":
            # DELETE /calibration commits the currently-open EC session.
            # The real device only bumps the date matching the sub-calibration
            # that was actually performed during the session (skim or cup).
            # If no sub-calibration was performed (only POST /calibration/2),
            # no date is updated.
            now = int(_time.time())
            last_type = getattr(server, "_last_calibration_type", None)
            update: dict[str, int] = {}
            if last_type == "skim":
                update["skim_last_calibration_date"] = now
            elif last_type == "cup":
                update["cup_last_calibration_date"] = now
            if (
                update
                and "/calibration" in server._db
                and "data" in server._db["/calibration"]
            ):
                server.update_db("/calibration", update)
            # Reset tracker for the next session.
            server._last_calibration_type = None
            self.log(
                "EC calibration session ended (last_type=%s, updated=%s)"
                % (last_type, list(update))
            )

        elif self.path in ("/pump/1/settings", "/pump/2/settings"):
            # Extract pump number from path
            pump_n = self.path.split("/")[2]  # "1" or "2"
            pump_key = f"pump_{pump_n}"
            # Reset pump to unknown/defaults in dashboard
            if "/dashboard" in server._db:
                server.update_db(
                    "/dashboard",
                    {
                        pump_key: {
                            "name": "",
                            "type": "unknown",
                            "model": "unknown",
                            "state": "operational",
                            "reconnect_pump": False,
                            "sensor_controlled": False,
                            "missing_pump": False,
                            "missing_sensor": False,
                            "schedule_enabled": False,
                            "intensity": 0,
                            "pulse": 0,
                            "temperature": 0,
                        }
                    },
                )
            # Reset pump in /pump/settings
            if "/pump/settings" in server._db:
                server.update_db(
                    "/pump/settings",
                    {
                        pump_key: {
                            "id": int(pump_n),
                            "name": "",
                            "type": "unknown",
                            "model": "unknown",
                            "sensor_controlled": False,
                            "schedule_enabled": False,
                            "schedule": [{"st": 0, "ti": 100, "pd": 0}],
                        }
                    },
                )
            self.log("Pump %s reset to factory defaults" % pump_n)

        elif self.path == "/preview":
            # Restore operational state for pumps that were in preview
            if "/dashboard" in server._db:
                dashboard = server.get_data("/dashboard")
                if isinstance(dashboard, dict):
                    for pk in ("pump_1", "pump_2"):
                        pump = dashboard.get(pk, {})
                        if isinstance(pump, dict) and pump.get("state") == "preview":
                            server.update_db(
                                "/dashboard", {pk: {"state": "operational"}}
                            )
            self.log("Preview stopped")

        elif self.path == "/emergency":
            self.log("Emergency cleared")


def ServerProcess(config: MutableMapping[str, Any]) -> None:
    """Run a device HTTP server based on one device config dict.

    Args:
        config: A JSON-like configuration mapping loaded from `config.json`.

    Returns:
        None
    """

    conf = cast(
        ServerConfig,
        json.loads(json.dumps(config), object_hook=lambda d: SimpleNamespace(**d)),
    )
    if conf.enabled:
        try:
            print(
                "HTTP Server [%s] %s:%d running - Use Ctrl-C to terminate"
                % (conf.name, conf.ip, conf.port)
            )
            httpd = MyServer(HttpServer, conf)
            while True:
                httpd.handle_request()
        except Exception:
            print("Unable to start server")
            print(traceback.format_exc())


if __name__ == "__main__":
    usage = "sudo %prog [-c <user_config_file>]"
    exec_path = os.path.dirname(sys.argv[0])
    version = "1.0.0"
    parser = OptionParser(usage, version=version)
    parser.add_option("-c", "--config", dest="config", help="Use a specific config")

    (options, args) = parser.parse_args()

    if os.geteuid() != 0:
        print("Must be run as root")
        parser.print_usage()
        sys.exit(1)

    conf_file = options.config or exec_path + "/config/config.json"
    print("Running with config: %s" % conf_file)
    with open(conf_file) as f:
        confs: dict[str, Any] = json.load(f)

    threads: list[Thread] = []
    for conf in confs["devices"]:
        if conf["enabled"]:
            thread = Thread(target=ServerProcess, args=[conf])
            threads += [thread]
            thread.start()

    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("Bye")
    time.sleep(2)
    subprocess.run(["sudo", "pkill", "-9", "-f", "sudo ./reefbeat-devices.py"])
