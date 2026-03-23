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
                    setattr(func, "_fired", True)
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

        content_length_str = self.headers.get("Content-Length")
        r_data: Any = ""
        if content_length_str:
            r_data = json.loads(self.rfile.read(int(content_length_str)))
        self.log_reqst(method, r_data)
        data = self.get_data(self.path)
        server = cast(MyServer, self.server)
        if data is not None and server.is_allow(self.path, method):
            self.send_response(200)
            self.end_headers()
            if r_data:
                post_action = server.get_post_action(self.path)
                if post_action:
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
                else:
                    server.update_db(self.path, r_data)
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

        # Generic DELETE: check if path exists in DB and has DELETE access
        if self.path in server._db:
            access = server._db[self.path].get("access", {})
            rights = access.get("rights", [])
            # Allow DELETE if explicitly listed or if we have the data
            if "DELETE" in rights or "GET" in rights:
                self._handle_delete_side_effects(server)
                self.send_response(200)
                self.end_headers()
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
            # Update calibration dates to current time (like real device)
            now = int(_time.time())
            if "/calibration" in server._db and "data" in server._db["/calibration"]:
                server.update_db(
                    "/calibration",
                    {
                        "skim_last_calibration_date": now,
                        "cup_last_calibration_date": now,
                    },
                )
            self.log("EC calibration ended, dates updated to %d" % now)

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
