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
from collections.abc import Sequence as ABCSequence
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from types import SimpleNamespace
from typing import Any, MutableMapping, Optional, Protocol, Sequence, Union, cast

from jsonmerge import merge  # type: ignore[import]

JSONValue = Any


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


class ServerConfig(Protocol):
    """Configuration required to run a simulated device HTTP server."""

    enabled: bool
    name: str
    ip: str
    port: int
    base_url: str
    access: AccessControl
    post_actions: Sequence[RequestPostAction]


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

        self.config = config
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
                    data = f.read()
                else:
                    data = json.loads(
                        json.dumps(json.load(f)).replace(
                            "__REEFBEAT_DEVICE_IP__", self.config.ip
                        )
                    )
                self._db[path]["data"] = data
                rights: list[str] = []
                if path not in self.config.access.no_GET:
                    rights += ["GET"]
                methods = ["POST", "PUT"]
                for method in methods:
                    if hasattr(self.config.access, method) and path in getattr(
                        self.config.access, method
                    ):
                        rights += [method]
                access: dict[str, list[str]] = {"rights": rights}
                self._db[path]["access"] = access
        for action in self.config.post_actions:
            self._db[action.request] = {}
            self._db[action.request]["access"] = {"rights": ["POST"]}
            self._db[action.request]["action"] = action.action

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

        Args:
            path: API path.

        Returns:
            The cached data if present; an empty string if the entry exists but
            has no data; otherwise `None`.
        """
        if path in self._db:
            if "data" in self._db[path]:
                return self._db[path]["data"]
            else:
                return ""
        return None

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
        self.recv_with_param("POST")

    def do_PUT(self) -> None:
        """Handle HTTP PUT requests.

        Returns:
            None
        """

        self.recv_with_param("PUT")

    def do_DELETE(self) -> None:
        """Handle HTTP DELETE requests.

        Returns:
            None
        """

        self.log_reqst("DELETE")
        if self.path == "/off":
            cast(MyServer, self.server).update_db("/mode", {"mode": "auto"})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}', "utf8"))
            return


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
    if os.geteuid() != 0:
        print("Must be run as root")
        sys.exit(1)

    with open("config.json") as f:
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
