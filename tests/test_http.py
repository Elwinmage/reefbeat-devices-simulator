"""End to end over HTTP: the request handler, the extensions, the modifiers."""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import HTTPServer
from typing import Any, Iterator, Optional

import pytest

from conftest import build, sim


def _serve(name: str) -> Any:
    server = build(name, calibration_seconds=1)
    HTTPServer.__init__(server, ("127.0.0.1", 0), sim.HttpServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def pair() -> Iterator[tuple]:
    hub, power = _serve("RSCONTROLPRO"), _serve("RSPOWER6")
    yield hub, power
    for server in (hub, power):
        server.shutdown()
        server.server_close()


def request(server: Any, method: str, path: str, body: Optional[Any] = None) -> tuple:
    host, port = server.server_address[:2]
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        "http://%s:%d%s" % (host, port, path), data=data, method=method
    )
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"null")


def test_probe_scenario_over_http(pair: tuple) -> None:
    hub, power = pair
    status, answer = request(hub, "POST", "/probe/install?type=orp", {})
    assert status == 200
    uid = answer["uid"]
    request(hub, "PUT", "/probe/config", [{"type": "orp", "uid": uid, "name": "ORP 2"}])
    request(hub, "POST", "/probe/offset?type=orp&uid=%s" % uid, {"offset": 10})
    dashboard = request(hub, "GET", "/dashboard")[1]
    orp = next(p for p in dashboard["probes"] if p["uid"] == uid)
    assert (orp["name"], orp["value"], orp["status"]) == ("ORP 2", 260, "auto")
    assert request(hub, "DELETE", "/probe?type=orp&uid=%s" % uid)[0] == 200


def test_pairing_over_http(pair: tuple) -> None:
    hub, power = pair
    assert request(power, "DELETE", "/paired-device")[0] == 200
    assert request(hub, "GET", "/dashboard")[1]["connected_device"] is None
    request(hub, "POST", "/power/discover", {"pair": True})
    link = request(power, "GET", "/dashboard")[1]["connected_device"]
    assert link["type"] == "control" and link["status"] == "connected"


def test_generic_endpoints_still_work(pair: tuple) -> None:
    hub, power = pair
    assert request(hub, "GET", "/device-info")[1]["hw_model"] == "RSCONTROLPRO"
    status, _ = request(
        power,
        "PUT",
        "/sockets/config",
        {"sockets": [{"number": 2, "mode": "on", "name": "Heater"}]},
    )
    assert status == 200
    socket = request(power, "GET", "/dashboard")[1]["sockets"][2]
    assert (socket["mode"], socket["name"]) == ("on", "Heater")
    assert request(power, "GET", "/temperature/config")[0] == 404
