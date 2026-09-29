"""The simulated ReefBeat cloud account: devices and light programs library."""

from __future__ import annotations

import json
import ssl
import threading
import urllib.request
from http.server import HTTPServer
from typing import Any

import pytest

import function_extension as fx
from conftest import build, call, sim

cloud_fx = fx.rs_cloud


@pytest.fixture
def cloud() -> Any:
    return build("CLOUD")


@pytest.fixture
def lamps() -> list:
    """The lamps, registered as when the simulator runs."""
    return [build("LED_G1_160"), build("LED_G2"), build("LED_G1_90")]


def test_token(cloud: Any) -> None:
    status, token = call(cloud, "POST", "/oauth/token", {"username": "a"})
    assert status == 200 and token["token_type"] == "bearer"
    assert token["access_token"]
    # Credentials set in the config are checked
    strict = build("CLOUD", username="sim@example.com", password="pw")
    assert call(strict, "POST", "/oauth/token", {"username": "x"})[0] == 401
    good = {"username": "sim@example.com", "password": "pw"}
    assert call(strict, "POST", "/oauth/token", good)[0] == 200
    assert cloud_fx.parse_form(b"username=a%40b.c&password=p") == {
        "username": "a@b.c",
        "password": "p",
    }


def test_account_and_devices(cloud: Any, lamps: list) -> None:
    assert call(cloud, "GET", "/user")[1]["email"] == "user@example.com"
    aquarium = call(cloud, "GET", "/aquarium")[1][0]
    status, devices = call(cloud, "GET", "/device")
    assert status == 200
    # The lamps only, in the account's aquarium
    assert sorted(d["model"] for d in devices) == ["RSLED115", "RSLED160", "RSLED90"]
    g1 = next(d for d in devices if d["model"] == "RSLED160")
    assert g1["hwid"] == "521f271d32c8"
    assert g1["aquarium_uid"] == aquarium["uid"]
    assert g1["ip_address"] == "192.168.0.242"
    # A RSLED90 reports no hwid: its uuid stands for it, as in the integration
    g1_90 = next(d for d in devices if d["model"] == "RSLED90")
    assert g1_90["hwid"] == "d0ef768c2096"
    assert call(cloud, "GET", "/firmware/api/reef-lights/latest?board=esp32")[1] == {
        "version": "1.8.0"
    }
    assert call(cloud, "GET", "/firmware/api/reef-mat/latest")[1] == {
        "version": "0.0.0"
    }
    # Or the devices named in the config
    listed = build("CLOUD", devices=["RSDOSE4"])
    build("RSDOSE4")
    assert [d["model"] for d in call(listed, "GET", "/device")[1]] == ["RSDOSE4"]
    assert call(cloud, "GET", "/nothing")[0] == 404
    assert cloud_fx.handle(cloud, "PUT", "/user", {}) is None
    assert cloud_fx.handle(lamps[0], "GET", "/device", None) is None


def test_g1_library(cloud: Any) -> None:
    path = "/reef-lights/library?include=all"
    names = [e["name"] for e in call(cloud, "GET", path)[1]]
    assert names[:5] == ["12K", "15K", "18K", "20K", "23K"]
    program = {"white": {"rise": 600, "set": 1200, "points": []}}
    aquarium = call(cloud, "GET", "/aquarium")[1][0]["uid"]
    body = {"aquarium_uid": aquarium, "name": "prog-202609291000", "program": program}
    status, entry = call(cloud, "POST", "/reef-lights/library", body)
    assert status == 201
    assert entry["uid"] and entry["id"] == 1000011 and entry["clouds"] is None
    assert call(cloud, "GET", path)[1][-1]["name"] == "prog-202609291000"
    clouds = {"from": 700, "to": 800, "intensity": "Low"}
    update = {"name": "Mine", "program": program, "clouds": clouds}
    status, updated = call(cloud, "PUT", "/reef-lights/library/" + entry["uid"], update)
    assert status == 200
    assert (updated["name"], updated["clouds"], updated["uid"]) == (
        "Mine",
        clouds,
        entry["uid"],
    )
    # A program sent without clouds loses them
    call(cloud, "PUT", "/reef-lights/library/" + entry["uid"], {"name": "Mine"})
    assert (
        call(cloud, "GET", "/reef-lights/library/" + entry["uid"])[1]["clouds"] is None
    )
    assert call(cloud, "DELETE", "/reef-lights/library/" + entry["uid"])[0] == 200
    assert call(cloud, "GET", "/reef-lights/library/" + entry["uid"])[0] == 404
    assert call(cloud, "POST", "/reef-lights/library", {"program": {}})[0] == 400
    assert call(cloud, "PUT", "/reef-lights/library/%s" % names, "x")[0] == 404


def test_g2_library(cloud: Any) -> None:
    entries = call(cloud, "GET", "/v2/reef-lights/library")[1]
    assert entries[0]["name"] == "Perso G2" and "color" in entries[0]
    body = {"name": "Deep", "color": {"rise": 1, "set": 2, "points": []}}
    status, entry = call(cloud, "POST", "/v2/reef-lights/library", body)
    assert status == 201 and entry["id"] and entry["clouds"] is None
    uid = entry["id"]
    assert call(cloud, "PUT", "/v2/reef-lights/library/" + uid, "x")[0] == 400
    assert call(cloud, "PUT", "/v2/reef-lights/library/" + uid, {"name": "D"})[0] == 200
    assert call(cloud, "GET", "/v2/reef-lights/library")[1][-1]["name"] == "D"
    assert cloud_fx.handle(cloud, "PATCH", "/v2/reef-lights/library/" + uid, {}) is None
    assert cloud_fx.handle(cloud, "PATCH", "/v2/reef-lights/library", {}) is None
    assert call(cloud, "DELETE", "/v2/reef-lights/library/" + uid)[0] == 200
    assert len(call(cloud, "GET", "/v2/reef-lights/library")[1]) == 1


def test_no_aquarium(cloud: Any) -> None:
    cloud._db["/aquarium"]["data"] = []
    assert cloud_fx.aquarium(cloud) == {"id": 0, "uid": ""}
    cloud._db["/reef-lights/library"]["data"] = None
    assert call(cloud, "GET", "/reef-lights/library")[1] == []


def test_over_https(tmp_path: Any) -> None:
    """Token (form body) then a library read, over TLS."""
    server = build(
        "CLOUD",
        tls_cert=str(tmp_path / "cert.pem"),
        tls_key=str(tmp_path / "key.pem"),
    )
    HTTPServer.__init__(server, ("127.0.0.1", 0), sim.HttpServer)
    server.socket = sim.tls_context(server.config).wrap_socket(
        server.socket, server_side=True
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    host, port = server.server_address[:2]
    base = "https://%s:%d" % (host, port)
    try:
        req = urllib.request.Request(
            base + "/oauth/token",
            data=b"grant_type=password&username=u&password=p",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, context=context) as resp:
            assert json.loads(resp.read())["access_token"]
        req = urllib.request.Request(base + "/v2/reef-lights/library")
        with urllib.request.urlopen(req, context=context) as resp:
            assert json.loads(resp.read())[0]["name"] == "Perso G2"
    finally:
        server.shutdown()
        server.server_close()
