"""Simulated devices built from the fixtures, without binding a socket."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
from types import SimpleNamespace
from typing import Any, Optional

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import function_extension as fx  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "reefbeat_devices", ROOT / "reefbeat-devices.py"
)
assert _spec is not None and _spec.loader is not None
sim = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sim)


def _namespace(value: Any) -> Any:
    return json.loads(json.dumps(value), object_hook=lambda d: SimpleNamespace(**d))


def build(name: str, **overrides: Any) -> Any:
    """A device of config/config.json, its state loaded from the fixtures."""
    with open(ROOT / "config" / "config.json") as f:
        conf = next(d for d in json.load(f)["devices"] if d["name"] == name)
    server = object.__new__(sim.MyServer)
    server.config = _namespace({**conf, **overrides})
    server._ctx = sim.Object()
    server._ctx.server = server
    with open(ROOT / server.config.actions) as f:
        server.actions = _namespace(json.load(f))
    server._db = {}
    # What __init__ sets besides the DB
    server._last_calibration_type = None
    server._ato_fill_started_at = None
    server._ato_fill_last_tick = None
    server._ato_fill_carry = 0.0
    server.load_fixtures()
    return server


def call(server: Any, method: str, path: str, body: Any = None) -> Optional[tuple]:
    """Send a request to the extension modules, as the HTTP handler does."""
    result = fx.rs_control.handle(server, method, path, body)
    if result is None:
        result = fx.handle_local_temp(server, method, path, body)
    return result


def dashboard(server: Any) -> Any:
    """``GET /dashboard`` as a client sees it (modifiers applied)."""
    return server.get_data("/dashboard")


def probe(server: Any, ptype: str) -> dict:
    return next(p for p in dashboard(server)["probes"] if p["type"] == ptype)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(ROOT)
    fx.registry.clear()
    yield
    fx.registry.clear()


@pytest.fixture
def hub() -> Any:
    return build("RSCONTROLPRO", calibration_seconds=10)


@pytest.fixture
def power() -> Any:
    return build("RSPOWER6")
