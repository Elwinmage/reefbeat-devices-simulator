"""control_timelapse.py against the simulator: the probe -> output -> water loop.

The hub and the strip are built from the fixtures and served over real HTTP on
the loopback, so the script runs exactly as against a running simulator.
"""

from __future__ import annotations

import importlib.util
import sys
import threading
from http.server import HTTPServer
from typing import Any, Iterator

import pytest

import function_extension as fx
from conftest import ROOT, build, call, dashboard, sim

_spec = importlib.util.spec_from_file_location(
    "control_timelapse", ROOT / "scripts" / "control_timelapse.py"
)
assert _spec is not None and _spec.loader is not None
tl = importlib.util.module_from_spec(_spec)
# dataclasses look their module up in sys.modules while the class is built
sys.modules["control_timelapse"] = tl
_spec.loader.exec_module(tl)


def _serve(server: Any) -> str:
    """Bind a fixture-built server to a free loopback port and serve it."""
    HTTPServer.__init__(server, ("127.0.0.1", 0), sim.HttpServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return "http://127.0.0.1:%d" % server.server_address[1]


@pytest.fixture
def served() -> Iterator[tuple[Any, Any, str, str]]:
    hub = build("RSCONTROLPRO", calibration_seconds=10)
    power = build("RSPOWER6")
    hub_url, power_url = _serve(hub), _serve(power)
    yield hub, power, hub_url, power_url
    for server in (hub, power):
        server.shutdown()
        server.server_close()
    fx.probe_rules.set_clock(None)


def _scenario(**overrides: Any) -> dict[str, Any]:
    scenario: dict[str, Any] = {
        "start": "02:00",
        "duration": "04:00",
        "speed": 30,
        "tick": 0.01,
        "seed": 1,
        "ambient": {"mean": 20, "swing": 0},
        "water": {"temperature": 25.4, "level": 2.5},
        "physics": {
            "temperature": {"toward": "ambient", "rate": 0.5},
            "level": {"evaporation": 2},
        },
        "actuators": [
            {"name": "Heater", "socket": 3, "watts": 150, "effect": {"temperature": 4}},
            {"name": "ATO", "port": 1, "watts": 18, "effect": {"level": 12}},
        ],
        "setup": {
            "sockets": [
                {
                    "socket": 3,
                    "name": "Heater",
                    "mode": "sensor",
                    "probe": "temperature",
                    "when": "below",
                    "value": 25.0,
                    "hysteresis": 0.2,
                    "turn": "on",
                }
            ],
            "ports": [{"port": 1, "name": "ATO", "mode": "sensor", "probe": "ato"}],
        },
    }
    scenario.update(overrides)
    return scenario


def _timelapse(served: Any, scenario: dict[str, Any]) -> Any:
    _hub, _power, hub_url, power_url = served
    timelapse = tl.Timelapse(
        scenario, tl.Device(hub_url, "hub"), tl.Device(power_url, "power")
    )
    timelapse.load_probes()
    timelapse.load_actuators()
    timelapse.load_events()
    return timelapse


# ── Simulator endpoints ──────────────────────────────────────────────────────


def test_virtual_clock_drives_schedules(hub: Any, power: Any) -> None:
    power._db["/socket/0/config/schedule"]["data"] = {
        "intervals": [{"time": 600, "duration": 60}]
    }
    assert call(hub, "PUT", "/sim/clock", {"minute": 630})[1]["minute"] == 630
    assert dashboard(power)["sockets"][0]["state"] == "on"
    call(power, "PUT", "/sim/clock", {"minute": 700})
    assert dashboard(power)["sockets"][0]["state"] == "standby"
    assert call(hub, "GET", "/sim/clock")[1] == {"minute": 700}
    call(hub, "PUT", "/sim/clock", {"minute": None})
    assert fx.probe_rules.clock() is None


def test_sim_probes_are_raw(hub: Any) -> None:
    call(hub, "POST", "/probe/offset?type=orp&uid=0x0071F", {"offset": 20})
    raw = call(hub, "GET", "/sim/probes")[1]["probes"]
    orp = next(p for p in raw if p["type"] == "orp")
    assert orp["value"] == 250  # the dashboard says 270
    assert (
        next(p for p in dashboard(hub)["probes"] if p["type"] == "orp")["value"] == 270
    )
    leak = next(p for p in raw if p["type"] == "leak")
    assert leak["leak_status"] == "dry"


def test_simulated_consumption(hub: Any, power: Any) -> None:
    call(power, "PUT", "/sim/watts", {"watts": {"0": 36, "2": 150}})
    sockets = dashboard(power)["sockets"]
    assert sockets[0]["consumption"] == 36  # on, by its fixture schedule
    assert sockets[2]["consumption"] == 0  # in setup, not powered
    assert sockets[1]["consumption"] == 0  # not simulated: fixture value
    call(hub, "PUT", "/sim/watts", {"watts": {"0": 18}})
    call(hub, "POST", "/port/0/install", {"type": "other"})
    call(hub, "PUT", "/ports/config", [{"number": 0, "mode": "on"}])
    hub._db["/dashboard"]["data"]["ports"][0]["state"] = "on"
    assert dashboard(hub)["ports"][0]["consumption"] == 18


def test_power_local_temperature(hub: Any, power: Any) -> None:
    call(power, "DELETE", "/paired-device")
    call(power, "POST", "/sensor/install", {"type": "temperature"})
    assert call(power, "PUT", "/sim/temperature", {"value": 22.4})[0] == 200
    assert dashboard(power)["temperature"]["value"] == 22.4
    assert call(power, "GET", "/sim/temperature")[1]["value"] == 22.4
    assert call(power, "PUT", "/sim/temperature", {})[0] == 400


# ── The loop ─────────────────────────────────────────────────────────────────


def test_setup_configures_both_devices(served: Any) -> None:
    hub, power, _, _ = served
    timelapse = _timelapse(served, _scenario())
    timelapse.setup()
    socket = dashboard(power)["sockets"][2]
    assert (socket["mode"], socket["name"]) == ("sensor", "Heater")
    rule = call(hub, "GET", "/subscription-info")[1]["external"][0]
    assert rule["number"] == 2 and rule["type"] == "temperature"
    assert rule["is_above"] is False and rule["value"] == 25.0
    port = dashboard(hub)["ports"][0]
    assert (port["mode"], port["type"], port["name"]) == ("sensor", "other", "ATO")


def test_cold_night_turns_the_heater_on_and_warms_the_water(served: Any) -> None:
    hub, power, _, _ = served
    timelapse = _timelapse(served, _scenario())
    timelapse.setup()
    timelapse.push_watts()
    heater = timelapse.actuators[0]

    seen_on = False
    for _ in range(40):
        timelapse.read_outputs()
        timelapse.advance(15)
        timelapse.write_probes()
        seen_on = seen_on or heater.on
    # The air is at 20 °C: without the heater the water would be there
    assert seen_on
    assert 24.5 < timelapse.water["temperature"] < 25.8
    socket = dashboard(power)["sockets"][2]
    if socket["state"] == "on":
        assert socket["consumption"] == 150


def test_evaporation_starts_the_ato_pump(served: Any) -> None:
    timelapse = _timelapse(served, _scenario())
    timelapse.setup()
    ato = timelapse.actuators[1]
    levels, states = [], []
    for _ in range(60):
        timelapse.read_outputs()
        states.append((tl.level_mark(timelapse.water["level"]), ato.on))
        timelapse.advance(10)
        timelapse.write_probes()
        levels.append(timelapse.water["level"])
    assert any(on for _, on in states)
    # Topped up each time it reached "below": never left empty for long
    assert min(levels[20:]) > 0.5
    # ...and only then: the pump rests while the probe reads a mark. The
    # first frame still reads the fixture's own "below", before any write.
    assert all(mark == "below" for mark, on in states[1:] if on)


def test_events_and_restore(served: Any) -> None:
    hub, _power, _, _ = served
    scenario = _scenario(
        setup=None,
        events=[
            {"at": "+00:10", "leak": "aquarium"},
            {"at": "+00:20", "unplug": "ph"},
            {"at": "+00:30", "bias": {"probe": "ec", "sensor": "temp", "delta": 2}},
        ],
    )
    timelapse = _timelapse(served, scenario)
    timelapse.minute = timelapse.start + 40
    timelapse.play_due_events()
    timelapse.write_probes()
    probes = {p["type"]: p for p in dashboard(hub)["probes"]}
    assert probes["leak"]["detected"] is True
    assert probes["ph"]["status"] == "disconnected"
    assert probes["ec"]["temp_value"] - probes["temperature"]["value"] > 1.5
    assert dashboard(hub)["buzzer"]["cause"] == "leak"

    timelapse.restore()
    probes = {p["type"]: p for p in dashboard(hub)["probes"]}
    assert probes["leak"]["detected"] is False
    assert probes["ph"]["status"] == "auto"
    assert probes["ph"]["value"] == 8.15
    assert fx.probe_rules.clock() is None


def test_full_run_is_quick_and_clean(served: Any) -> None:
    hub, _power, _, _ = served
    timelapse = _timelapse(served, _scenario(duration="01:00"))
    assert timelapse.run() == 0
    assert fx.probe_rules.clock() is None
    assert (
        next(p for p in dashboard(hub)["probes"] if p["type"] == "temperature")["value"]
        == 25.2
    )


def test_demo_scenario_is_valid(served: Any) -> None:
    scenario = tl.load_scenario(str(ROOT / "scripts" / "control_demo.yaml"))
    timelapse = _timelapse(served, scenario)
    assert len(timelapse.actuators) == 6
    assert [e["_when"] for e in timelapse.events] == sorted(
        e["_when"] for e in timelapse.events
    )
    timelapse.setup()
    assert timelapse.show() == 0
