"""RSCONTROL hub: probes, offsets, calibration, leaks, buzzer, ports, pairing."""

from __future__ import annotations

from typing import Any

import pytest

import function_extension as fx
from conftest import call, dashboard, probe

ORP = "type=orp&uid=0x0071F"
PH = "type=ph&uid=0x00B39"
EC = "type=ec&uid=0x007BF"
LEAK = "type=leak&uid=0x0032B"
TEMP = "type=temperature&uid=0x000F7"


# ── Dashboard ────────────────────────────────────────────────────────────────


def test_dashboard_is_firmware_shaped(hub: Any) -> None:
    probes = {p["type"]: p for p in dashboard(hub)["probes"]}
    assert not any(k.startswith("_") for p in probes.values() for k in p)
    assert probes["ec"]["measurement_unit"] == "ec"
    assert probes["ec"]["ec"] == probes["ec"]["value"] == 53.0
    assert probes["ph"]["temp_value"] == 25.1
    assert probes["ph"]["last_adjustment_date"] is None
    assert probes["ato"]["water_level"] == "below"
    assert "value" not in probes["ato"]
    assert probes["leak"]["detected"] is False
    assert "last_adjustment_date" not in probes["orp"]


# ── Offsets ──────────────────────────────────────────────────────────────────


def test_offset_adds_and_moves_the_reading(hub: Any) -> None:
    """Captured: offset 1, POST 35 -> 36; readings include it."""
    assert call(hub, "POST", "/probe/offset?" + ORP, {"offset": 35})[0] == 200
    assert call(hub, "POST", "/probe/offset?" + ORP, {"offset": 20.4})[0] == 200
    status, off = call(hub, "GET", "/probe/offset?" + ORP)
    assert status == 200 and off["offset"] == 55
    assert off["last_adjustment_date"] > 0
    assert probe(hub, "orp")["value"] == 305
    assert call(hub, "GET", "/probe?" + ORP)[1]["value"] == 305
    call(hub, "DELETE", "/probe/offset?" + ORP)
    assert probe(hub, "orp")["value"] == 250


def test_embedded_temperature_offset(hub: Any) -> None:
    """pH, EC, ATO: the offset moves temp_value, not the reading."""
    call(hub, "POST", "/probe/offset?" + PH, {"offset": 0.9})
    ph = probe(hub, "ph")
    assert ph["temp_value"] == 26.0
    assert ph["value"] == 8.15
    # Not a pH calibration
    assert ph["last_adjustment_date"] is None
    call(hub, "POST", "/probe/offset?" + TEMP, {"offset": -0.2})
    assert probe(hub, "temperature")["value"] == 25.0


def test_offset_refusals(hub: Any) -> None:
    assert call(hub, "GET", "/probe/offset?" + LEAK)[0] == 400
    assert call(hub, "POST", "/probe/offset?" + ORP, {"offset": "x"})[0] == 400
    assert call(hub, "GET", "/probe/offset?type=orp&uid=0xNONE")[0] == 404
    call(hub, "PUT", "/sim/probe?" + ORP, {"status": "disconnected"})
    assert call(hub, "GET", "/probe/offset?" + ORP) == (
        503,
        {"success": False, "message": "Failed to get offset"},
    )
    assert call(hub, "POST", "/probe/offset?" + ORP, {"offset": 1})[0] == 503
    assert call(hub, "DELETE", "/probe/offset?" + ORP)[0] == 503
    assert call(hub, "GET", "/probe?" + ORP)[0] == 503
    assert call(hub, "GET", "/probe/info?" + ORP)[0] == 503
    assert probe(hub, "orp")["status"] == "disconnected"
    call(hub, "PUT", "/sim/probe?" + ORP, {"status": "connected"})
    assert call(hub, "GET", "/probe?" + ORP)[0] == 200


# ── Probe life cycle ─────────────────────────────────────────────────────────


def test_install_configure_and_delete(hub: Any) -> None:
    status, answer = call(hub, "POST", "/probe/install?type=ec")
    assert status == 200 and answer["success"]
    uid = answer["uid"]
    assert int(uid, 16) > 0x0071F
    new = next(p for p in dashboard(hub)["probes"] if p["uid"] == uid)
    assert new["status"] == "setup"
    assert call(hub, "POST", "/ble/off?type=ec&uid=" + uid)[0] == 200
    call(
        hub,
        "PUT",
        "/probe/config",
        [{"type": "ec", "uid": uid, "name": "EC 2", "unit": "ppt", "buzzer": False}],
    )
    new = next(p for p in dashboard(hub)["probes"] if p["uid"] == uid)
    assert new["status"] == "auto" and new["name"] == "EC 2"
    config = next(c for c in call(hub, "GET", "/probe/config")[1] if c["uid"] == uid)
    assert config["unit"] == "ppt" and config["buzzer"] is False
    assert "temp" in config
    assert call(hub, "DELETE", "/probe?type=ec&uid=" + uid)[0] == 200
    assert call(hub, "DELETE", "/probe?type=ec&uid=" + uid)[0] == 404
    assert call(hub, "POST", "/probe/install?type=unknown")[0] == 400


def test_setup_probes_are_cleared(hub: Any) -> None:
    uid = call(hub, "POST", "/probe/install?type=orp")[1]["uid"]
    status, answer = call(hub, "DELETE", "/setup-probes")
    assert answer == {"deleted_probes": [{"type": "orp", "uid": uid}]}


def test_disable_and_enable(hub: Any) -> None:
    call(hub, "POST", "/probe/disable?" + ORP)
    assert probe(hub, "orp")["status"] == "disabled"
    call(hub, "DELETE", "/probe/disable?" + ORP)
    assert probe(hub, "orp")["status"] == "auto"


def test_leak_probe_takes_only_its_name(hub: Any) -> None:
    body = [{"type": "leak", "uid": "0x0032B", "name": "Sump"}]
    assert call(hub, "PUT", "/probe/config", body)[0] == 200
    body = [{"type": "leak", "uid": "0x0032B", "buzzer": False}]
    assert call(hub, "PUT", "/probe/config", body)[0] == 503
    leak = next(c for c in call(hub, "GET", "/probe/config")[1] if c["type"] == "leak")
    assert leak == {"name": "Sump", "type": "leak", "uid": "0x0032B"}


# ── Leaks and buzzer ─────────────────────────────────────────────────────────


def test_leak_origin_and_buzzer(hub: Any) -> None:
    assert call(hub, "GET", "/probe?" + LEAK)[1]["leak_status"] == "dry"
    call(hub, "PUT", "/sim/probe?" + LEAK, {"leak_status": "aquarium_water_leak"})
    reading = call(hub, "GET", "/probe?" + LEAK)[1]
    assert reading["leak_status"] == "aquarium_water_leak" and reading["ec"] == 1540
    assert probe(hub, "leak")["detected"] is True
    assert dashboard(hub)["buzzer"] == {
        "active": True,
        "cause": "leak",
        "dismissed": False,
    }
    # The hub button silences it until the leak dries up
    call(hub, "PUT", "/sim/buzzer", {"dismissed": True})
    assert dashboard(hub)["buzzer"]["active"] is False
    call(hub, "PUT", "/sim/probe?" + LEAK, {"leak_status": "dry"})
    assert dashboard(hub)["buzzer"] == {
        "active": False,
        "cause": "none",
        "dismissed": False,
    }


def test_leak_detector_switch(hub: Any) -> None:
    call(hub, "PUT", "/sim/probe?" + LEAK, {"leak_status": "rodi_water_leak"})
    call(hub, "PUT", "/configuration", {"leak_detector": False})
    assert dashboard(hub)["leak_detector"] is False
    assert call(hub, "GET", "/leak/config")[1]["leak_detector"] is False
    assert dashboard(hub)["buzzer"]["cause"] == "none"
    call(hub, "PUT", "/leak/config", {"leak_detector": True, "buzzer": False})
    assert hub.get_data("/configuration")["leak_detector"] is True
    buzzer = dashboard(hub)["buzzer"]
    assert buzzer["cause"] == "leak" and buzzer["active"] is False
    # A partial write keeps the rest
    call(hub, "PUT", "/configuration", {"leak_buzzer_config": {"frequency": 3}})
    conf = hub.get_data("/configuration")["leak_buzzer_config"]
    assert conf == {"enabled": True, "frequency": 3, "duty_cycle": 50}


def test_danger_buzzer(hub: Any) -> None:
    call(hub, "PUT", "/sim/probe?" + TEMP, {"value": 30})
    assert dashboard(hub)["buzzer"]["cause"] == "danger"
    assert dashboard(hub)["buzzer"]["active"] is True
    call(hub, "PUT", "/configuration", {"danger_buzzer_config": {"enabled": False}})
    assert dashboard(hub)["buzzer"]["active"] is False


# ── Multi-point calibration ──────────────────────────────────────────────────


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> dict:
    now = {"t": 1000.0}
    monkeypatch.setattr(fx.rs_control, "_clock", lambda: now["t"])
    return now


def test_ph_two_point_calibration(hub: Any, clock: dict) -> None:
    point = {"point": "MID", "solution_value": 7.0, "solution_rated_temp": 25}
    assert call(hub, "POST", "/probe/calibration-point-start?" + PH, point)[0] == 503
    assert call(hub, "POST", "/probe/calibration-enter?" + PH, {"time": 1})[0] == 200
    assert call(hub, "POST", "/probe/calibration-point-start?" + PH, point)[0] == 200
    clock["t"] += 4
    status = call(hub, "GET", "/probe/calibration-status?" + PH)[1]
    assert status == {
        "calibration_status": "in_progress",
        "time_left": 6,
        "stability_progress": "40",
    }
    clock["t"] += 6
    status = call(hub, "GET", "/probe/calibration-status?" + PH)[1]
    assert status["calibration_status"] == "success"

    high = {"point": "HIGH", "solution_value": 4.0, "solution_rated_temp": 25}
    call(hub, "POST", "/probe/calibration-point-start?" + PH, high)
    clock["t"] += 10
    status = call(hub, "GET", "/probe/calibration-status?" + PH)[1]
    assert status["calibration_status"] == "fail_check_solution"

    assert call(hub, "POST", "/probe/calibration-exit?" + PH, {})[0] == 200
    assert probe(hub, "ph")["last_adjustment_date"] > 0
    log = call(hub, "GET", "/probe/calibration-log?" + PH)[1]
    assert [entry["point"] for entry in log] == ["MID"]
    assert call(hub, "GET", "/probe/ph/0x00B39/calibration-log")[1] == log
    assert call(hub, "GET", "/probe/calibration-log?" + PH + "&point=high")[1] == []
    idle = call(hub, "GET", "/probe/calibration-status?" + PH)[1]
    assert idle["calibration_status"] == "idle"

    assert call(hub, "POST", "/probe/calibration-restore?" + PH)[0] == 200
    call(hub, "POST", "/probe/calibration-factory-reset?" + PH)
    assert probe(hub, "ph")["last_adjustment_date"] is None


def test_ec_calibration(hub: Any, clock: dict) -> None:
    call(hub, "POST", "/probe/calibration-enter?" + EC)
    bad = {"point": "HIGH", "solution_value": 53.1}
    assert call(hub, "POST", "/probe/calibration-point-start?" + EC, bad)[0] == 400
    point = {"point": "MID", "solution_value": 53.1}
    call(hub, "POST", "/probe/calibration-point-start?" + EC, point)
    clock["t"] += 10
    # Exiting settles the point
    call(hub, "POST", "/probe/calibration-exit?" + EC)
    assert probe(hub, "ec")["last_adjustment_date"] > 0
    call(hub, "POST", "/probe/calibration-enter?" + EC)
    call(
        hub,
        "POST",
        "/probe/calibration-point-start?" + EC,
        {"point": "MID", "solution_value": 5},
    )
    clock["t"] += 10
    assert (
        call(hub, "GET", "/probe/calibration-status?" + EC)[1]["calibration_status"]
        == "fail_value_error"
    )


def test_calibration_refusals(hub: Any) -> None:
    assert call(hub, "POST", "/probe/calibration-enter?" + ORP)[0] == 400
    assert call(hub, "POST", "/probe/calibration-enter?type=ph&uid=0xNONE")[0] == 404
    call(hub, "PUT", "/sim/probe?" + PH, {"status": "disconnected"})
    assert call(hub, "POST", "/probe/calibration-enter?" + PH)[0] == 503


# ── Ports ────────────────────────────────────────────────────────────────────


def _port(hub: Any, number: int) -> dict:
    return next(p for p in dashboard(hub)["ports"] if p["number"] == number)


def test_port_config_toggle_and_schedule(hub: Any) -> None:
    call(hub, "PUT", "/ports/config", [{"number": 0, "mode": "on", "name": "Pump"}])
    port = _port(hub, 0)
    assert (port["mode"], port["name"], port["state"]) == ("on", "Pump", "unknown")
    config = hub.get_data("/ports/config")[0]
    assert config["user_config_mode"] == "on"
    call(hub, "POST", "/port/0/toggle", {})
    assert _port(hub, 0)["mode"] == "off"
    call(hub, "PUT", "/port/0/schedule", {"intervals": [{"time": 0, "duration": 1440}]})
    assert call(hub, "GET", "/port/0/schedule")[1]["intervals"][0]["duration"] == 1440
    call(hub, "PUT", "/ports/config", [{"number": 0, "mode": "schedule"}])
    assert _port(hub, 0)["state"] == "on"
    call(hub, "POST", "/port/0/toggle", {})
    call(hub, "POST", "/port/0/toggle", {})
    # Back to its schedule rather than plain on
    assert _port(hub, 0)["mode"] == "schedule"


def test_port_delete_and_install(hub: Any) -> None:
    assert call(hub, "DELETE", "/port/1")[1]["message"] == "Successfully deleted port"
    port = _port(hub, 1)
    assert (port["type"], port["mode"], port["name"]) == ("unknown", "setup", "S2")
    assert call(hub, "PUT", "/ports/config", [{"number": 1, "mode": "on"}])[0] == 503
    assert call(hub, "GET", "/port/1/schedule")[0] == 503
    assert call(hub, "PUT", "/port/1/schedule", {"intervals": []})[0] == 503
    assert call(hub, "POST", "/port/1/toggle", {})[0] == 503
    call(hub, "POST", "/port/1/install", {"type": "other"})
    assert _port(hub, 1)["type"] == "other"
    assert call(hub, "PUT", "/ports/config", [{"number": 1, "mode": "on"}])[0] == 200
    assert call(hub, "POST", "/port/9/install", {})[0] == 404


def test_port_follows_a_probe(hub: Any) -> None:
    rule = {
        "number": 1,
        "type": "temperature",
        "uid": "0x000F7",
        "sensor": "primary",
        "is_above": True,
        "value": 26,
        "hysteresis": 0.5,
        "trigger_op": True,
        "default_state": False,
    }
    call(hub, "PUT", "/ports/subscribe", {"ports": [rule]})
    assert hub.get_data("/ports/config")[1]["sensor"]["default_state"] is False
    call(hub, "PUT", "/ports/config", [{"number": 1, "mode": "sensor"}])
    assert _port(hub, 1)["state"] == "standby"
    call(hub, "PUT", "/sim/probe?" + TEMP, {"value": 26.5})
    assert _port(hub, 1)["state"] == "on"
    # Hysteresis: stays on until 0.5 °C under the threshold
    call(hub, "PUT", "/sim/probe?" + TEMP, {"value": 25.8})
    assert _port(hub, 1)["state"] == "on"
    call(hub, "PUT", "/sim/probe?" + TEMP, {"value": 25.4})
    assert _port(hub, 1)["state"] == "standby"
    # An unplugged probe falls back on the default state
    call(hub, "PUT", "/sim/probe?" + TEMP, {"status": "disconnected", "value": 30})
    assert _port(hub, 1)["state"] == "standby"
    rules = call(hub, "GET", "/subscription-info")[1]["internal"]
    assert rules[0]["last_sock_op"] == "off"


def test_setup_finish(hub: Any) -> None:
    assert hub.get_data("/mode")["mode"] == "setup"
    call(hub, "POST", "/setup-finish", {})
    assert hub.get_data("/mode")["mode"] == "auto"


def test_sim_controls_refuse_unknown_targets(hub: Any) -> None:
    assert call(hub, "PUT", "/sim/probe?type=ph&uid=0xNONE", {})[0] == 404
    assert call(hub, "PUT", "/sim/probe?" + PH, "x")[0] == 400
    assert call(hub, "GET", "/unknown") is None


# ── Logs ─────────────────────────────────────────────────────────────────────


def test_logs_follow_the_readings(hub: Any) -> None:
    call(hub, "POST", "/probe/offset?" + PH, {"offset": 1})
    log = call(hub, "GET", "/temperature-log?" + PH + "&duration=PT720H")[1]
    assert log["avg"][0] == 26.1
    assert call(hub, "GET", "/sensor-log?" + ORP)[1]["avg"][0] == 250


def test_readings_per_probe_type(hub: Any) -> None:
    """GET /probe answers in the shape each type has on a real hub."""
    assert set(call(hub, "GET", "/probe?" + EC)[1]) == {
        "name",
        "status",
        "ec",
        "ppt",
        "sg",
        "temperature",
    }
    ph = call(hub, "GET", "/probe?" + PH)[1]
    assert ph["value"] == 8.15 and ph["temperature"] == {"value": 25.1}
    ato = call(hub, "GET", "/probe?type=ato&uid=0x0024E")[1]
    assert ato["ato_sensor_status"] == "below"
    assert set(call(hub, "GET", "/probe?" + TEMP)[1]) == {"name", "status", "value"}
    info = call(hub, "GET", "/probe/info?" + PH)[1]
    assert info["hw_revision"] == "2.3.0"


def test_probe_config_ranges_and_temperature(hub: Any) -> None:
    body = [
        {"type": "ph", "uid": "0x00B39", "ranges": [7.5, 7.8, 8.3, 8.5]},
        {
            "type": "ph",
            "uid": "0x00B39",
            "temp": {"ranges": [20, 22, 27, 29], "buzzer": True, "notify": False},
        },
        "junk",
        {"type": "ph", "uid": "0xNONE", "name": "x"},
    ]
    call(hub, "PUT", "/probe/config", body)
    config = next(c for c in call(hub, "GET", "/probe/config")[1] if c["type"] == "ph")
    assert config["ranges"] == [7.5, 7.8, 8.3, 8.5]
    assert config["temp"] == {
        "ranges": [20, 22, 27, 29],
        "buzzer": True,
        "notify": False,
    }
    # The temperature buzzer now sounds for a danger on it
    call(hub, "PUT", "/sim/probe?" + PH, {"temp": 31})
    assert dashboard(hub)["buzzer"]["cause"] == "danger"
