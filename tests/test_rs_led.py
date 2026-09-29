"""ReefLED: the week of programs, as the app writes it, and the light given."""

from __future__ import annotations

from typing import Any

import pytest

import function_extension as fx
from conftest import build, call

led = fx.rs_led


@pytest.fixture
def g1() -> Any:
    return build("LED_G1_160")


@pytest.fixture
def g2() -> Any:
    return build("LED_G2")


@pytest.fixture
def g1_90() -> Any:
    return build("LED_G1_90")


def at(monkeypatch: pytest.MonkeyPatch, weekday: int, hhmm: str) -> None:
    """Pin the lamps' clock to a weekday and a time."""
    h, m = (int(v) for v in hhmm.split(":"))
    monkeypatch.setattr(led, "now", lambda: (weekday, h * 60 + m))


def manual(server: Any) -> dict:
    call(server, "GET", "/manual")
    return server.get_data("/manual")


# --- Programs -----------------------------------------------------------------
def test_g1_program_levels(g1: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # Tuesday: white rises at 11:00 (2100), full from 13:00 to 19:00
    at(monkeypatch, 2, "09:04")
    assert (manual(g1)["white"], manual(g1)["blue"]) == (0, 0)
    at(monkeypatch, 2, "12:00")
    levels = manual(g1)
    assert (levels["white"], levels["blue"]) == (50, 100)
    assert levels["white_pwm"] == round(50 * led.PWM_MAX / 100)
    # The dashboard follows, with today's program name
    call(g1, "GET", "/dashboard")
    dash = g1.get_data("/dashboard")
    assert dash["manual"]["white"] == 50
    assert dash["current_program"]["name"] == "Perso"


def test_clouds_dim_the_light(g1: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # Tuesday's clouds: 2299..2436 (14:19..16:36), 4 min of cloud, 6 clear
    at(monkeypatch, 2, "14:20")
    assert manual(g1)["white"] == round(100 * led.CLOUD_DIMMING["Medium"])
    at(monkeypatch, 2, "14:24")
    assert manual(g1)["white"] == 100
    assert call(g1, "DELETE", "/clouds/2") == (
        200,
        {"success": True, "message": "clouds deleted"},
    )
    assert g1.get_data("/clouds/2") == {}
    at(monkeypatch, 2, "14:20")
    assert manual(g1)["white"] == 100


def test_moon_runs_past_midnight(g1: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # Monday's moon: 22:25 to 01:23 on Tuesday, full from 23:40 to 00:10
    at(monkeypatch, 2, "00:00")
    assert manual(g1)["moon"] == 10
    at(monkeypatch, 2, "00:30")
    assert manual(g1)["moon"] == 7
    # Sunday's moon goes on on Monday: the week wraps
    at(monkeypatch, 1, "00:00")
    assert manual(g1)["moon"] == 10


def test_app_write_order(g1: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    program = {
        "white": {"rise": 1500, "set": 2000, "points": [{"t": 100, "i": 80}]},
        "blue": {"rise": 1500, "set": 2000, "points": [{"t": 100, "i": 90}]},
        "moon": {"rise": 2010, "set": 2100, "points": [{"t": 30, "i": 5}]},
    }
    clouds = {
        "from": 1700,
        "to": 1800,
        "intensity": "High",
        "cloud_duration": 6,
        "no_cloud_duration": 4,
    }
    assert call(g1, "POST", "/preset_name/2", {"name": "Reef-1759130000000"})[0] == 200
    assert call(g1, "POST", "/clouds/2", clouds)[0] == 200
    assert call(g1, "POST", "/auto/2", program)[0] == 200
    call(g1, "POST", "/mode", {"mode": "manual"})
    assert call(g1, "POST", "/auto/apply", {})[0] == 200
    assert g1.get_data("/auto/2") == program
    assert g1.get_data("/clouds/2") == clouds
    # Both name endpoints of this firmware
    assert g1.get_data("/preset_name/2") == {"name": "Reef-1759130000000"}
    assert g1.get_data("/preset_name")[1] == {"day": 2, "name": "Reef-1759130000000"}
    assert g1.get_data("/mode") == {"mode": "auto"}
    at(monkeypatch, 2, "02:40")
    assert manual(g1)["white"] == 80
    # Under a cloud
    at(monkeypatch, 2, "04:20")
    assert manual(g1)["white"] == round(60 * led.CLOUD_DIMMING["High"])
    call(g1, "GET", "/dashboard")
    assert g1.get_data("/dashboard")["current_program"]["name"] == (
        "Reef-1759130000000"
    )


def test_names_on_the_endpoints_the_lamp_has(g2: Any, g1_90: Any) -> None:
    # The G2 fixture only has the list: the per-day write still lands in it
    assert call(g2, "POST", "/preset_name/3", {"name": "Deep"})[0] == 200
    assert g2.get_data("/preset_name")[2] == {"day": 3, "name": "Deep"}
    assert "/preset_name/3" not in g2._db
    # A RSLED90 only has the per-day endpoints
    call(g1_90, "POST", "/preset_name/3", {"name": "Deep"})
    assert g1_90.get_data("/preset_name/3") == {"name": "Deep"}
    assert led.preset_name(g1_90, 3) == "Deep"
    assert led.preset_name(g1_90, 9) is None
    assert call(g2, "POST", "/preset_name/3", {})[0] == 400
    # A day missing from the list is added
    g2._db["/preset_name"]["data"] = [{"day": 1, "name": "A"}]
    led.set_preset_name(g2, 4, "B")
    assert g2.get_data("/preset_name") == [
        {"day": 1, "name": "A"},
        {"day": 4, "name": "B"},
    ]


def test_g2_program_and_its_clouds(g2: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # Monday: the day of the fixture, kelvin from the points
    at(monkeypatch, 1, "12:00")
    levels = manual(g2)
    assert levels["intensity"] == 60
    assert levels["kelvin"] == 14500
    assert levels["blue"] > levels["white"] > 0
    at(monkeypatch, 1, "08:00")
    levels = manual(g2)
    assert (levels["intensity"], levels["kelvin"]) == (0, 14000)
    program = {
        "color": {
            "rise": 600,
            "set": 1200,
            "points": [{"t": 60, "i1": 80, "k1": 20000, "i2": 40, "k2": 10000}],
        },
        "moon": {"rise": 1210, "set": 1300, "points": [{"t": 30, "i": 5}]},
        "clouds": {"from": 700, "to": 800, "intensity": "Low"},
    }
    call(g2, "POST", "/auto/1", program)
    assert g2.get_data("/clouds/1")["intensity"] == "Low"
    assert g2.get_data("/auto/1")["clouds"]["from"] == 700
    # Left from (40 %, 10000 K) after the point
    at(monkeypatch, 1, "11:30")
    assert (manual(g2)["intensity"], manual(g2)["kelvin"]) == (38, 10000)
    at(monkeypatch, 1, "10:30")
    assert manual(g2)["intensity"] == 40
    # A program without clouds removes them
    del program["clouds"]
    call(g2, "POST", "/auto/1", program)
    assert g2.get_data("/clouds/1") == {}
    # Clouds deleted: out of the program too
    call(g2, "POST", "/auto/1", {**program, "clouds": {"from": 700, "to": 800}})
    call(g2, "DELETE", "/clouds/1")
    assert "clouds" not in g2.get_data("/auto/1")


def test_modes(g2: Any, g1_90: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, 1, "12:00")
    assert call(g2, "POST", "/manual", {"kelvin": 23000, "intensity": 50})[0] == 200
    assert g2.get_data("/mode") == {"mode": "manual"}
    assert g2.get_data("/dashboard")["mode"] == "manual"
    # The hand-set levels stay
    levels = manual(g2)
    assert (levels["intensity"], levels["white"], levels["blue"]) == (50, 0, 50)
    call(g2, "POST", "/timer", {"white": 10, "duration": 30})
    assert g2.get_data("/mode") == {"mode": "timer"}
    assert g2.get_data("/timer") == {"timer_status": "timer enabled", "duration": 30}
    assert manual(g2)["white"] == 10
    call(g2, "POST", "/mode", {"mode": "off"})
    assert manual(g2)["intensity"] == 0
    assert call(g2, "POST", "/mode", {})[0] == 400
    # A RSLED90: no dashboard, /manual only
    call(g1_90, "POST", "/manual", {"white": 30, "blue": 40, "moon": 2})
    assert (manual(g1_90)["white"], manual(g1_90)["blue"]) == (30, 40)
    assert "/dashboard" not in g1_90._db


def test_settings_mirrored_on_the_dashboard(
    g1: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = {"enabled": True, "duration": 30, "current_intensity_factor": 50}
    assert call(g1, "POST", "/acclimation", body)[0] == 200
    assert g1.get_data("/acclimation")["duration"] == 30
    assert g1.get_data("/dashboard")["acclimation"]["current_intensity_factor"] == 50
    at(monkeypatch, 2, "12:00")
    assert manual(g1)["blue"] == 50
    call(g1, "POST", "/moonphase", {"enabled": False})
    assert g1.get_data("/dashboard")["moon_phase"]["enabled"] is False
    assert call(g1, "POST", "/moonphase", "x")[0] == 400
    assert call(g1, "POST", "/identify", {})[0] == 200


def test_bad_requests_and_other_devices(g1: Any) -> None:
    assert call(g1, "POST", "/auto/1", [])[0] == 400
    assert call(g1, "POST", "/clouds/1", None)[0] == 400
    assert call(g1, "POST", "/manual", None)[0] == 400
    # Left to the generic machinery
    assert led.handle(g1, "POST", "/firmware", {}) is None
    assert led.handle(g1, "DELETE", "/auto/1", None) is None
    assert led.handle(g1, "GET", "/device-info", None) is None
    assert led.handle(build("RSDOSE4"), "POST", "/auto/1", {}) is None


def test_clock(g1: Any) -> None:
    try:
        assert call(g1, "PUT", "/sim/clock", {"minute": 725}) == (200, {"minute": 725})
        assert call(g1, "GET", "/sim/clock") == (200, {"minute": 725})
        assert led.now()[1] == 725
    finally:
        call(g1, "PUT", "/sim/clock", {"minute": None})
    assert call(g1, "GET", "/sim/clock") == (200, {"minute": None})


def test_level_helpers() -> None:
    assert led.channel_level(None, 10) == 0
    assert led.channel_level({"rise": 0, "set": 100, "points": []}, 50) == 0
    assert led.color_level({"rise": 0, "set": 10, "points": []}, 5) == (
        0.0,
        led.DEFAULT_KELVIN,
    )
    assert led.clouds_factor(None, 10) == 1.0
    assert led.clouds_factor({"from": 0, "to": 10}, 20) == 1.0
    assert led.white_blue_of(9000, 100) == (100, 60)


def test_over_http() -> None:
    """The integration's write sequence, over HTTP."""
    from test_http import _serve, request

    server = _serve("LED_G1_160")
    try:
        assert request(server, "GET", "/preset_name")[0] == 200
        assert request(server, "POST", "/preset_name/1", {"name": "A-1"})[0] == 200
        assert request(server, "POST", "/clouds/1", {"from": 1, "to": 2})[0] == 200
        assert request(server, "DELETE", "/clouds/1")[0] == 200
        assert request(server, "GET", "/clouds/1") == (200, {})
        status, _ = request(server, "POST", "/auto/1", {"moon": {"rise": 0}})
        assert status == 200
        assert request(server, "GET", "/auto/1") == (200, {"moon": {"rise": 0}})
        assert request(server, "POST", "/auto/apply", {})[0] == 200
        assert request(server, "GET", "/manual")[0] == 200
    finally:
        server.shutdown()
        server.server_close()
