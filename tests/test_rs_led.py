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
    call(g1, "POST", "/moonphase", {"enabled": False})  # the program as it is
    at(monkeypatch, 2, "00:00")
    assert manual(g1)["moon"] == 10
    at(monkeypatch, 2, "00:30")
    assert manual(g1)["moon"] == 7
    # Sunday's moon goes on on Monday: the week wraps
    at(monkeypatch, 1, "00:00")
    assert manual(g1)["moon"] == 10


def test_write_order(g1: Any, monkeypatch: pytest.MonkeyPatch) -> None:
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
    # As the firmware: new clouds outside the program held are refused, and
    # so is a program leaving the held clouds (Tuesday: 14:19..16:36) out
    assert call(g1, "POST", "/clouds/2", clouds) == led.OUTSIDE_PRESET
    assert call(g1, "POST", "/auto/2", program) == led.OUTSIDE_PRESET
    # Clouds removed, program, then its clouds
    assert call(g1, "DELETE", "/clouds/2")[0] == 200
    assert call(g1, "POST", "/auto/2", program)[0] == 200
    assert call(g1, "POST", "/clouds/2", clouds)[0] == 200
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
    # A G2 computes its white and blue: written, they are ignored (the
    # whole /manual read back and sent as it is would set them to 0)
    body = {"kelvin": 12000, "intensity": 50, "white": 0, "blue": 0, "moon": 4}
    call(g2, "POST", "/manual", body)
    levels = manual(g2)
    assert (levels["kelvin"], levels["intensity"], levels["moon"]) == (12000, 50, 4)
    assert (levels["white"], levels["blue"]) == tuple(
        int(round(v)) for v in led.white_blue_of(12000, 50)
    )
    assert levels["white"] > 0 and levels["blue"] > 0
    call(g2, "POST", "/timer", {"white": 10, "intensity": 40, "duration": 30})
    assert g2.get_data("/mode") == {"mode": "timer"}
    assert g2.get_data("/timer") == {"timer_status": "timer enabled", "duration": 30}
    assert manual(g2)["white"] == int(round(led.white_blue_of(12000, 40)[0]))
    call(g2, "POST", "/mode", {"mode": "off"})
    assert manual(g2)["intensity"] == 0
    assert call(g2, "POST", "/mode", {})[0] == 400
    # A RSLED90: no dashboard, /manual only
    call(g1_90, "POST", "/manual", {"white": 30, "blue": 40, "moon": 2})
    assert (manual(g1_90)["white"], manual(g1_90)["blue"]) == (30, 40)
    assert "/dashboard" not in g1_90._db


@pytest.fixture
def calendar() -> Any:
    """Move the lamps' calendar, back to today afterwards."""
    yield led.set_days
    led.set_days(0)


def test_acclimation_runs_over_its_days(
    g1: Any, monkeypatch: pytest.MonkeyPatch, calendar: Any
) -> None:
    at(monkeypatch, 2, "12:00")  # blue at 100 without acclimation
    assert manual(g1)["blue"] == 100
    # As the integration and the app start it: its settings only
    body = {"duration": 10, "start_intensity_factor": 50}
    assert call(g1, "POST", "/acclimation", body) == (200, {"success": True})
    acc = g1.get_data("/acclimation")
    assert acc["enabled"] is True and isinstance(acc["started_on"], int)
    assert (acc["remaining_days"], acc["current_intensity_factor"]) == (10, 50)
    assert g1.get_data("/dashboard")["acclimation"] == acc
    assert manual(g1)["blue"] == 50
    # Day after day, in equal steps; read on any of the endpoints
    calendar(4)
    call(g1, "GET", "/acclimation")
    acc = g1.get_data("/acclimation")
    assert (acc["remaining_days"], acc["current_intensity_factor"]) == (6, 70)
    assert manual(g1)["blue"] == 70
    # Written again: started again, from that day
    started = acc["started_on"]
    call(g1, "POST", "/acclimation", {"duration": 8})
    acc = g1.get_data("/acclimation")
    assert acc["started_on"] > started
    assert (acc["remaining_days"], acc["current_intensity_factor"]) == (8, 50)
    calendar(8)
    call(g1, "GET", "/acclimation")
    assert g1.get_data("/acclimation")["current_intensity_factor"] == 75
    # Over: it turns itself off
    calendar(12)
    call(g1, "GET", "/dashboard")
    acc = g1.get_data("/dashboard")["acclimation"]
    assert (acc["enabled"], acc["started_on"]) == (False, "never")
    assert (acc["remaining_days"], acc["current_intensity_factor"]) == (0, 100)
    assert acc["duration"] == 8 and acc["start_intensity_factor"] == 50
    assert manual(g1)["blue"] == 100
    # Stopped by hand
    calendar(0)
    call(g1, "POST", "/acclimation", {})
    assert g1.get_data("/acclimation")["current_intensity_factor"] == 50
    assert call(g1, "DELETE", "/acclimation") == (200, {"success": True})
    acc = g1.get_data("/acclimation")
    assert (acc["enabled"], acc["started_on"]) == (False, "never")
    assert g1.get_data("/dashboard")["acclimation"] == acc
    assert led.acclimation_factor(g1) == 1.0


def test_acclimation_bad_requests_and_fixtures(g1: Any, g1_90: Any) -> None:
    for body in (
        "x",
        {"enabled": "yes"},
        {"duration": 0},
        {"duration": True},
        {"start_intensity_factor": 101},
        {"start_intensity_factor": "50"},
    ):
        assert call(g1, "POST", "/acclimation", body)[0] == 400
    assert g1.get_data("/acclimation")["enabled"] is False
    # A lamp without dashboard, or without the endpoint
    assert call(g1_90, "POST", "/acclimation", {"duration": 3})[0] == 200
    del g1._db["/acclimation"]
    led.refresh_acclimation(g1)
    assert led.acclimation_factor(g1) == 1.0
    assert call(g1, "POST", "/acclimation", {"enabled": True, "duration": 5})[0] == 200
    assert g1.get_data("/acclimation")["remaining_days"] == 5
    # An acclimation enabled without a start (odd fixture): not running
    state = led.acclimation_state({"enabled": True, "started_on": "never"}, 1)
    assert (state["enabled"], state["current_intensity_factor"]) == (False, 100)


def test_moon_phase_cycle() -> None:
    # As captured on lamps: day 2 -> 14 %, day 28 -> 0 %
    assert [led.moon_intensity(d) for d in (1, 2, 7, 14, 21, 28)] == [
        7,
        14,
        50,
        100,
        50,
        0,
    ]
    assert [led.moon_name(d) for d in (1, 2, 7, 13, 14, 15, 21, 28)] == [
        "New Moon",
        "Waxing Crescent",
        "First Quarter",
        "Waxing Gibbous",
        "Full Moon",
        "Waning Gibbous",
        "Last Quarter",
        "Waning Crescent",
    ]
    # The fixtures: (day 2: full in 12, new in 27), (day 28: 14 and 1)
    state = led.moon_state({}, (100, 2), 100)
    assert (state["next_full_moon"], state["next_new_moon"]) == (12, 27)
    state = led.moon_state({}, (100, 2), 126)
    assert (state["todays_moon_day"], state["intensity"]) == (28, 0)
    assert (state["next_full_moon"], state["next_new_moon"]) == (14, 1)
    assert led.moon_state({}, (100, 2), 127)["todays_moon_day"] == 1


def test_moon_phase_dims_the_moon(
    g1: Any, monkeypatch: pytest.MonkeyPatch, calendar: Any
) -> None:
    at(monkeypatch, 2, "00:00")  # Monday's moon, at 10 in the program
    # The fixture: day 2 of the cycle, 14 % of the full moon
    moon = manual(g1)
    assert (moon["moon"], moon["moon_full"]) == (1, 1.4)
    assert g1.get_data("/moonphase")["todays_moon_day"] == 2
    # Today set as the full moon
    assert call(g1, "POST", "/moonphase", {"moon_day": 14})[0] == 200
    phase = g1.get_data("/moonphase")
    assert (phase["todays_moon_day"], phase["intensity"]) == (14, 100)
    assert (phase["name"], phase["next_full_moon"]) == ("Full Moon", 0)
    assert "moon_day" not in phase and phase["started_on"] > 1758491094
    assert g1.get_data("/dashboard")["moon_phase"] == phase
    assert manual(g1)["moon"] == 10
    # A week later: last quarter
    calendar(7)
    call(g1, "GET", "/moonphase")
    phase = g1.get_data("/moonphase")
    assert (phase["todays_moon_day"], phase["intensity"]) == (21, 50)
    assert manual(g1)["moon"] == 5
    # Turned off: the moon of the program as it is, the cycle goes on
    started = phase["started_on"]
    assert call(g1, "DELETE", "/moonphase") == (200, {"success": True})
    assert g1.get_data("/dashboard")["moon_phase"]["enabled"] is False
    assert manual(g1)["moon"] == 10
    assert g1.get_data("/moonphase")["started_on"] == started
    # On again (a write without a day): started now, same day of the cycle
    call(g1, "POST", "/moonphase", {})
    phase = g1.get_data("/moonphase")
    assert phase["enabled"] is True
    assert phase["started_on"] > started and phase["todays_moon_day"] == 21
    call(g1, "POST", "/moonphase", {"enabled": True})
    assert g1.get_data("/moonphase")["started_on"] == phase["started_on"]


def test_moon_phase_bad_requests_and_fixtures(g1: Any) -> None:
    for body in (
        "x",
        {"enabled": 1},
        {"moon_day": 0},
        {"moon_day": 29},
        {"moon_day": True},
        {"moon_day": 2.5},
    ):
        assert call(g1, "POST", "/moonphase", body)[0] == 400
    assert call(g1, "POST", "/identify", {})[0] == 200
    # A lamp without the endpoint
    del g1._db["/moonphase"]
    led.refresh_moon(g1)
    assert led.moon_factor(g1) == 1.0
    assert call(g1, "POST", "/moonphase", {"enabled": True})[0] == 200
    assert g1.get_data("/moonphase")["todays_moon_day"] == 1


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
    clock = {"minute": 725, "days": 0}
    try:
        assert call(g1, "PUT", "/sim/clock", {"minute": 725}) == (200, clock)
        assert call(g1, "GET", "/sim/clock") == (200, clock)
        assert led.now()[1] == 725
        # The lamps' calendar, moved without touching the minute
        today = led.today()
        moved = {"minute": 725, "days": 3}
        assert call(g1, "PUT", "/sim/clock", {"days": 3}) == (200, moved)
        assert led.today() == today + 3
        assert call(g1, "PUT", "/sim/clock", {"minute": 10, "days": 0})[1] == {
            "minute": 10,
            "days": 0,
        }
    finally:
        call(g1, "PUT", "/sim/clock", {"minute": None, "days": 0})
    assert call(g1, "GET", "/sim/clock") == (200, {"minute": None, "days": 0})
    assert call(g1, "PUT", "/sim/clock", None)[1] == {"minute": None, "days": 0}


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
        assert request(server, "POST", "/clouds/1", {"from": 1, "to": 2})[0] == 500
        clouds = {"from": 900, "to": 950}
        assert request(server, "POST", "/clouds/1", clouds)[0] == 200
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


def test_clouds_checked_against_the_day() -> None:
    program = {"white": {"rise": 600, "set": 1200}, "moon": {"rise": 1300}}
    assert led.clouds_fit({"from": 600, "to": 1200}, program)
    assert not led.clouds_fit({"from": 1250, "to": 1300}, program)
    assert led.clouds_fit({}, program)
    assert led.clouds_fit({"from": 1, "to": 2}, {"moon": {}})
    assert led.light_window(None) is None
    g2 = build("LED_G2")
    body = {
        "color": {"rise": 600, "set": 700, "points": []},
        "clouds": {"from": 650, "to": 800, "intensity": "Low"},
    }
    assert call(g2, "POST", "/auto/1", body) == led.OUTSIDE_PRESET


# --- Staggered sunrise ----------------------------------------------------------
def test_offset_delays_the_program(g1: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    assert call(g1, "GET", "/offset") == (200, {"offset": 0})
    # Tuesday 12:00: white at 50 (see test_g1_program_levels)
    at(monkeypatch, 2, "12:00")
    assert manual(g1)["white"] == 50
    status, answer = call(g1, "POST", "/offset", {"offset": 60})
    assert status == 200 and answer == {"success": True, "message": "Offset saved"}
    assert call(g1, "GET", "/offset") == (200, {"offset": 60})
    # One hour late: at 13:00 the lamp gives what it gave at 12:00
    at(monkeypatch, 2, "13:00")
    assert manual(g1)["white"] == 50
    # A new offset replaces the previous one
    call(g1, "POST", "/offset", {"offset": 12})
    assert call(g1, "GET", "/offset") == (200, {"offset": 12})
    assert call(g1, "DELETE", "/offset")[0] == 200
    assert call(g1, "GET", "/offset") == (200, {"offset": 0})
    for bad in ({}, {"offset": -1}, {"offset": True}, {"offset": "5"}, []):
        assert call(g1, "POST", "/offset", bad)[0] == 400


def test_shifted_wraps_around_the_week() -> None:
    assert led.shifted(2, 60, 30) == (2, 30)
    assert led.shifted(2, 10, 30) == (1, 1420)
    assert led.shifted(1, 0, 1) == (7, 1439)
