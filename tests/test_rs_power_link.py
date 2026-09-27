"""RSPower strip: local probe, sockets following a probe, link with the hub."""

from __future__ import annotations

from typing import Any

import function_extension as fx
from conftest import build, call, dashboard

TEMP = "type=temperature&uid=0x000F7"


def _socket(power: Any, number: int) -> dict:
    return dashboard(power)["sockets"][number]


def _set_mode(power: Any, number: int, mode: str) -> None:
    """What PUT /sockets/config does to the dashboard (generic handler)."""
    power._db["/dashboard"]["data"]["sockets"][number]["mode"] = mode


# ── Pairing ──────────────────────────────────────────────────────────────────


def test_fixtures_start_paired(hub: Any, power: Any) -> None:
    assert dashboard(hub)["connected_device"]["hwid"] == fx.registry.hwid(power)
    assert dashboard(power)["connected_device"]["hwid"] == fx.registry.hwid(hub)
    answer = call(hub, "POST", "/power/discover", {"pair": True})[1]
    assert answer == {"hwid": fx.registry.hwid(power), "paired": True, "success": True}


def test_unpair_from_the_hub_and_pair_again(hub: Any, power: Any) -> None:
    call(hub, "PUT", "/socket/2/subscribe", {"type": "ph", "uid": "0x00B39"})
    assert call(hub, "POST", "/power/unpair", {})[0] == 200
    assert dashboard(hub)["connected_device"] is None
    assert dashboard(power)["connected_device"] is None
    assert call(hub, "GET", "/subscription-info")[1]["external"] == []

    found = call(hub, "POST", "/power/discover", {"pair": False})[1]
    assert found == {"hwid": fx.registry.hwid(power), "pairing_status": "unpaired"}
    call(hub, "POST", "/power/discover", {"pair": True})
    assert dashboard(hub)["connected_device"]["state"] == "paired_connected"
    link = dashboard(power)["connected_device"]
    assert link == {
        "type": "control",
        "hwid": fx.registry.hwid(hub),
        "status": "connected",
        "internet_connected": True,
    }


def test_unpair_from_the_strip(hub: Any, power: Any) -> None:
    assert call(power, "DELETE", "/paired-device")[0] == 200
    assert dashboard(hub)["connected_device"] is None
    assert dashboard(power)["connected_device"] is None


def test_a_strip_with_its_own_probe_does_not_pair(hub: Any, power: Any) -> None:
    call(power, "DELETE", "/paired-device")
    call(power, "POST", "/sensor/install", {"type": "temperature"})
    assert call(hub, "POST", "/power/discover", {"pair": True})[0] == 503
    assert call(hub, "POST", "/power/discover", {"pair": False})[1]["hwid"] == ""


def test_pairs_with_another_free_strip(hub: Any, power: Any) -> None:
    other = build("RSPOWER8")
    call(power, "DELETE", "/paired-device")
    call(power, "POST", "/sensor/install", {})
    call(other, "DELETE", "/paired-device")
    call(hub, "POST", "/power/discover", {"pair": True})
    assert dashboard(hub)["connected_device"]["hwid"] == fx.registry.hwid(other)


# ── Local temperature probe ──────────────────────────────────────────────────


def test_local_probe_needs_an_unpaired_strip(power: Any) -> None:
    assert call(power, "GET", "/temperature/config")[0] == 404
    assert call(power, "GET", "/temperature/subscriptions")[0] == 404
    assert call(power, "POST", "/sensor/install", {"type": "temperature"})[0] == 503
    call(power, "DELETE", "/paired-device")
    status, answer = call(power, "POST", "/sensor/install", {"type": "temperature"})
    assert status == 200 and answer["uid"] == "0x000F7"
    config = call(power, "GET", "/temperature/config")[1]
    # The fixture's config of the probe
    assert config["name"] == "Temp" and config["desired_range_low"] == 25
    assert dashboard(power)["temperature"]["value"] == 25.0


def test_local_offset_adds(power: Any) -> None:
    call(power, "DELETE", "/paired-device")
    assert call(power, "POST", "/probe/offset", {"offset": 1})[0] == 404
    call(power, "POST", "/sensor/install", {})
    call(power, "POST", "/probe/offset", {"offset": 0.3})
    call(power, "POST", "/probe/offset", {"offset": 0.2})
    assert call(power, "GET", "/temperature/config")[1]["offset"] == 0.5
    assert call(power, "GET", "/temperature")[1] == {"temperature": 25.5}
    assert dashboard(power)["temperature"]["value"] == 25.5
    assert call(power, "POST", "/probe/offset", {})[0] == 400
    call(power, "DELETE", "/probe/offset")
    assert call(power, "GET", "/probe/offset")[1]["offset"] == 0


def test_local_probe_config_and_removal(power: Any) -> None:
    call(power, "DELETE", "/paired-device")
    call(power, "POST", "/sensor/install", {})
    call(power, "PUT", "/temperature/config", {"name": "Sump", "desired_range_low": 24})
    assert dashboard(power)["temperature"]["name"] == "Sump"
    call(power, "PUT", "/temperature/subscribe", {"sockets": [{"number": 3}]})
    assert call(power, "DELETE", "/sensor")[0] == 200
    assert dashboard(power)["temperature"] is None
    assert call(power, "GET", "/temperature")[0] == 404
    assert power._db["/temperature/subscriptions"]["data"]["sockets"] == []


# ── Sockets following a probe ────────────────────────────────────────────────


def test_socket_follows_a_hub_probe(hub: Any, power: Any) -> None:
    call(
        power,
        "PUT",
        "/subscribe",
        {"sockets": [{"number": 2, "app_cache": "temperature", "default_state": True}]},
    )
    call(
        hub,
        "PUT",
        "/socket/2/subscribe",
        {
            "type": "temperature",
            "uid": "0x000F7",
            "sensor": "primary",
            "is_above": True,
            "value": 26,
            "trigger_op": True,
        },
    )
    _set_mode(power, 2, "sensor")
    assert _socket(power, 2)["state"] == "standby"
    call(hub, "PUT", "/sim/probe?" + TEMP, {"value": 27})
    assert _socket(power, 2)["state"] == "on"
    assert (
        call(hub, "GET", "/subscription-info")[1]["external"][0]["last_sock_op"] == "on"
    )
    # Without the hub's rule, the socket's default state
    call(hub, "PUT", "/socket/2/unsubscribe", {})
    call(hub, "PUT", "/sim/probe?" + TEMP, {"value": 20})
    assert _socket(power, 2)["state"] == "on"
    call(power, "PUT", "/unsubscribe", {"sockets": [2]})
    assert power.get_data("/sockets/config")["sockets"][2]["sensor"] is None
    assert _socket(power, 2)["state"] == "standby"


def test_socket_follows_the_local_probe(power: Any) -> None:
    call(power, "DELETE", "/paired-device")
    call(power, "POST", "/sensor/install", {})
    call(
        power,
        "PUT",
        "/temperature/subscribe",
        {
            "sockets": [
                {
                    "number": 3,
                    "is_above": False,
                    "value": 24,
                    "turn_on": True,
                    "sensor": "primary",
                }
            ]
        },
    )
    _set_mode(power, 3, "sensor")
    # 25 °C is not below 24: the heater stays off
    assert _socket(power, 3)["state"] == "standby"
    call(power, "POST", "/probe/offset", {"offset": -2})
    assert _socket(power, 3)["state"] == "on"


def test_schedule_sockets_still_follow_the_clock(power: Any) -> None:
    assert _socket(power, 0)["state"] == "on"


def test_setup_finish_on_the_strip(power: Any) -> None:
    power._db["/dashboard"]["data"]["mode"] = "setup"
    call(power, "POST", "/setup-finish", {})
    assert dashboard(power)["mode"] == "auto"


def test_other_paths_are_left_to_the_generic_handler(power: Any) -> None:
    assert call(power, "GET", "/dashboard") is None
    assert call(power, "DELETE", "/socket/2/config/schedule") is None


# ── Socket configuration and deletion ────────────────────────────────────────


def test_partial_socket_config_keeps_the_others(power: Any) -> None:
    body = {"sockets": [{"number": 2, "mode": "on", "name": "Heater"}]}
    assert call(power, "PUT", "/sockets/config", body)[0] == 200
    sockets = power.get_data("/sockets/config")["sockets"]
    assert len(sockets) == 6
    assert (sockets[2]["name"], sockets[2]["mode"]) == ("Heater", "on")
    assert sockets[2]["user_config_mode"] == "on"
    assert sockets[0]["name"] == "Led refuge"
    socket = _socket(power, 2)
    assert (socket["name"], socket["mode"], socket["prev_mode"]) == (
        "Heater",
        "on",
        "setup",
    )
    call(power, "PUT", "/sockets/config", {"number": 2, "mode": "off"})
    assert _socket(power, 2)["state"] == "unknown"
    assert (
        call(power, "PUT", "/sockets/config", {"sockets": ["junk", {"number": 99}]})[0]
        == 200
    )


def test_socket_delete(power: Any) -> None:
    call(power, "DELETE", "/paired-device")
    call(power, "POST", "/sensor/install", {})
    call(
        power,
        "PUT",
        "/sockets/config",
        {"sockets": [{"number": 3, "mode": "sensor", "name": "Heater"}]},
    )
    call(
        power,
        "PUT",
        "/subscribe",
        {"sockets": [{"number": 3, "app_cache": "temperature"}]},
    )
    call(
        power,
        "PUT",
        "/temperature/subscribe",
        {"sockets": [{"number": 3, "value": 24}]},
    )
    assert call(power, "DELETE", "/socket/3/config") == (
        200,
        {"success": True, "message": "Successfully deleted sockets"},
    )
    socket = _socket(power, 3)
    assert (socket["mode"], socket["name"], socket["state"]) == (
        "setup",
        "S4",
        "unknown",
    )
    config = power.get_data("/sockets/config")["sockets"][3]
    assert (config["mode"], config["name"], config["sensor"]) == ("setup", "S4", None)
    assert call(power, "GET", "/temperature/subscriptions")[1]["sockets"] == []
    assert call(power, "DELETE", "/socket/9/config")[0] == 404
    assert call(power, "PUT", "/unsubscribe", {"sockets": [3]})[0] == 200
