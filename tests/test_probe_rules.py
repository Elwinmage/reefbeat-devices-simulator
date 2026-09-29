"""Rules deciding whether an output following a probe is powered."""

from __future__ import annotations

from function_extension.probe_rules import evaluate, is_on, is_within


def test_threshold_with_hysteresis() -> None:
    rule = {
        "type": "temperature",
        "is_above": True,
        "value": 26,
        "hysteresis": 0.5,
        "trigger_op": "on",
    }
    assert evaluate(rule, 26.2, None) is True
    assert evaluate(rule, 25.8, True) is True
    assert evaluate(rule, 25.4, True) is False
    assert evaluate(rule, 25.8, False) is False


def test_below_and_trigger_off() -> None:
    rule = {"type": "ph", "is_above": False, "value": 8.0, "trigger_op": False}
    assert evaluate(rule, 7.9, None) is False
    assert evaluate(rule, 8.1, None) is True


def test_leak_ato_and_missing_readings() -> None:
    leak = {"type": "leak", "trigger_op": "off", "default_state": True}
    assert evaluate(leak, True, None) is False
    assert evaluate(leak, False, None) is True
    assert evaluate(leak, None, None) is True
    ato = {"type": "ato", "trigger_op": True}
    assert evaluate(ato, "below", None) is True
    assert evaluate(ato, "desired_level_1", None) is False
    no_value = {"type": "ec", "default_state": True}
    assert evaluate(no_value, 50, None) is True


def test_flags_and_schedules() -> None:
    assert is_on("ON") and is_on(1) and not is_on("off")
    assert is_within([{"time": 1380, "duration": 120}], 30)
    assert not is_within([{"time": 1380, "duration": 120}], 90)
    assert not is_within("x", 0)
    assert not is_within([{"time": "x"}, {"time": 0, "duration": 0}, "y"], 0)


def test_ato_rule_without_trigger_op_pumps_only_below() -> None:
    # The app sends an ATO rule as {uid, type, sensor, default_state}: the
    # trigger_op the hub stores by default must not invert the pump
    rule = {"type": "ato", "trigger_op": False, "default_state": False}
    assert evaluate(rule, "below", None) is True
    assert evaluate(rule, "desired_level_1", True) is False
    assert evaluate(rule, None, None) is False
