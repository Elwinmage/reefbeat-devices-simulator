"""Clock and probe rules shared by the RSCONTROL hub and the RSPower strips.

A 12V port of the hub, or a socket of a strip, can follow a schedule or a
probe. Both devices decide on their own whether the output is powered; the
simulator serves fixtures, so these helpers make that decision when the
dashboard is polled.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional


def minutes_now() -> int:
    """Minutes elapsed since midnight, local time."""
    now = datetime.now()
    return now.hour * 60 + now.minute


def is_within(intervals: Any, minute: int) -> bool:
    """Whether a moment falls inside one of the ON windows of a schedule.

    Intervals are ``{"time": <minutes from midnight>, "duration": <minutes>}``.
    A window running past midnight wraps around to the start of the day,
    which is how the devices store an overnight programme.
    """
    if not isinstance(intervals, list):
        return False
    day = 24 * 60
    for interval in intervals:
        if not isinstance(interval, dict):
            continue
        try:
            start = int(interval["time"])
            duration = int(interval["duration"])
        except (KeyError, TypeError, ValueError):
            continue
        if duration <= 0:
            continue
        if (minute - start) % day < duration:
            return True
    return False


def is_on(value: Any) -> bool:
    """Read a rule flag written as a boolean, "on"/"off" or 1/0."""
    if isinstance(value, str):
        return value.lower() in ("on", "true", "1", "yes")
    return bool(value)


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def as_float(value: Any) -> Optional[float]:
    """A JSON number as a float, None for anything else (bools included)."""
    return float(value) if is_number(value) else None


def evaluate(rule: dict[str, Any], reading: Any, previous: Optional[bool]) -> bool:
    """Whether an output following a probe rule is powered.

    Args:
        rule: the rule, as stored in ``/subscription-info`` (hub) or
            ``/temperature/subscriptions`` (strip): ``type``, ``is_above``,
            ``value``, ``hysteresis``, ``trigger_op`` (hub) or ``turn_on``
            (strip), ``default_state``.
        reading: what the probe reports — a number, the ``water_level`` of
            an ATO probe, whether a leak probe is wet — or None when the
            probe cannot be read (missing, unplugged, disabled).
        previous: whether the output was powered at the previous
            evaluation, None the first time. Used for the hysteresis: once
            triggered, the reading has to come back past the threshold by
            ``hysteresis`` before the output switches back.

    Returns:
        True when powered. Without a reading, the rule's ``default_state``.
    """
    if reading is None:
        return is_on(rule.get("default_state", False))
    trigger = is_on(rule.get("trigger_op", rule.get("turn_on", True)))
    ptype = rule.get("type")
    if ptype == "leak":
        condition = bool(reading)
    elif ptype == "ato":
        # The level probe asks for water while it reads below its mark
        condition = reading == "below"
    else:
        value = as_float(reading)
        threshold = as_float(rule.get("value"))
        if value is None or threshold is None:
            return is_on(rule.get("default_state", False))
        margin = as_float(rule.get("hysteresis")) or 0.0
        triggered_before = previous is not None and previous == trigger
        if is_on(rule.get("is_above", True)):
            condition = value > threshold - (margin if triggered_before else 0)
        else:
            condition = value < threshold + (margin if triggered_before else 0)
    return trigger if condition else not trigger
