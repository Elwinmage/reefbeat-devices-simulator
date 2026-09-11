"""Modifiers for the ReefPower smart power centers (RSPOWER6, RSPOWER8)."""

from datetime import datetime
from typing import Any


def _minutes_now() -> int:
    """Return minutes elapsed since midnight, local time."""
    now = datetime.now()
    return now.hour * 60 + now.minute


def _is_within(intervals: Any, minute: int) -> bool:
    """Whether a moment falls inside one of a socket's ON windows.

    Intervals are ``{"time": <minutes from midnight>, "duration": <minutes>}``
    and mark the periods a socket is powered. A window running past midnight
    wraps around to the start of the day, which is how the device stores an
    overnight programme rather than splitting it in two.

    Args:
        intervals: the schedule's interval list, as served by the device.
        minute: minutes since midnight to test.

    Returns:
        True when the socket should be on at that moment.
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

        offset = (minute - start) % day
        if offset < duration:
            return True
    return False


def apply_socket_schedules(
    path: str, data: dict[str, Any], params: Any, ctx: Any
) -> dict[str, Any]:
    """Drive schedule-controlled sockets from the clock.

    A real strip decides for itself whether a scheduled socket is powered
    right now; the simulator serves a fixture, so without this the socket
    stays at whatever state was written into it and a schedule can never be
    seen working.

    Only sockets whose mode is ``schedule`` are touched. The others are left
    exactly as they are: their state is owned by the toggle actions and by
    whatever the client last wrote.

    Args:
        path: the endpoint being served.
        data: the dashboard payload, modified in place.
        params: modifier parameters; ``path`` selects the endpoint.
        ctx: the request context, carrying the server and its DB.

    Returns:
        The dashboard payload.
    """
    if path != getattr(params, "path", None):
        return data

    server = getattr(ctx, "server", None)
    if server is None:
        return data

    sockets = data.get("sockets")
    if not isinstance(sockets, list):
        return data

    minute = _minutes_now()

    for index, socket in enumerate(sockets):
        if not isinstance(socket, dict) or socket.get("mode") != "schedule":
            continue

        entry = server._db.get(f"/socket/{index}/config/schedule", {})
        schedule = entry.get("data")
        if not isinstance(schedule, dict):
            continue

        on = _is_within(schedule.get("intervals"), minute)
        socket["state"] = "on" if on else "standby"

    return data
