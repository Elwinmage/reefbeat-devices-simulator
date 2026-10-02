"""ReefLED lamps (G1 and G2): their week of programs and the light they give.

What the ReefBeat app, the Home Assistant integration and the reef card do
with a lamp, besides the generic fixture machinery:

- the week of programs, one per ISO weekday (1 = Monday), each on the
  lamp's weekly timeline (day N starts at (N - 1) * 1440 min), written in
  the app's order: ``POST /preset_name/<day>`` ``{"name"}``, the clouds,
  ``POST /auto/<day>``, then ``POST /auto/apply``;

  - a G1 program is ``{white, blue, moon}``, each channel
    ``{rise, set, points: [{t, i}]}`` (``t`` from the rise);
  - a G2 program is ``{color, moon}``, ``color`` holding
    ``points: [{t, i1, k1, i2, k2}]`` (the intensity and colour
    temperature reached at ``t``, then left from), and its clouds inside
    the program;
  - a program replaces the day's one as a whole (a G2 program written over
    a G1-shaped fixture keeps none of its white/blue channels);

- the clouds of a day: ``POST /clouds/<day>``
  ``{from, to, intensity, cloud_duration, no_cloud_duration}``, removed by
  ``DELETE /clouds/<day>`` (then read back as ``{}``); a G2 also takes them
  from its program;
- the name of a day's program: kept per day (``/preset_name/<day>``) or in
  the list ``/preset_name``, whichever the firmware fixture exposes (a lamp
  without the per-day endpoints still takes the write, as the app sends it
  to every lamp);
- the light: in ``auto`` mode ``/manual`` and ``/dashboard`` report the
  levels today's program gives now (yesterday's one when it runs past
  midnight), dimmed while a cloud passes and during an acclimation; in
  ``manual`` or ``timer`` mode, the levels last written to ``/manual`` or
  ``/timer``; nothing once ``off``;
- ``/mode``: written and mirrored on ``/dashboard``; ``POST /identify``;
- the acclimation (``POST /acclimation`` ``{enabled, duration,
  start_intensity_factor}``): once enabled the light starts at
  ``start_intensity_factor`` % and goes back to 100 % over ``duration``
  days, in equal daily steps; ``started_on``, ``remaining_days`` and
  ``current_intensity_factor`` follow, and it turns itself off when done
  (``started_on`` back to ``"never"``);
- the moon phase (``POST /moonphase`` ``{enabled}`` and/or
  ``{"moon_day": <1-28>}``): a cycle of 28 days, new moon on day 1, full
  moon on day 14; ``todays_moon_day`` moves on by one each day from the
  day last set, ``intensity`` is the share of the full moon (0 on day 28,
  100 on day 14), with ``name``, ``next_full_moon`` and ``next_new_moon``;
  while enabled, the moon channel of the programs is dimmed to that share;
  both are mirrored on ``/dashboard``;
- the staggered sunrise offset of a grouped lamp: ``GET /offset``
  ``{"offset": <minutes>}``, ``POST /offset`` ``{"offset"}`` replaces it
  (``{"success": true, "message": "Offset saved"}``, as captured on a lamp),
  ``DELETE /offset`` sets it back to 0; the lamp then runs its programs that
  many minutes late.

Simulator-only endpoint, shared with the other devices:

- ``GET|PUT /sim/clock``: ``{"minute": <0-1439>}`` pins the clock of every
  simulated device; ``{"minute": null}`` goes back to the real time. On a
  lamp, ``{"days": <n>}`` also moves the lamps' calendar ``n`` days ahead
  (to watch an acclimation or the moon go by); ``{"days": 0}`` goes back
  to today.
"""

from __future__ import annotations

import copy
import re
from datetime import datetime, timedelta
from typing import Any, Optional, Tuple

from . import probe_rules, registry

Response = Tuple[int, Any]

MINUTES_PER_DAY = 24 * 60
MINUTES_PER_WEEK = 7 * MINUTES_PER_DAY

# Share of the light left while a cloud passes, by cloud intensity
CLOUD_DIMMING: dict[str, float] = {"Low": 0.75, "Medium": 0.55, "High": 0.35}

# Colour temperature range of a G2, and the default one
KELVIN_MIN = 9000
KELVIN_MAX = 23000
DEFAULT_KELVIN = 15000

# PWM resolution of the channels (12 bits)
PWM_MAX = 4095

_OK = {"success": True}

_DAY_PATH = re.compile(r"^/(auto|clouds|preset_name)/([1-7])$")


# --------------------------------------------------------------------------
# Recognition and state access
# --------------------------------------------------------------------------
def led_type(server: Any) -> str:
    """ "RSLED_G1", "RSLED_G2", or "" for another device."""
    return str(getattr(getattr(server, "actions", None), "type", "") or "")


def is_led(server: Any) -> bool:
    """Whether the device is a ReefLED."""
    return led_type(server) in ("RSLED_G1", "RSLED_G2")


def is_g2(server: Any) -> bool:
    """Whether the device is a ReefLED G2 (color/moon programs)."""
    return led_type(server) == "RSLED_G2"


def _get(server: Any, path: str) -> Any:
    entry = server._db.get(path)
    return None if entry is None else entry.get("data")


def _set(server: Any, path: str, data: Any, rights: Optional[list] = None) -> None:
    """Replace the data of an endpoint (created readable when missing)."""
    entry = server._db.setdefault(path, {"access": {"rights": rights or ["GET"]}})
    entry.setdefault("access", {"rights": rights or ["GET"]})
    entry["data"] = data


def _merge(server: Any, path: str, data: Any) -> None:
    """Merge a partial write into an endpoint, when it exists."""
    current = _get(server, path)
    if isinstance(current, dict) and isinstance(data, dict):
        _set(server, path, {**current, **data})


def _dashboard_merge(server: Any, key: str, value: Any) -> None:
    """Mirror a setting on the dashboard (a RSLED90 has none)."""
    dash = _get(server, "/dashboard")
    if not isinstance(dash, dict):
        return
    current = dash.get(key)
    if isinstance(current, dict) and isinstance(value, dict):
        value = {**current, **value}
    _set(server, "/dashboard", {**dash, key: value})


# --------------------------------------------------------------------------
# Clock
# --------------------------------------------------------------------------
# Days the lamps' calendar is moved ahead (``/sim/clock`` ``days``)
_CALENDAR: dict[str, int] = {"days": 0}


def set_days(days: int) -> None:
    """Move the lamps' calendar ``days`` ahead of the real one (0: today)."""
    _CALENDAR["days"] = int(days)


def moment() -> datetime:
    """Date and time of the lamps' calendar."""
    return datetime.now() + timedelta(days=_CALENDAR["days"])


def today() -> int:
    """Day of the lamps' calendar (proleptic ordinal)."""
    return moment().toordinal()


def now() -> Tuple[int, int]:
    """ISO weekday and minute of the day of the lamps' clock.

    The minute follows the virtual clock shared with the other devices when
    one is pinned (``/sim/clock``), the local time otherwise.
    """
    return moment().isoweekday(), probe_rules.minutes_now()


def week_minute(weekday: int, minute: int) -> int:
    """Minute of the lamp's weekly timeline."""
    return (weekday - 1) * MINUTES_PER_DAY + minute


# --------------------------------------------------------------------------
# Programs
# --------------------------------------------------------------------------
def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _in_window(channel: Any, minute: float) -> Optional[float]:
    """Minutes since the rise of a channel, None outside its window.

    The week wraps: a Sunday running past midnight goes on on Monday.
    """
    if not isinstance(channel, dict):
        return None
    rise = _num(channel.get("rise"))
    set_ = _num(channel.get("set"))
    for m in (minute, minute + MINUTES_PER_WEEK):
        if rise <= m <= set_:
            return m - rise
    return None


def _interpolate(points: list, t: float) -> float:
    """Value at ``t`` of a line through ``(t, value)`` points."""
    if not points:
        return 0.0
    if t <= points[0][0]:
        return points[0][1]
    for (t0, v0), (t1, v1) in zip(points, points[1:]):
        if t0 <= t <= t1:
            return v0 if t1 == t0 else v0 + (v1 - v0) * (t - t0) / (t1 - t0)
    return points[-1][1]


def channel_level(channel: Any, minute: float) -> float:
    """Level (%) of a G1 channel ``{rise, set, points: [{t, i}]}``.

    The light goes from 0 at the rise through the points to 0 at the set.
    """
    t = _in_window(channel, minute)
    if t is None:
        return 0.0
    span = _num(channel.get("set")) - _num(channel.get("rise"))
    points = [(0.0, 0.0)]
    for p in channel.get("points") or []:
        if isinstance(p, dict):
            points.append((_num(p.get("t")), _num(p.get("i"))))
    points.append((span, 0.0))
    points.sort(key=lambda p: p[0])
    return _interpolate(points, t)


def color_level(color: Any, minute: float) -> Tuple[float, int]:
    """Intensity (%) and colour temperature of a G2 ``color`` channel.

    Each point is reached at ``(i1, k1)`` and left from ``(i2, k2)``; the
    intensity rises from 0 and falls back to 0 at the set, the colour
    temperature holds before the first point and after the last one.
    """
    t = _in_window(color, minute)
    raw = [p for p in (color or {}).get("points") or [] if isinstance(p, dict)]
    raw.sort(key=lambda p: _num(p.get("t")))
    if t is None or not raw:
        kelvin = int(_num(raw[0].get("k1"), DEFAULT_KELVIN)) if raw else DEFAULT_KELVIN
        return 0.0, kelvin
    span = _num(color.get("set")) - _num(color.get("rise"))
    intensity: list = [(0.0, 0.0)]
    temperatures: list = []
    for p in raw:
        pt = _num(p.get("t"))
        i1 = _num(p.get("i1", p.get("i")))
        k1 = _num(p.get("k1", p.get("k")), DEFAULT_KELVIN)
        intensity += [(pt, i1), (pt, _num(p.get("i2"), i1))]
        temperatures += [(pt, k1), (pt, _num(p.get("k2"), k1))]
    intensity.append((span, 0.0))
    return _interpolate(intensity, t), int(round(_interpolate(temperatures, t)))


def white_blue_of(kelvin: float, intensity: float) -> Tuple[float, float]:
    """Rough white and blue levels of a G2 at a colour temperature.

    Blue leads over the whole range; white fades out towards the coldest
    temperature. Only meant for the read-only white/blue sensors.
    """
    k = max(KELVIN_MIN, min(KELVIN_MAX, kelvin))
    white_share = (KELVIN_MAX - k) / (KELVIN_MAX - KELVIN_MIN)
    blue_share = 0.6 + 0.4 * (1 - white_share)
    return intensity * white_share, intensity * blue_share


def clouds_factor(clouds: Any, minute: float) -> float:
    """Share of the light left by the clouds at a minute of the week.

    Inside the clouds' window, a cloud passes for ``cloud_duration``
    minutes, then the sky clears for ``no_cloud_duration`` minutes.
    """
    if not isinstance(clouds, dict) or "from" not in clouds or "to" not in clouds:
        return 1.0
    start = _num(clouds.get("from"))
    end = _num(clouds.get("to"))
    for m in (minute, minute + MINUTES_PER_WEEK):
        if start <= m < end:
            cloud = max(1.0, _num(clouds.get("cloud_duration"), 4))
            clear = max(0.0, _num(clouds.get("no_cloud_duration"), 6))
            if (m - start) % (cloud + clear) < cloud:
                return CLOUD_DIMMING.get(str(clouds.get("intensity")), 0.55)
    return 1.0


def program_levels(server: Any, weekday: int, minute: int) -> dict[str, float]:
    """Levels the week of programs gives at a moment.

    Today's program, and yesterday's one for what runs past midnight: the
    brighter of both wins on each channel.
    """
    levels: dict[str, float] = {
        "white": 0.0,
        "blue": 0.0,
        "moon": 0.0,
        "intensity": 0.0,
        "kelvin": float(DEFAULT_KELVIN),
    }
    at = week_minute(weekday, minute)
    kelvin_set = False
    for day in (weekday, (weekday - 2) % 7 + 1):
        program = _get(server, "/auto/%d" % day)
        if not isinstance(program, dict):
            continue
        clouds = _get(server, "/clouds/%d" % day)
        if is_g2(server) and isinstance(program.get("clouds"), dict):
            clouds = program["clouds"]
        factor = clouds_factor(clouds, at)
        if "color" in program:
            intensity, kelvin = color_level(program["color"], at)
            intensity *= factor
            if intensity > levels["intensity"] or (day == weekday and not kelvin_set):
                levels["kelvin"] = float(kelvin)
                kelvin_set = True
            levels["intensity"] = max(levels["intensity"], intensity)
        else:
            for key in ("white", "blue"):
                levels[key] = max(
                    levels[key], channel_level(program.get(key), at) * factor
                )
        levels["moon"] = max(levels["moon"], channel_level(program.get("moon"), at))
    if is_g2(server):
        levels["white"], levels["blue"] = white_blue_of(
            levels["kelvin"], levels["intensity"]
        )
    else:
        levels["intensity"] = max(levels["white"], levels["blue"])
    return levels


def offset(server: Any) -> int:
    """Minutes the lamp runs its programs late (staggered sunrise)."""
    data = _get(server, "/offset")
    return int(_num(data.get("offset"))) if isinstance(data, dict) else 0


def shifted(weekday: int, minute: int, late: int) -> Tuple[int, int]:
    """Moment of the week ``late`` minutes before (weekday, minute)."""
    at = (week_minute(weekday, minute) - late) % MINUTES_PER_WEEK
    return at // MINUTES_PER_DAY + 1, at % MINUTES_PER_DAY


def _write_offset(server: Any, body: Any) -> Response:
    value = body.get("offset") if isinstance(body, dict) else None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return 400, {"success": False, "message": "offset expected"}
    _set(server, "/offset", {"offset": int(value)}, ["GET", "POST", "DELETE"])
    return 200, {"success": True, "message": "Offset saved"}


# --------------------------------------------------------------------------
# Acclimation
# --------------------------------------------------------------------------
NEVER = "never"


def _day_of(epoch: Any) -> Optional[int]:
    """Day (ordinal) of a ``started_on`` timestamp, None for "never"."""
    if isinstance(epoch, bool) or not isinstance(epoch, (int, float)):
        return None
    return datetime.fromtimestamp(epoch).toordinal()


def acclimation_state(acc: dict[str, Any], day: int) -> dict[str, Any]:
    """An acclimation as the lamp reports it on a day.

    From ``start_intensity_factor`` % on the day it started to 100 % after
    ``duration`` days, in equal daily steps; over, it turns itself off.
    """
    duration = max(1, int(_num(acc.get("duration"), 1)))
    start = max(0.0, min(100.0, _num(acc.get("start_intensity_factor"), 100)))
    started = _day_of(acc.get("started_on"))
    elapsed = 0 if started is None else max(0, day - started)
    if not acc.get("enabled") or started is None or elapsed >= duration:
        return {
            **acc,
            "enabled": False,
            "started_on": NEVER,
            "remaining_days": 0,
            "current_intensity_factor": 100,
        }
    return {
        **acc,
        "remaining_days": duration - elapsed,
        "current_intensity_factor": int(
            round(start + (100 - start) * elapsed / duration)
        ),
    }


def refresh_acclimation(server: Any) -> None:
    """Bring ``/acclimation`` (and the dashboard) to today."""
    acc = _get(server, "/acclimation")
    if isinstance(acc, dict):
        state = acclimation_state(acc, today())
        _set(server, "/acclimation", state)
        _dashboard_merge(server, "acclimation", state)


def acclimation_factor(server: Any) -> float:
    """Share of the light an acclimation in progress lets through."""
    acc = _get(server, "/acclimation")
    if not isinstance(acc, dict) or not acc.get("enabled"):
        return 1.0
    return max(0.0, min(100.0, _num(acc.get("current_intensity_factor"), 100))) / 100


def _write_acclimation(server: Any, body: Any) -> Response:
    """``{enabled, duration, start_intensity_factor}``, each optional."""
    if not isinstance(body, dict):
        return 400, {"success": False, "message": "settings expected"}
    enabled = body.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        return 400, {"success": False, "message": "enabled: boolean expected"}
    for key, low, high in (("duration", 1, 365), ("start_intensity_factor", 0, 100)):
        value = body.get(key)
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not low <= value <= high
        ):
            return 400, {"success": False, "message": "%s: %d-%d" % (key, low, high)}
    current = _get(server, "/acclimation")
    current = dict(current) if isinstance(current, dict) else {}
    was_running = bool(current.get("enabled"))
    for key in ("enabled", "duration", "start_intensity_factor"):
        if body.get(key) is not None:
            current[key] = body[key]
    # Starting (not a setting changed while it runs): from today
    if current.get("enabled") and not was_running:
        current["started_on"] = int(moment().timestamp())
    _set(server, "/acclimation", current, ["GET", "POST"])
    refresh_acclimation(server)
    return 200, dict(_OK)


# --------------------------------------------------------------------------
# Moon phase
# --------------------------------------------------------------------------
MOON_CYCLE = 28
NEW_MOON_DAY = 1
FULL_MOON_DAY = 14

# Name of the phase, by the last day it covers
MOON_NAMES = (
    (1, "New Moon"),
    (6, "Waxing Crescent"),
    (7, "First Quarter"),
    (13, "Waxing Gibbous"),
    (14, "Full Moon"),
    (20, "Waning Gibbous"),
    (21, "Last Quarter"),
    (28, "Waning Crescent"),
)


def moon_intensity(moon_day: int) -> int:
    """Share (%) of the full moon on a day of the cycle: 100 on day 14,
    0 on day 28, as the lamps report it (14 on day 2)."""
    if moon_day <= FULL_MOON_DAY:
        return int(round(100 * moon_day / FULL_MOON_DAY))
    return int(round(100 * (MOON_CYCLE - moon_day) / (MOON_CYCLE - FULL_MOON_DAY)))


def moon_name(moon_day: int) -> str:
    """Name of the phase on a day of the cycle."""
    return next(name for last, name in MOON_NAMES if moon_day <= last)


def _moon_anchor(server: Any, moon: dict[str, Any]) -> Tuple[int, int]:
    """(day, moon day that day): where the lamp's cycle is counted from.

    A lamp starts from the moon day of its fixture, taken as today's.
    """
    anchor = getattr(server, "_moon_anchor", None)
    if anchor is None:
        first = int(_num(moon.get("todays_moon_day"), NEW_MOON_DAY))
        anchor = (today(), min(MOON_CYCLE, max(1, first)))
        server._moon_anchor = anchor
    return anchor


def moon_state(moon: dict[str, Any], anchor: Tuple[int, int], day: int) -> dict:
    """The moon phase as the lamp reports it on a day."""
    moon_day = (anchor[1] - 1 + day - anchor[0]) % MOON_CYCLE + 1
    return {
        **moon,
        "todays_moon_day": moon_day,
        "intensity": moon_intensity(moon_day),
        "name": moon_name(moon_day),
        "next_full_moon": (FULL_MOON_DAY - moon_day) % MOON_CYCLE,
        "next_new_moon": (NEW_MOON_DAY - moon_day) % MOON_CYCLE,
    }


def refresh_moon(server: Any) -> None:
    """Bring ``/moonphase`` (and the dashboard) to today."""
    moon = _get(server, "/moonphase")
    if isinstance(moon, dict):
        state = moon_state(moon, _moon_anchor(server, moon), today())
        _set(server, "/moonphase", state)
        _dashboard_merge(server, "moon_phase", state)


def moon_factor(server: Any) -> float:
    """Share of the programs' moon light the moon phase lets through."""
    moon = _get(server, "/moonphase")
    if not isinstance(moon, dict) or not moon.get("enabled"):
        return 1.0
    return max(0.0, min(100.0, _num(moon.get("intensity"), 100))) / 100


def _write_moon(server: Any, body: Any) -> Response:
    """``{enabled}`` and/or ``{moon_day}`` (today's day of the cycle)."""
    if not isinstance(body, dict):
        return 400, {"success": False, "message": "settings expected"}
    enabled = body.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        return 400, {"success": False, "message": "enabled: boolean expected"}
    moon_day = body.get("moon_day")
    if moon_day is not None and (
        isinstance(moon_day, bool)
        or not isinstance(moon_day, int)
        or not 1 <= moon_day <= MOON_CYCLE
    ):
        return 400, {"success": False, "message": "moon_day: 1-%d" % MOON_CYCLE}
    current = _get(server, "/moonphase")
    current = dict(current) if isinstance(current, dict) else {}
    _moon_anchor(server, current)
    restart = moon_day is not None
    if moon_day is not None:
        server._moon_anchor = (today(), moon_day)
    if enabled is not None:
        restart = restart or (enabled and not current.get("enabled"))
        current["enabled"] = enabled
    if restart:
        current["started_on"] = int(moment().timestamp())
    _set(server, "/moonphase", current, ["GET", "POST"])
    refresh_moon(server)
    return 200, dict(_OK)


def mode(server: Any) -> str:
    """Mode of the lamp: auto, manual, timer or off."""
    data = _get(server, "/mode")
    return str(data.get("mode", "auto")) if isinstance(data, dict) else "auto"


# --------------------------------------------------------------------------
# Light currently produced
# --------------------------------------------------------------------------
def _channel_fields(manual: dict[str, Any], key: str, value: float) -> None:
    """Level of a channel, with the fields the firmware reports beside it."""
    value = max(0.0, min(100.0, value))
    manual[key] = int(round(value))
    if key + "_full" in manual:
        manual[key + "_full"] = round(value, 2)
    if key + "_pwm" in manual:
        manual[key + "_pwm"] = int(round(value * PWM_MAX / 100))


def refresh_light(server: Any) -> None:
    """Bring ``/manual`` and the dashboard's ``manual`` to the lamp's light.

    In auto mode: what the program gives now. Off: nothing. Manual or
    timer: the levels last written, left as they are.
    """
    manual = _get(server, "/manual")
    if not isinstance(manual, dict):
        return
    current = mode(server)
    if current in ("manual", "timer"):
        return
    manual = dict(manual)
    if current == "off":
        levels = {"white": 0.0, "blue": 0.0, "moon": 0.0, "intensity": 0.0}
    else:
        weekday, minute = shifted(*now(), offset(server))
        levels = program_levels(server, weekday, minute)
        refresh_acclimation(server)
        refresh_moon(server)
        factor = acclimation_factor(server)
        for key in ("white", "blue", "intensity"):
            levels[key] *= factor
        levels["moon"] *= moon_factor(server)
        if "kelvin" in manual:
            manual["kelvin"] = int(levels["kelvin"])
    for key in ("white", "blue", "moon"):
        _channel_fields(manual, key, levels[key])
    if "intensity" in manual:
        manual["intensity"] = int(round(levels["intensity"]))
    _set(server, "/manual", manual)
    _dashboard_merge(server, "manual", manual)


def refresh_program_name(server: Any) -> None:
    """Name of today's program on the dashboard's ``current_program``."""
    dash = _get(server, "/dashboard")
    if not isinstance(dash, dict):
        return
    weekday, _minute = now()
    name = preset_name(server, weekday)
    if name is None:
        return
    current = dash.get("current_program")
    current = dict(current) if isinstance(current, dict) else {}
    current["name"] = name
    _set(server, "/dashboard", {**dash, "current_program": current})


# --------------------------------------------------------------------------
# Names
# --------------------------------------------------------------------------
def preset_name(server: Any, weekday: int) -> Optional[str]:
    """Name of a weekday's program, from whichever endpoint the lamp has."""
    single = _get(server, "/preset_name/%d" % weekday)
    if isinstance(single, dict) and "name" in single:
        return str(single["name"])
    listed = _get(server, "/preset_name")
    if isinstance(listed, list):
        for entry in listed:
            if isinstance(entry, dict) and entry.get("day") == weekday:
                return str(entry.get("name", ""))
    return None


def set_preset_name(server: Any, weekday: int, name: str) -> None:
    """Rename a weekday's program, on every endpoint the lamp has."""
    if isinstance(_get(server, "/preset_name/%d" % weekday), dict):
        _set(server, "/preset_name/%d" % weekday, {"name": name})
    listed = _get(server, "/preset_name")
    if isinstance(listed, list):
        entries = [dict(e) for e in listed if isinstance(e, dict)]
        for entry in entries:
            if entry.get("day") == weekday:
                entry["name"] = name
                break
        else:
            entries.append({"day": weekday, "name": name})
            entries.sort(key=lambda e: e.get("day", 0))
        _set(server, "/preset_name", entries)


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------
# The firmware's answer to clouds outside the day of the program
OUTSIDE_PRESET = (
    500,
    {
        "success": False,
        "message": "json structure is wrong.Cloud period is outside the "
        "preset [rise:set] interval",
    },
)


def light_window(program: Any) -> Optional[Tuple[float, float]]:
    """First rise and last set of a program's light (moon left out)."""
    if not isinstance(program, dict):
        return None
    channels = [
        program[key]
        for key in ("white", "blue", "color")
        if isinstance(program.get(key), dict)
    ]
    if not channels:
        return None
    return (
        min(_num(ch.get("rise")) for ch in channels),
        max(_num(ch.get("set")) for ch in channels),
    )


def clouds_fit(clouds: Any, program: Any) -> bool:
    """Whether clouds (if any) stay inside the day of a program, as the
    firmware requires of every clouds/program pair it holds."""
    if not isinstance(clouds, dict) or "from" not in clouds or "to" not in clouds:
        return True
    window = light_window(program)
    if window is None:
        return True
    return window[0] <= _num(clouds["from"]) and _num(clouds["to"]) <= window[1]


def _write_program(server: Any, weekday: int, body: Any) -> Response:
    if not isinstance(body, dict):
        return 400, {"success": False, "message": "program expected"}
    program = copy.deepcopy(body)
    if is_g2(server):
        # A G2 carries its clouds in its program; they are read back on
        # /clouds/<day> too
        clouds = program.get("clouds")
        if not clouds_fit(clouds, program):
            return OUTSIDE_PRESET
        if isinstance(clouds, dict) and "from" in clouds:
            full = {"cloud_duration": 4, "no_cloud_duration": 6, **clouds}
            _set(server, "/clouds/%d" % weekday, full)
        else:
            program.pop("clouds", None)
            _set(server, "/clouds/%d" % weekday, {})
    elif not clouds_fit(_get(server, "/clouds/%d" % weekday), program):
        # The clouds the lamp holds must stay inside the new day
        return OUTSIDE_PRESET
    _set(server, "/auto/%d" % weekday, program)
    return 200, dict(_OK)


def _write_clouds(server: Any, weekday: int, body: Any) -> Response:
    if not isinstance(body, dict):
        return 400, {"success": False, "message": "clouds expected"}
    # Checked against the program the lamp holds
    if not clouds_fit(body, _get(server, "/auto/%d" % weekday)):
        return OUTSIDE_PRESET
    _set(server, "/clouds/%d" % weekday, dict(body))
    return 200, dict(_OK)


def _clear_clouds(server: Any, weekday: int) -> Response:
    _set(server, "/clouds/%d" % weekday, {})
    if is_g2(server):
        program = _get(server, "/auto/%d" % weekday)
        if isinstance(program, dict) and "clouds" in program:
            _set(
                server,
                "/auto/%d" % weekday,
                {k: v for k, v in program.items() if k != "clouds"},
            )
    return 200, {"success": True, "message": "clouds deleted"}


def _write_manual(server: Any, body: Any, new_mode: str) -> Response:
    """Levels written by hand: the lamp leaves its program."""
    if not isinstance(body, dict):
        return 400, {"success": False, "message": "levels expected"}
    manual = dict(_get(server, "/manual") or {})
    if "kelvin" in body or "intensity" in body:
        kelvin = _num(body.get("kelvin"), _num(manual.get("kelvin"), DEFAULT_KELVIN))
        intensity = _num(body.get("intensity"), _num(manual.get("intensity")))
        white, blue = white_blue_of(kelvin, intensity)
        manual["kelvin"] = int(kelvin)
        manual["intensity"] = int(round(intensity))
        _channel_fields(manual, "white", white)
        _channel_fields(manual, "blue", blue)
    for key in ("white", "blue", "moon"):
        if key in body:
            _channel_fields(manual, key, _num(body[key]))
    _set(server, "/manual", manual)
    _dashboard_merge(server, "manual", manual)
    _set_mode(server, new_mode)
    if new_mode == "timer":
        _set(
            server,
            "/timer",
            {"timer_status": "timer enabled", "duration": body.get("duration", 0)},
        )
    return 200, dict(_OK)


def _set_mode(server: Any, value: str) -> None:
    _merge(server, "/mode", {"mode": value})
    if _get(server, "/mode") is None:
        _set(server, "/mode", {"mode": value})
    dash = _get(server, "/dashboard")
    if isinstance(dash, dict) and "mode" in dash:
        _set(server, "/dashboard", {**dash, "mode": value})


def _handle_post(server: Any, path: str, body: Any) -> Optional[Response]:
    day = _DAY_PATH.match(path)
    if day:
        kind, weekday = day.group(1), int(day.group(2))
        if kind == "auto":
            return _write_program(server, weekday, body)
        if kind == "clouds":
            return _write_clouds(server, weekday, body)
        name = body.get("name") if isinstance(body, dict) else None
        if not isinstance(name, str):
            return 400, {"success": False, "message": "name expected"}
        set_preset_name(server, weekday, name)
        return 200, dict(_OK)
    if path == "/auto/apply":
        _set_mode(server, "auto")
        refresh_program_name(server)
        return 200, {"success": True, "message": "auto program applied"}
    if path == "/manual":
        return _write_manual(server, body, "manual")
    if path == "/timer":
        return _write_manual(server, body, "timer")
    if path == "/mode":
        value = body.get("mode") if isinstance(body, dict) else None
        if not isinstance(value, str):
            return 400, {"success": False, "message": "mode expected"}
        _set_mode(server, value)
        return 200, dict(_OK)
    if path == "/acclimation":
        return _write_acclimation(server, body)
    if path == "/moonphase":
        return _write_moon(server, body)
    if path == "/identify":
        return 200, {"success": True, "message": "identify started"}
    if path == "/offset":
        return _write_offset(server, body)
    return None


def _sim_clock() -> dict[str, Any]:
    return {"minute": probe_rules.clock(), "days": _CALENDAR["days"]}


def _handle_get(server: Any, path: str) -> Optional[Response]:
    if path == "/sim/clock":
        return 200, _sim_clock()
    if path == "/offset":
        return 200, {"offset": offset(server)}
    # The acclimation and the moon move on with the days
    if path in ("/acclimation", "/moonphase", "/dashboard"):
        refresh_acclimation(server)
        refresh_moon(server)
    # The light follows the program: brought up to date when read, then
    # served by the generic machinery
    if path in ("/manual", "/dashboard"):
        refresh_light(server)
        if path == "/dashboard":
            refresh_program_name(server)
    return None


def handle(server: Any, method: str, raw_path: str, body: Any) -> Optional[Response]:
    """Handle a ReefLED request.

    Returns ``(status, json_value)`` when this module owns the request, else
    ``None`` so the caller falls back to the generic machinery.
    """
    if not is_led(server):
        return None
    path = raw_path.split("?")[0]
    with registry.LOCK:
        if method == "GET":
            return _handle_get(server, path)
        if method == "PUT" and path == "/sim/clock":
            body = body if isinstance(body, dict) else {}
            # "days" alone leaves the minute as it is
            if "minute" in body or "days" not in body:
                minute = body.get("minute")
                probe_rules.set_clock(None if minute is None else int(minute))
            if "days" in body:
                set_days(int(_num(body.get("days"))))
            return 200, _sim_clock()
        if method in ("POST", "PUT"):
            return _handle_post(server, path, body)
        if method == "DELETE":
            if path == "/offset":
                _set(server, "/offset", {"offset": 0}, ["GET", "POST", "DELETE"])
                return 200, dict(_OK)
            day = _DAY_PATH.match(path)
            if day and day.group(1) == "clouds":
                return _clear_clouds(server, int(day.group(2)))
    return None
