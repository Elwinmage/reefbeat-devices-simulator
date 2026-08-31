"""ReefRun modifier: sync pump intensity between /pump/settings and /dashboard.

Keeps the dashboard intensity, the schedule ``ti`` value in /pump/settings,
and the dashboard ``schedule_enabled`` flag all in sync.

Toggle OFF  → save ti, set dashboard intensity=0 & schedule_enabled=false
Toggle ON   → restore ti into both dashboard intensity AND schedule segment
Normal      → dashboard intensity follows the active schedule ti
"""

import datetime
import random
from typing import Any

# Per-pump store for the last known schedule intensity before disable.
# Keyed by (server-name, pump_key) so multiple RUN instances don't collide.
_saved_intensity: dict[tuple, int] = {}

# Plausible body temperature range (°C) reported by a running ReefRun pump.
_TEMP_MIN = 38.0
_TEMP_MAX = 45.0
# Maximum drift applied between two consecutive /dashboard reads.
_TEMP_STEP = 0.2

# Per-pump temperature state: key -> [current_value, low_bound, high_bound].
# Keyed by (server-name, pump_key), like _saved_intensity.
_temperature: dict[tuple, list[float]] = {}


def _find_active_segment(schedule: list, now_minutes: int) -> dict:
    """Return the active schedule segment for the given time of day."""
    cur = schedule[0]
    for seg in schedule[1:]:
        if int(seg.get("st", 0)) <= now_minutes:
            cur = seg
        else:
            break
    return cur


def sync_pump_intensity(
    path: str, data: dict[str, Any], params: Any, ctx: Any
) -> dict[str, Any]:
    """Sync schedule intensity between /pump/settings and /dashboard.

    Behaviour:
    - schedule_enabled=true (normal)
        dashboard.intensity  = active segment ti
        dashboard.schedule_enabled = true
    - schedule_enabled toggled OFF
        save current ti, set dashboard.intensity = 0,
        dashboard.schedule_enabled = false
    - schedule_enabled toggled ON (restore)
        restore saved ti into dashboard.intensity AND into
        the active segment ti in /pump/settings,
        dashboard.schedule_enabled = true

    Expects ctx.server to hold a reference to the MyServer instance.
    """
    server = getattr(ctx, "server", None)
    if server is None:
        return data

    # Read settings directly from the DB to avoid recursive get_data calls
    settings_entry = server._db.get("/pump/settings", {})
    settings = settings_entry.get("data")
    if not isinstance(settings, dict):
        return data

    now = datetime.datetime.now()
    now_minutes = now.hour * 60 + now.minute

    server_name = getattr(server.config, "name", "")

    for pump_key in ("pump_1", "pump_2"):
        pump_cfg = settings.get(pump_key, {})
        if not isinstance(pump_cfg, dict):
            continue

        schedule_enabled = pump_cfg.get("schedule_enabled", True)
        schedule = pump_cfg.get("schedule")
        if not isinstance(schedule, list) or not schedule:
            continue

        # Locate the active schedule segment (mutable ref into settings)
        active_seg = _find_active_segment(schedule, now_minutes)
        schedule_ti = active_seg.get("ti", 0)

        save_key = (server_name, pump_key)

        if pump_key not in data or not isinstance(data[pump_key], dict):
            continue

        # If the pump is physically disconnected (missing_pump=true), leave
        # the state produced by the disconnect modifiers alone. Running the
        # normal sync logic would otherwise restore intensity to the
        # schedule's ti and undo the "no pump" simulation.
        if data[pump_key].get("missing_pump"):
            continue

        if schedule_enabled:
            if save_key in _saved_intensity:
                # Just re-enabled: restore saved intensity everywhere
                restored = _saved_intensity.pop(save_key)
                data[pump_key]["intensity"] = restored
                # Write back into the active schedule segment in /pump/settings
                active_seg["ti"] = restored
            else:
                # Normal operation: dashboard follows schedule ti
                data[pump_key]["intensity"] = schedule_ti
            data[pump_key]["schedule_enabled"] = True
        else:
            # Schedule disabled: save ti, zero dashboard
            if save_key not in _saved_intensity:
                _saved_intensity[save_key] = schedule_ti
            data[pump_key]["intensity"] = 0
            data[pump_key]["schedule_enabled"] = False

    return data


def _pump_is_present(pump: dict[str, Any]) -> bool:
    """Return True when the dashboard entry describes a connected pump."""
    if pump.get("missing_pump"):
        return False
    return str(pump.get("type", "unknown")).strip().lower() not in ("", "unknown")


def simulate_pump_temperature(
    path: str, data: dict[str, Any], params: Any, ctx: Any
) -> dict[str, Any]:
    """Keep a plausible ``temperature`` on /dashboard for each pump.

    Real hardware never reports 0 °C for a connected pump, but the simulator
    does after a ``DELETE /pump/{n}/settings`` followed by a re-adoption
    (``PUT /pump/settings``): the delete side-effect resets the dashboard
    entry to 0 and nothing ever brings it back.

    Behaviour:
    - pump absent (``type`` unknown/empty) or disconnected (``missing_pump``)
        temperature forced to 0, stored state dropped
    - pump present with an implausible temperature (0, missing, non numeric)
        seed a random value in the [min, max] range (38-45 °C by default)
    - pump present with an existing plausible value (fixture data)
        keep that value as the starting point and widen the drift band so the
        original fixture reading is preserved

    On every subsequent read the value drifts slightly inside its band, which
    gives the card/integration something realistic to display and graph.

    Optional ``params``: ``min``, ``max``, ``step``.
    """
    server = getattr(ctx, "server", None)
    server_name = getattr(getattr(server, "config", None), "name", "")

    t_min = float(getattr(params, "min", _TEMP_MIN))
    t_max = float(getattr(params, "max", _TEMP_MAX))
    step = float(getattr(params, "step", _TEMP_STEP))

    for pump_key in ("pump_1", "pump_2"):
        pump = data.get(pump_key)
        if not isinstance(pump, dict):
            continue

        state_key = (server_name, pump_key)

        if not _pump_is_present(pump):
            # No pump plugged in: the device reports 0 and we forget the state
            # so a later re-adoption seeds a fresh value.
            _temperature.pop(state_key, None)
            pump["temperature"] = 0
            continue

        state = _temperature.get(state_key)
        if state is None:
            current = pump.get("temperature")
            if isinstance(current, (int, float)) and not isinstance(current, bool):
                seed = float(current)
            else:
                seed = 0.0
            if seed <= 0:
                # Freshly added pump: pick a realistic starting temperature
                seed = random.uniform(t_min, t_max)
                low, high = t_min, t_max
            else:
                # Fixture value kept as-is, band widened around it if needed
                low, high = min(t_min, seed), max(t_max, seed)
            state = [seed, low, high]
        else:
            state[0] += random.uniform(-step, step)

        state[0] = min(max(state[0], state[1]), state[2])
        _temperature[state_key] = state
        pump["temperature"] = round(state[0], 2)

    return data
