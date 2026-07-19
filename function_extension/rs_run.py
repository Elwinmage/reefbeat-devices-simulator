"""ReefRun modifier: sync pump intensity between /pump/settings and /dashboard.

Keeps the dashboard intensity, the schedule ``ti`` value in /pump/settings,
and the dashboard ``schedule_enabled`` flag all in sync.

Toggle OFF  → save ti, set dashboard intensity=0 & schedule_enabled=false
Toggle ON   → restore ti into both dashboard intensity AND schedule segment
Normal      → dashboard intensity follows the active schedule ti
"""

import datetime
from typing import Any, Dict

# Per-pump store for the last known schedule intensity before disable.
# Keyed by (server-name, pump_key) so multiple RUN instances don't collide.
_saved_intensity: Dict[tuple, int] = {}


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
    path: str, data: Dict[str, Any], params: Any, ctx: Any
) -> Dict[str, Any]:
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
