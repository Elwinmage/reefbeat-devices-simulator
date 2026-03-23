"""ReefRun modifier: sync pump intensity from /pump/settings into /dashboard."""

import datetime
from typing import Any, Dict


def sync_pump_intensity(
    path: str, data: Dict[str, Any], params: Any, ctx: Any
) -> Dict[str, Any]:
    """Copy current schedule intensity from /pump/settings to /dashboard.

    Picks the active schedule segment based on current time of day.
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

    for pump_key in ("pump_1", "pump_2"):
        pump_cfg = settings.get(pump_key, {})
        if not isinstance(pump_cfg, dict):
            continue
        schedule = pump_cfg.get("schedule")
        if not isinstance(schedule, list) or not schedule:
            continue

        # Find the active segment (last one whose start time <= now)
        cur = schedule[0]
        for seg in schedule[1:]:
            if int(seg.get("st", 0)) <= now_minutes:
                cur = seg
            else:
                break

        if pump_key in data and isinstance(data[pump_key], dict):
            data[pump_key]["intensity"] = cur.get("ti", 0)

    return data
