#!/usr/bin/env python3
"""Fake the passing of time on ha-reefbeat maintenance tasks.

Demo helper: every N seconds it decrements the `days_left` attribute of the
given `button.*` maintenance entities, so a recording shows tasks drifting
from "ok" to "warning" to "overdue" in a couple of minutes instead of weeks.

It talks to the Home Assistant REST API and overwrites the state machine
entry directly (POST /api/states/<entity_id>). That is a display-level
override: the integration owns these entities and will restore the real
values on its next refresh, so run this with a long polling interval, or
accept that the countdown resets when the integration polls.

Nothing is written to disk on the HA side; a Ctrl-C (or --duration) restores
the snapshot taken at startup.

Usage:
    export HA_URL=http://homeassistant.local:8123
    export HA_TOKEN=<long-lived access token>

    # from a Home Assistant add-on (Terminal & SSH, AppDaemon, ...) the
    # Supervisor token is picked up automatically, no HA_URL/HA_TOKEN needed

    # list the maintenance tasks the card would show
    ./maint_timelapse.py --list

    # one day every 2 s on two tasks, stop after 60 s and restore
    ./maint_timelapse.py --interval 2 --duration 60 \\
        button.reefled_160_clean_lenses button.reefmat_replace_carbon

    # stagger the starting points so the tasks tip over one after the other
    ./maint_timelapse.py --interval 2 \\
        button.reefled_160_clean_lenses=3 \\
        button.reefmat_replace_carbon=8 \\
        button.reefrun_clean_rotor=15

    # everything from 10 days, except one task staged closer to the edge
    ./maint_timelapse.py --all --start 10 button.reefled_160_clean_lenses=2

    # every maintenance task at once, 3 days per tick, floor at -10
    ./maint_timelapse.py --all --step 3 --floor -10
"""

import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from typing import Any

DEFAULT_URL = "http://homeassistant.local:8123"
# Inside an add-on the Supervisor proxies the core API under this host
SUPERVISOR_URL = "http://supervisor/core"

MAINTENANCE_ROLE_PREFIX = "maint_"
# Same default as MAINTENANCE_WARNING_RATIO in the card
WARNING_RATIO = 0.2


# --------------------------------------------------------------------------- #
#   Home Assistant REST API
# --------------------------------------------------------------------------- #


class HomeAssistant:
    """Minimal REST client, standard library only."""

    def __init__(self, url: str, token: str, timeout: float = 10.0) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: Any = None) -> Any:
        """Send one request and decode the JSON answer.

        :param method: HTTP verb
        :param path: path below /api
        :param payload: body to send, JSON encoded
        :return: the decoded answer, or None when the body is empty
        """
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            f"{self.url}/api{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as answer:
                body = answer.read()
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace")
            raise SystemExit(f"HTTP {err.code} on {method} {path}: {detail}") from err
        except urllib.error.URLError as err:
            raise SystemExit(f"Cannot reach {self.url}: {err.reason}") from err
        return json.loads(body) if body else None

    def states(self) -> list[dict[str, Any]]:
        """Return every state known to Home Assistant."""
        return self._request("GET", "/states")

    def state(self, entity_id: str) -> dict[str, Any]:
        """Return one state object.

        :param entity_id: the entity to read
        """
        return self._request("GET", f"/states/{entity_id}")

    def set_state(self, entity_id: str, state: str, attributes: dict[str, Any]) -> None:
        """Overwrite a state machine entry.

        :param entity_id: the entity to overwrite
        :param state: the state string to publish
        :param attributes: the full attribute set to publish
        """
        self._request(
            "POST",
            f"/states/{entity_id}",
            {"state": state, "attributes": attributes},
        )


# --------------------------------------------------------------------------- #
#   Maintenance helpers
# --------------------------------------------------------------------------- #


def is_maintenance_state(state: dict[str, Any]) -> bool:
    """Tell whether a state looks like a maintenance action button.

    Mirrors is_maintenance_state() in the card: a button carrying a
    `maint_*` reef_role and a non empty task_key.

    :param state: a state object from the API
    :return: True when the card would list it
    """
    entity_id = state.get("entity_id", "")
    if not entity_id.startswith("button."):
        return False
    attributes = state.get("attributes") or {}
    role = attributes.get("reef_role")
    if not isinstance(role, str) or not role.startswith(MAINTENANCE_ROLE_PREFIX):
        return False
    task_key = attributes.get("task_key")
    return isinstance(task_key, str) and bool(task_key)


def status_of(days_left: float | None, interval_days: float) -> str:
    """Derive the status the card would display.

    :param days_left: remaining days, None when never reset
    :param interval_days: the configured interval
    :return: never / overdue / warning / ok
    """
    if days_left is None:
        return "never"
    if days_left < 0:
        return "overdue"
    threshold = max(1, round(interval_days * WARNING_RATIO)) if interval_days > 0 else 0
    return "warning" if days_left <= threshold else "ok"


def current_days_left(attributes: dict[str, Any]) -> int | None:
    """Read `days_left` as an integer.

    :param attributes: the attributes of a maintenance button
    :return: the value, or None when the task was never reset or is unusable
    """
    raw = attributes.get("days_left")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def with_days_left(attributes: dict[str, Any], value: int) -> dict[str, Any]:
    """Build attributes carrying a new `days_left`.

    Keeps `days_left`, `overdue` and `last_reset` consistent with each other,
    because the card derives its colours from days_left but prints last_reset
    as-is: a countdown running against a frozen date reads as a bug on video.

    :param attributes: the current attributes
    :param value: the value to publish
    :return: a new attribute set
    """
    updated = dict(attributes)
    updated["days_left"] = value
    updated["overdue"] = value < 0

    previous = current_days_left(attributes)
    last_reset = attributes.get("last_reset")

    if isinstance(last_reset, str) and previous is not None:
        # Move the reset date back by the same number of days
        try:
            moved = datetime.fromisoformat(
                last_reset.replace("Z", "+00:00")
            ) - timedelta(days=previous - value)
            updated["last_reset"] = moved.isoformat()
        except ValueError:
            pass
    elif last_reset is None:
        # Never reset, but the demo asks for a deadline: synthesise the date
        # the task would have been reset on to be `value` days from done.
        interval = attributes.get("interval_days") or 0
        try:
            elapsed = float(interval) - value
        except (TypeError, ValueError):
            elapsed = 0.0
        if elapsed > 0:
            moved = datetime.now().astimezone() - timedelta(days=elapsed)
            updated["last_reset"] = moved.isoformat()

    return updated


def seed_attributes(
    attributes: dict[str, Any], start: int, floor: int
) -> dict[str, Any] | None:
    """Force the starting point of a countdown.

    Unlike a tick, this applies to a task that was never reset too: an
    explicit start value is exactly how you stage one for a recording.

    :param attributes: the current attributes
    :param start: the days_left to start from
    :param floor: lowest days_left the run will reach
    :return: the new attributes, or None when the value is already in place
    """
    if start < floor:
        return None
    if current_days_left(attributes) == start:
        return None
    return with_days_left(attributes, start)


def shift_attributes(
    attributes: dict[str, Any], step: int, floor: int
) -> dict[str, Any] | None:
    """Build the attribute set for one tick of the fake clock.

    A task that was never reset is left alone: it has no deadline to move.
    Give it an explicit start value to bring it into the animation.

    :param attributes: the current attributes
    :param step: how many days to remove per tick
    :param floor: lowest days_left to go down to
    :return: the new attributes, or None when nothing should change
    """
    days_left = current_days_left(attributes)
    if days_left is None or days_left <= floor:
        return None
    return with_days_left(attributes, max(floor, days_left - step))


def parse_target(spec: str) -> tuple:
    """Split an `entity_id` or `entity_id=days_left` command line argument.

    :param spec: the raw argument
    :return: the entity id and the requested start value, or None
    """
    entity_id, sep, raw = spec.partition("=")
    entity_id = entity_id.strip()
    if not sep:
        return entity_id, None
    try:
        return entity_id, int(raw)
    except ValueError:
        raise SystemExit(
            f"{spec}: the start value must be a whole number of days"
        ) from None


# --------------------------------------------------------------------------- #
#   Runner
# --------------------------------------------------------------------------- #


def resolve_targets(
    hass: HomeAssistant, requested: list[str], take_all: bool, default_start
) -> list[tuple]:
    """Collect the state objects to animate and their starting point.

    :param hass: the API client
    :param requested: `entity_id` or `entity_id=days_left` arguments
    :param take_all: when True, every maintenance task is taken
    :param default_start: start value applied when none is given, or None
    :return: pairs of state object and requested start value
    """
    tasks = [state for state in hass.states() if is_maintenance_state(state)]
    by_id = {state["entity_id"]: state for state in tasks}

    # Per-entity values are still honoured alongside --all
    starts = {}
    for spec in requested:
        entity_id, start = parse_target(spec)
        if entity_id not in by_id:
            known = ", ".join(sorted(by_id)) or "none found"
            raise SystemExit(
                f"{entity_id} is not a maintenance task. Available: {known}"
            )
        starts[entity_id] = start

    selected = tasks if take_all else [by_id[entity_id] for entity_id in starts]
    return [
        (state, starts.get(state["entity_id"]) or default_start)
        if starts.get(state["entity_id"]) is None
        else (state, starts[state["entity_id"]])
        for state in selected
    ]


def print_tasks(states: list[dict[str, Any]]) -> None:
    """Print a table of maintenance tasks.

    :param states: the state objects to print
    """
    if not states:
        print("No maintenance task found.")
        return
    width = max(len(state["entity_id"]) for state in states)
    print(f"{'entity_id'.ljust(width)}  {'days_left':>9}  {'interval':>8}  status")
    for state in sorted(states, key=lambda s: s["entity_id"]):
        attributes = state.get("attributes") or {}
        days_left = attributes.get("days_left")
        interval = attributes.get("interval_days", 0) or 0
        try:
            status = status_of(
                None if days_left is None else int(days_left), float(interval)
            )
        except (TypeError, ValueError):
            status = "?"
        shown = "never" if days_left is None else str(days_left)
        name = state["entity_id"].ljust(width)
        print(f"{name}  {shown:>9}  {interval!s:>8}  {status}")


def restore(hass: HomeAssistant, snapshot: dict[str, dict[str, Any]]) -> None:
    """Put the captured states back.

    :param hass: the API client
    :param snapshot: entity_id to the state object captured at startup
    """
    for entity_id, state in snapshot.items():
        try:
            hass.set_state(entity_id, state["state"], state["attributes"])
        except SystemExit as err:
            print(f"  could not restore {entity_id}: {err}", file=sys.stderr)
    print(f"Restored {len(snapshot)} entities.")


def run(args: argparse.Namespace, hass: HomeAssistant) -> int:
    """Run the fake clock until the floor, the duration or Ctrl-C.

    :param args: parsed command line
    :param hass: the API client
    :return: the process exit code
    """
    targets = resolve_targets(hass, args.entities, args.all, args.start)
    if not targets:
        print("Nothing to animate.")
        return 1

    snapshot = {
        state["entity_id"]: {
            "state": state["state"],
            "attributes": dict(state["attributes"]),
        }
        for state, _start in targets
    }
    live = {
        entity_id: dict(state["attributes"]) for entity_id, state in snapshot.items()
    }

    # Stage the starting points before the first tick so the recording opens
    # on the values asked for rather than on whatever the tank reports today
    for state, start in targets:
        if start is None:
            continue
        entity_id = state["entity_id"]
        seeded = seed_attributes(live[entity_id], start, args.floor)
        if seeded is None:
            print(
                f"  {entity_id}: start {start} ignored "
                f"(already there, or below the floor {args.floor})"
            )
            continue
        live[entity_id] = seeded
        hass.set_state(entity_id, snapshot[entity_id]["state"], seeded)
        print(f"  {entity_id}: starting at {start} day(s)")

    print(
        f"Animating {len(live)} task(s): -{args.step} day(s) every "
        f"{args.interval}s, floor {args.floor}. Ctrl-C to stop and restore."
    )

    stopping = {"now": False}

    def on_signal(_signum: int, _frame: Any) -> None:
        stopping["now"] = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    started = time.monotonic()
    tick = 0
    try:
        while not stopping["now"]:
            tick += 1
            moved = 0
            for entity_id, attributes in live.items():
                updated = shift_attributes(attributes, args.step, args.floor)
                if updated is None:
                    continue
                live[entity_id] = updated
                hass.set_state(entity_id, snapshot[entity_id]["state"], updated)
                moved += 1
                if args.verbose:
                    interval = float(updated.get("interval_days", 0) or 0)
                    print(
                        f"  {entity_id}: days_left="
                        f"{updated['days_left']} "
                        f"({status_of(updated['days_left'], interval)})"
                    )

            print(f"tick {tick}: {moved} task(s) moved")
            if moved == 0:
                print("Every task reached the floor.")
                break
            if args.duration and time.monotonic() - started >= args.duration:
                print("Duration reached.")
                break

            # Sleep in slices so Ctrl-C is honoured promptly
            deadline = time.monotonic() + args.interval
            while not stopping["now"] and time.monotonic() < deadline:
                time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
    finally:
        if args.restore:
            print("Restoring original values...")
            restore(hass, snapshot)
        else:
            print("Leaving the faked values in place (--no-restore).")

    return 0


def resolve_credentials(url, token) -> tuple:
    """Work out which Home Assistant instance to talk to, and with what.

    The API needs a bearer token wherever the script runs from: there is no
    localhost exemption. Inside an add-on the Supervisor already provides one,
    so no long-lived token has to be created for a demo.

    :param url: the --url argument, or None
    :param token: the --token argument, or None
    :return: the base URL, the token, and a label describing where they came from
    """
    if token:
        return url or os.environ.get("HA_URL", DEFAULT_URL), token, "--token"

    env_token = os.environ.get("HA_TOKEN")
    if env_token:
        return url or os.environ.get("HA_URL", DEFAULT_URL), env_token, "$HA_TOKEN"

    supervisor = os.environ.get("SUPERVISOR_TOKEN")
    if supervisor:
        # Add-on context: the Supervisor proxies the core API, no long-lived
        # token needed. An explicit --url still wins.
        return url or SUPERVISOR_URL, supervisor, "$SUPERVISOR_TOKEN"

    return url or os.environ.get("HA_URL", DEFAULT_URL), None, "none"


def main() -> int:
    """Parse the command line and dispatch."""
    parser = argparse.ArgumentParser(
        description="Accelerate maintenance countdowns for a demo video.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "entities",
        nargs="*",
        metavar="ENTITY[=DAYS]",
        help=(
            "button.* maintenance entities to animate; append =DAYS to force "
            "the starting days_left of that entity (e.g. button.foo=12)"
        ),
    )
    parser.add_argument(
        "--url",
        default=None,
        help=(
            "Home Assistant base URL "
            "(default: $HA_URL, or the Supervisor API inside an add-on)"
        ),
    )
    parser.add_argument(
        "--token",
        default=None,
        help=(
            "long-lived access token "
            "(default: $HA_TOKEN, or $SUPERVISOR_TOKEN inside an add-on)"
        ),
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="seconds between two ticks (default: 2)",
    )
    parser.add_argument(
        "--step",
        type=int,
        default=1,
        help="days removed per tick (default: 1)",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=None,
        help="starting days_left for entities with no =DAYS of their own",
    )
    parser.add_argument(
        "--floor",
        type=int,
        default=-5,
        help="lowest days_left to reach (default: -5)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="stop after this many seconds (default: no limit)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="animate every maintenance task found",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list the maintenance tasks and exit",
    )
    parser.add_argument(
        "--no-restore",
        dest="restore",
        action="store_false",
        help="keep the faked values instead of restoring on exit",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print each entity on every tick",
    )
    args = parser.parse_args()

    url, token, origin = resolve_credentials(args.url, args.token)
    if not token:
        parser.error(
            "no token: pass --token, set HA_TOKEN, or run this from an add-on "
            "where SUPERVISOR_TOKEN is available"
        )
    args.url, args.token = url, token
    if args.verbose:
        print(f"Using {args.url} ({origin})")
    if not args.list and not args.entities and not args.all:
        parser.error("name at least one entity, or pass --all or --list")
    if args.interval <= 0:
        parser.error("--interval must be positive")
    if args.step <= 0:
        parser.error("--step must be positive")
    if args.start is not None and args.start < args.floor:
        parser.error("--start is below --floor: nothing would be animated")

    hass = HomeAssistant(args.url, args.token)

    if args.list:
        print_tasks([state for state in hass.states() if is_maintenance_state(state)])
        return 0

    return run(args, hass)


if __name__ == "__main__":
    sys.exit(main())
