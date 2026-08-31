#!/usr/bin/env python3
"""Play a scripted scenario on a ReefATO+ for a demo or a screen recording.

Drives the entities of one RSATO+ device through the Home Assistant REST API
so the ha-reef-card visuals can be filmed without waiting on real water: the
reservoir draining, the sump level cycling through its four states, a probe
being unplugged, a leak detector that was never configured.

The scenario lives in an external file (YAML or JSON) so the same script can
tell different stories. See `ato_demo.yaml` for a commented example.

Like maint_timelapse.py, this writes straight into the state machine with
POST /api/states/<entity_id>. That is a display-level override: the
integration owns these entities and restores the real values on its next
poll, so raise its scan interval for the duration of the shoot. Nothing is
written to disk on the HA side, and the snapshot taken at startup is replayed
on exit.

Credentials come from, in order: the command line, the environment, a
configuration file, then the Supervisor token when running as an add-on.

    # ato_timelapse.conf, chmod 600
    [default]
    url = http://homeassistant.local:8123
    token = <long-lived access token>
    device = rsato
    scenario = ato_demo.yaml

    [lab]
    url = http://192.168.0.50:8123
    token = <another token>

Usage:
    ./ato_timelapse.py --list                    # find the ATO devices
    ./ato_timelapse.py --device "Simu RSATO" --show-roles
    ./ato_timelapse.py --device "Simu RSATO" --scenario ato_demo.yaml --dry-run
    ./ato_timelapse.py --device "Simu RSATO" --scenario ato_demo.yaml
    ./ato_timelapse.py --profile lab             # another instance

The `simulate` step also feeds `today_volume_usage`, `total_volume_usage`,
`today_fills` and `total_fills`. Home Assistant records everything written
through /api/states, so the recorder picks those up and a history chart draws
them as real data. Two things to know when filming one:

  - History cannot be backdated. The curve starts filling from the moment the
    script runs, so a chart pinned to the calendar day will show a short
    segment near "now" rather than a full day. Use a rolling window of a few
    minutes (`hours: 0.1`) to fill the width.
  - The integration overwrites these entities on its next poll, and that
    overwrite is recorded too. Raise its scan interval for the shoot.

Every write of `is_pump_on`, wherever it comes from, also publishes the
`pump_state` and `prev_pump_state` the firmware carries next to it, so a
dashboard never shows a running pump beside `pump_state: off`. The `simulate`
step additionally sets `last_pump_on_cause`, since it knows what started the
fill it is playing.
"""

import argparse
import configparser
import json
import os
import re
import signal
import sys
import time
import urllib.error
import urllib.request
from typing import Any

DEFAULT_URL = "http://homeassistant.local:8123"

# Searched in order when --config is not given. The first file that exists
# wins; a missing file is not an error, since the token can also come from the
# environment or from the Supervisor.
CONFIG_LOCATIONS = (
    "./ato_timelapse.conf",
    "~/.config/ato_timelapse.conf",
    "~/.ato_timelapse.conf",
)

# Roles used to recognise an RSATO+ in the state machine. `reef_role` is the
# integration's translation_key, so it is stable across languages and entity
# renames.
#
# All three are sensor or binary_sensor entities on purpose: ReefRoleMixin is
# only mixed into the sensor, binary_sensor and select platforms, plus the
# maintenance entities. A `number` such as `ato_tank_volume` carries no
# reef_role at all, so it cannot be used as a marker — see capacity().
ATO_MARKER_ROLES = frozenset({"volume_left", "water_level", "is_pump_on"})

# The sump probe reports one of these, in physical order.
WATER_LEVELS = ("below", "desired_level_1", "desired_level_2", "above")


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
        if not body:
            return None
        return json.loads(body)

    def states(self) -> list[dict[str, Any]]:
        """Fetch the whole state machine."""
        return self._request("GET", "/states") or []

    def set_state(self, entity_id: str, state: str, attributes: dict[str, Any]) -> None:
        """Overwrite one entity in the state machine."""
        self._request(
            "POST",
            f"/states/{entity_id}",
            {"state": state, "attributes": attributes},
        )

    def render(self, template: str) -> str | None:
        """Render a Jinja template server-side.

        /api/template answers plain text, not JSON, and is the only way to
        reach the device registry over REST — /api/states carries no device
        information at all.

        :param template: the template source
        :return: the rendered text, or None when the endpoint refuses it
        """
        data = json.dumps({"template": template}).encode()
        request = urllib.request.Request(
            f"{self.url}/api/template",
            data=data,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as answer:
                return answer.read().decode()
        except urllib.error.HTTPError:
            # Older cores, or a template the instance rejects: the caller
            # falls back to grouping by entity_id.
            return None
        except urllib.error.URLError as err:
            raise SystemExit(f"Cannot reach {self.url}: {err.reason}") from err


# --------------------------------------------------------------------------- #
#   Device discovery
# --------------------------------------------------------------------------- #


# One line per entity: device id, device name, entity id. `integration_entities`
# scopes it to ha-reefbeat-component, so nothing else in the instance is
# touched, and `device_id` gives the real grouping instead of a name guess.
_DEVICE_TEMPLATE = (
    "{%- for e in integration_entities('redsea') -%}"
    "{%- set d = device_id(e) -%}"
    "{%- if d -%}{{ d }}\t{{ device_attr(d, 'name') }}\t{{ e }}\n{% endif -%}"
    "{%- endfor -%}"
)


def slugify(text: str) -> str:
    """Lowercase, underscore-separated form of a free-text name."""
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def collect_devices(hass: HomeAssistant) -> dict[str, dict[str, dict[str, Any]]]:
    """Group every ReefBeat entity by the device it belongs to.

    Uses the device registry through the template API. If that is refused,
    falls back to one bucket per entity_id prefix, which is only good enough
    for filtering with --device.

    :param hass: the API client
    :return: device label -> role -> state object
    """
    by_id = {state["entity_id"]: state for state in hass.states()}
    rendered = hass.render(_DEVICE_TEMPLATE)

    if not rendered or "\t" not in rendered:
        return _collect_devices_fallback(by_id)

    devices: dict[str, dict[str, dict[str, Any]]] = {}
    for line in rendered.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        _device_id, device_name, entity_id = parts
        state = by_id.get(entity_id)
        if state is None:
            continue
        role = (state.get("attributes") or {}).get("reef_role")
        if not role:
            continue
        # Two entities of one device never share a reef_role, so first wins.
        devices.setdefault(slugify(device_name), {}).setdefault(role, state)
    return devices


def _collect_devices_fallback(
    by_id: dict[str, dict[str, Any]],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Group by the leading words of the entity_id, registry unavailable.

    Entities of one device share a long entity_id prefix, but where the device
    name stops and the entity name starts cannot be recovered from the id
    alone. Grouping on the first three segments is arbitrary; it is enough to
    let --device select something, and --show-roles will make a bad split
    obvious.
    """
    devices: dict[str, dict[str, dict[str, Any]]] = {}
    for entity_id, state in by_id.items():
        role = (state.get("attributes") or {}).get("reef_role")
        if not role:
            continue
        body = entity_id.split(".", 1)[1]
        label = "_".join(body.split("_")[:3])
        devices.setdefault(label, {}).setdefault(role, state)
    return devices


def ato_devices(
    devices: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Keep only the devices that look like a ReefATO+."""
    return {
        slug: roles
        for slug, roles in devices.items()
        if ATO_MARKER_ROLES.issubset(roles.keys())
    }


def pick_any_device(
    hass: HomeAssistant, wanted: str | None
) -> tuple[str, dict[str, dict[str, Any]]]:
    """Resolve --device against every ReefBeat device, ATO or not.

    Used by --show-roles, which has to be able to inspect a device precisely
    when it fails the ATO test: that is when knowing its roles matters most.

    :param hass: the API client
    :param wanted: a substring of the device name, or None
    :return: the label and its role index
    """
    devices = collect_devices(hass)
    if not devices:
        raise SystemExit("No entity carrying a reef_role attribute was found.")
    if wanted:
        needle = slugify(wanted)
        devices = {slug: roles for slug, roles in devices.items() if needle in slug}
        if not devices:
            raise SystemExit(f"No device matching {wanted!r}.")
    if len(devices) > 1:
        names = ", ".join(sorted(devices))
        raise SystemExit(f"Several devices match: {names}. Narrow --device.")
    slug = next(iter(devices))
    return slug, devices[slug]


def pick_device(
    hass: HomeAssistant, wanted: str | None
) -> tuple[str, dict[str, dict[str, Any]]]:
    """Resolve the --device argument to one ATO device.

    :param hass: the API client
    :param wanted: a substring of the device slug or friendly name, or None
    :return: the slug and its role index
    """
    devices = collect_devices(hass)
    candidates = ato_devices(devices)
    if not candidates:
        if not devices:
            raise SystemExit(
                "No entity carrying a reef_role attribute was found. Check "
                "that ha-reefbeat-component is loaded and that this token can "
                "see it."
            )
        # Name the missing markers: on a real ATO this is nearly always one
        # platform that does not expose reef_role, not a wrong device.
        detail = "\n".join(
            f"  {slug}: missing {', '.join(sorted(ATO_MARKER_ROLES - set(roles)))}"
            for slug, roles in sorted(devices.items())
        )
        raise SystemExit(
            "No ReefATO+ found. Devices seen, and the marker roles they do "
            f"not expose:\n{detail}\n"
            "Use --show-roles on one of them to inspect it."
        )
    if wanted:
        needle = slugify(wanted)
        candidates = {
            slug: roles for slug, roles in candidates.items() if needle in slug
        }
        if not candidates:
            raise SystemExit(f"No ReefATO+ matching {wanted!r}.")
    if len(candidates) > 1:
        names = ", ".join(sorted(candidates))
        raise SystemExit(f"Several ATO devices match: {names}. Narrow --device.")
    slug = next(iter(candidates))
    return slug, candidates[slug]


# --------------------------------------------------------------------------- #
#   Scenario file
# --------------------------------------------------------------------------- #


def load_scenario(path: str) -> dict[str, Any]:
    """Read a scenario from YAML or JSON.

    YAML is used when PyYAML is importable, which it always is inside a Home
    Assistant environment; JSON keeps the script usable on a bare Python.

    :param path: the file to read
    :return: the parsed scenario
    """
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise SystemExit(
                f"{path} is YAML but PyYAML is not installed. "
                "Install it, or write the scenario as JSON."
            ) from None
        loaded = yaml.safe_load(text)
    else:
        loaded = json.loads(text)
    if not isinstance(loaded, dict) or "sequence" not in loaded:
        raise SystemExit(f"{path}: expected a mapping holding a `sequence` list.")
    return loaded


def resolve_amount(raw: Any, full_scale: float | None) -> float:
    """Turn a scenario value into a number.

    Accepts a plain number, or a percentage of the reservoir capacity such as
    `"100%"` — the latter is what makes a scenario portable between tanks.

    :param raw: the value read from the scenario
    :param full_scale: the value 100% refers to, or None
    :return: the resolved number
    """
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw).strip()
    if text.endswith("%"):
        if full_scale is None:
            raise SystemExit(
                f"{raw!r}: percentages need the reservoir capacity, and the "
                "`ato_tank_volume` number entity carries no reef_role so it "
                "cannot be read. Add `capacity: <full volume_left value>` at "
                "the top of the scenario, or use absolute values."
            )
        return float(text[:-1]) * full_scale / 100.0
    try:
        return float(text)
    except ValueError:
        raise SystemExit(f"{raw!r} is not a number or a percentage.") from None


# --------------------------------------------------------------------------- #
#   Player
# --------------------------------------------------------------------------- #


class Stopper:
    """Cooperative stop flag wired to SIGINT and SIGTERM."""

    def __init__(self) -> None:
        self.stopped = False
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def _handle(self, *_args: Any) -> None:
        self.stopped = True

    def sleep(self, seconds: float) -> None:
        """Sleep in slices so a Ctrl-C answers straight away."""
        deadline = time.monotonic() + seconds
        while not self.stopped and time.monotonic() < deadline:
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))


class Player:
    """Execute the steps of a scenario against one ATO device."""

    def __init__(
        self,
        hass: HomeAssistant,
        roles: dict[str, dict[str, Any]],
        dry_run: bool = False,
        verbose: bool = False,
    ) -> None:
        self.hass = hass
        self.roles = roles
        self.override_capacity: float | None = None
        # Days of autonomy at a full reservoir. When set, every write of
        # volume_left publishes a matching days_till_empty.
        self.days_when_full: float | None = None
        # Roles a `set` step asked for that this device does not expose.
        self.skipped: set = set()
        self.dry_run = dry_run
        self.verbose = verbose
        self.stopper = Stopper()
        self.snapshot: dict[str, dict[str, Any]] = {}
        # Last `pump_state` published, so the next write can report it as
        # `prev_pump_state`. Seeded from the device on the first write.
        self._pump_state: str | None = None

    # -- plumbing ---------------------------------------------------------- #

    def entity(self, role: str) -> dict[str, Any]:
        """Look up the entity backing a role, failing with a usable message."""
        state = self.roles.get(role)
        if state is None:
            known = ", ".join(sorted(self.roles))
            raise SystemExit(f"This device has no {role!r} entity. Known: {known}")
        return state

    def has(self, role: str) -> bool:
        """Whether the device exposes a role."""
        return role in self.roles

    def capacity(self) -> float | None:
        """Reservoir capacity, the reference for percentages.

        Expressed in the unit of `volume_left`, which the firmware reports in
        millilitres while `ato_tank_volume` is in litres — a 71 L reservoir is
        `capacity: 71000` here.

        `ato_tank_volume` is a `number` entity, and the integration only mixes
        ReefRoleMixin into sensor/binary_sensor/select, so on most installs it
        carries no reef_role and cannot be found here. The scenario can then
        state the capacity itself.

        :return: the capacity, or None when it cannot be determined
        """
        if self.override_capacity is not None:
            return self.override_capacity
        state = self.roles.get("ato_tank_volume")
        if state is None:
            return None
        try:
            return float(state["state"])
        except (TypeError, ValueError, KeyError):
            return None

    def resolve(self, role: str, value: Any) -> Any:
        """Turn a scenario value into what should be published.

        Percentages are resolved against the reservoir capacity, so a scenario
        written as `volume_left: 100%` works on any tank size. Booleans come
        from YAML turning bare `on`/`off` into True/False, but the state
        machine wants the strings a binary_sensor actually publishes.

        :param role: the reef_role being written
        :param value: the raw value from the scenario
        :return: a string or a number ready to publish
        """
        if isinstance(value, bool):
            return "on" if value else "off"
        if isinstance(value, str) and value.strip().endswith("%"):
            full_scale = self.capacity() if role == "volume_left" else None
            return resolve_amount(value, full_scale)
        return value

    def write(self, role: str, value: Any) -> None:
        """Publish one state, remembering the original first.

        Writing `volume_left` also refreshes `days_till_empty` when the
        scenario declared an autonomy: a countdown frozen at four days while
        the tank visibly drains reads as a bug on video.

        Writing `is_pump_on` likewise refreshes `pump_state` and
        `prev_pump_state`. `is_pump_on` is the field to watch, but the
        firmware carries those two next to it, and a dashboard showing a
        running pump beside `pump_state: off` reads as the same kind of bug.
        """
        self._write_one(role, value)
        if role == "volume_left":
            self._write_days_till_empty(value)
        elif role == "is_pump_on":
            self._write_pump_state(value)

    def _write_pump_state(self, is_pump_on: Any) -> None:
        """Publish the pump state fields matching an `is_pump_on` value.

        Skipped silently for any role the device does not expose, so a
        scenario stays valid on a firmware reporting a subset of them.

        :param is_pump_on: the value just written, `"on"` or `"off"`
        """
        state = "pump_on" if str(is_pump_on) == "on" else "off"
        if self._pump_state is None:
            # First write of the run: the device's own value is the previous
            # one, not a guess.
            current = self.roles.get("pump_state")
            self._pump_state = str(current["state"]) if current else "off"
        previous, self._pump_state = self._pump_state, state
        if self.has("prev_pump_state"):
            self._write_one("prev_pump_state", previous)
        if self.has("pump_state"):
            self._write_one("pump_state", state)

    def _write_days_till_empty(self, volume: Any) -> None:
        """Publish the autonomy matching a reservoir level.

        :param volume: the volume just written, in the unit of volume_left
        """
        if self.days_when_full is None or "days_till_empty" not in self.roles:
            return
        full_scale = self.capacity()
        if not full_scale:
            return
        try:
            ratio = float(volume) / full_scale
        except (TypeError, ValueError):
            return
        days = max(0.0, min(1.0, ratio)) * self.days_when_full
        self._write_one("days_till_empty", round(days, 1))

    def _write_one(self, role: str, value: Any) -> None:
        """Publish exactly one state, with no derived side effect."""
        state = self.entity(role)
        entity_id = state["entity_id"]
        if entity_id not in self.snapshot:
            self.snapshot[entity_id] = {
                "state": state["state"],
                "attributes": dict(state.get("attributes") or {}),
            }
        text = value if isinstance(value, str) else f"{value:g}"
        if self.dry_run:
            print(f"      would set {entity_id} = {text}")
            return
        self.hass.set_state(entity_id, text, self.snapshot[entity_id]["attributes"])
        if self.verbose:
            print(f"      {entity_id} = {text}")

    def restore(self) -> None:
        """Replay the snapshot taken as the scenario ran."""
        if self.dry_run or not self.snapshot:
            return
        for entity_id, original in self.snapshot.items():
            self.hass.set_state(entity_id, original["state"], original["attributes"])
        print(f"Restored {len(self.snapshot)} entit(ies) to their initial values.")

    # -- steps ------------------------------------------------------------- #

    def do_wait(self, seconds: float) -> None:
        print(f"    wait {seconds:g}s")
        if not self.dry_run:
            self.stopper.sleep(seconds)

    def do_set(self, assignments: dict[str, Any]) -> None:
        for role, raw in assignments.items():
            if not self.has(role):
                # Skipped rather than fatal: a scenario is written against the
                # full entity set, and a device missing one optional sensor
                # must not abort a three-minute recording at step one. The
                # role is still named, so a typo stays visible, and the run
                # ends on a summary of everything skipped.
                if role not in self.skipped:
                    print(f"    skip {role} (no such entity on this device)")
                    self.skipped.add(role)
                continue
            value = self.resolve(role, raw)
            shown = value if isinstance(value, str) else f"{value:g}"
            suffix = f"  ({raw})" if str(raw) != shown else ""
            print(f"    set {role} = {shown}{suffix}")
            self.write(role, value)

    def do_ramp(self, spec: dict[str, Any]) -> None:
        role = spec.get("role")
        if not role:
            raise SystemExit("a `ramp` step needs a `role`.")
        full_scale = self.capacity() if role == "volume_left" else None
        start = resolve_amount(spec.get("from", 0), full_scale)
        end = resolve_amount(spec.get("to", 0), full_scale)
        step = abs(resolve_amount(spec.get("step", 1), full_scale))
        every = float(spec.get("every", 1))
        if step == 0:
            raise SystemExit("a `ramp` step cannot have a step of 0.")

        descending = end < start
        print(f"    ramp {role} {start:g} -> {end:g} by {step:g} every {every:g}s")
        value = start
        self.write(role, value)
        while not self.stopper.stopped:
            value = value - step if descending else value + step
            # Clamp on the last frame so the ramp lands exactly on `to`
            # instead of overshooting when the range is not a multiple of step.
            if (descending and value <= end) or (not descending and value >= end):
                value = end
                self.wait_tick(every)
                self.write(role, value)
                break
            self.wait_tick(every)
            self.write(role, value)

    def do_cycle(self, spec: dict[str, Any]) -> None:
        role = spec.get("role")
        if not role:
            raise SystemExit("a `cycle` step needs a `role`.")
        values = spec.get("values") or list(WATER_LEVELS)
        every = float(spec.get("every", 1))
        repeat = int(spec.get("repeat", 1))
        bounce = bool(spec.get("bounce", False))

        order = list(values)
        if bounce and len(order) > 2:
            # Go up then back down without repeating the two ends, so a level
            # sweep reads as water rising and falling rather than teleporting.
            order = order + order[-2:0:-1]

        print(
            f"    cycle {role} through {len(order)} value(s) "
            f"every {every:g}s, {repeat} time(s)"
        )
        for _round in range(repeat):
            for value in order:
                if self.stopper.stopped:
                    return
                self.write(role, value)
                self.wait_tick(every)

    def do_simulate(self, spec: dict[str, Any]) -> None:
        """Play the real ATO loop: evaporation, top-up, reservoir draining.

        The two levels are not independent, so running them as parallel tracks
        would look wrong on camera: the RO reservoir only empties while the
        pump is filling, and the pump only runs between the trigger level and
        the target level. This models that coupling instead.

        One cycle is: the sump evaporates down to `trigger`, the pump starts,
        the sump climbs back to `target` while the reservoir gives up
        `consumption`, the pump stops. Repeat until the reservoir reaches `to`,
        at which point the device is left in `empty` with the sump low — which
        is exactly the state worth filming.
        """
        full_scale = self.capacity()
        volume = resolve_amount(spec.get("from", "100%"), full_scale)
        floor = resolve_amount(spec.get("to", 0), full_scale)
        consumption = abs(resolve_amount(spec.get("consumption", "5%"), full_scale))
        evaporation = float(spec.get("evaporation", 5))
        fill = float(spec.get("fill", 1.5))
        frames = max(1, int(spec.get("frames", 5)))
        max_cycles = int(spec.get("max_cycles", 0))
        cause = str(spec.get("cause", "ec_sensor_s1"))

        trigger = str(spec.get("trigger", "below"))
        target = str(spec.get("target", "desired_level_2"))
        start = str(spec.get("start_level", target))
        for name in (trigger, target, start):
            if name not in WATER_LEVELS:
                raise SystemExit(
                    f"{name!r} is not a sump level. "
                    f"Expected one of: {', '.join(WATER_LEVELS)}"
                )
        trigger_idx = WATER_LEVELS.index(trigger)
        target_idx = WATER_LEVELS.index(target)
        if target_idx <= trigger_idx:
            raise SystemExit(
                f"`target` ({target}) must sit above `trigger` ({trigger}); "
                "the pump has to have somewhere to fill to."
            )

        print(
            f"    simulate {volume:g} -> {floor:g}, "
            f"{consumption:g} per fill, sump {trigger} -> {target}"
        )

        level_idx = WATER_LEVELS.index(start)
        self.write("water_level", WATER_LEVELS[level_idx])
        self.write("volume_left", volume)
        self.write("is_pump_on", "off")

        # The counters the history chart reads. They are the mirror image of
        # the reservoir: what leaves the container is what was dispensed. Home
        # Assistant records every state written through /api/states, so these
        # feed the recorder and the chart draws them like real data.
        used = resolve_amount(spec.get("used_from", 0), full_scale)
        fills = int(spec.get("fills_from", 0))
        total = int(spec.get("total_fills_from", fills))
        self.write_counters(used, fills, total)

        rungs = target_idx - trigger_idx
        per_frame = consumption / (rungs * frames)
        cycles = 0

        while not self.stopper.stopped:
            # Checked before evaporating, not after: once the reservoir is
            # dry the sump must freeze where it is. Letting evaporation carry
            # on would be physically right but reads as "still working" on
            # video, which is the opposite of the point.
            if volume <= floor:
                self.run_dry(level_idx)
                return

            # Evaporation: the sump drops one level at a time, pump off.
            while level_idx > trigger_idx and not self.stopper.stopped:
                self.wait_tick(evaporation)
                level_idx -= 1
                self.write("water_level", WATER_LEVELS[level_idx])

            if self.stopper.stopped:
                return

            # Top-up: the pump runs, the sump climbs, the reservoir gives up
            # `consumption` spread over the whole climb.
            #
            # `last_pump_on_cause` names what started this fill. The loop
            # models an automatic top-up, so the default is the level sensor
            # that reached the trigger rung -- `manual` is what the fill
            # button produces, and would misdescribe what is on screen.
            if self.has("last_pump_on_cause"):
                self.write("last_pump_on_cause", cause)
            self.write("is_pump_on", "on")
            for _rung in range(rungs):
                for _frame in range(frames):
                    if self.stopper.stopped:
                        return
                    self.wait_tick(fill / frames)
                    volume = max(floor, volume - per_frame)
                    # Snap the float residue, otherwise the last frame lands on
                    # something like 2.8e-14 and the run buys a whole extra
                    # cycle that moves nothing.
                    if abs(volume - floor) < per_frame / 1000:
                        volume = floor
                    self.write("volume_left", volume)
                    used += per_frame
                    self.write_counters(used, fills, total)
                    if volume <= floor:
                        # The reservoir ran out mid-climb. A pump with nothing
                        # to pump cannot finish raising the sump, so the level
                        # stays on the rung it had reached.
                        self.run_dry(level_idx)
                        return
                level_idx += 1
                self.write("water_level", WATER_LEVELS[level_idx])
            self.write("is_pump_on", "off")

            # One completed top-up is one fill.
            fills += 1
            total += 1
            self.write_counters(used, fills, total)

            cycles += 1
            print(f"    cycle {cycles} done, reservoir at {volume:g}")
            if max_cycles and cycles >= max_cycles:
                return

    def write_counters(self, used: float, fills: int, total: int) -> None:
        """Publish the dispensed-volume and fill counters.

        Skipped silently for any role the device does not expose, so a
        scenario stays valid on a firmware reporting a subset of them.

        :param used: volume dispensed from the current container
        :param fills: number of fills today
        :param total: lifetime number of fills
        """
        for role, value in (
            ("today_volume_usage", round(used)),
            ("total_volume_usage", round(used)),
            ("today_fills", fills),
            ("total_fills", total),
        ):
            if self.has(role):
                self.write(role, value)

    def run_dry(self, level_idx: int) -> None:
        """Leave the device in the state an empty reservoir produces.

        :param level_idx: the sump level reached, left untouched from here on
        """
        print(
            f"    reservoir empty, pump stopped with the sump at "
            f"{WATER_LEVELS[level_idx]}"
        )
        self.write("is_pump_on", "off")
        self.write("mode", "empty")

    def wait_tick(self, seconds: float) -> None:
        if not self.dry_run:
            self.stopper.sleep(seconds)

    # -- driver ------------------------------------------------------------ #

    def play(self, scenario: dict[str, Any], loop: bool = False) -> int:
        steps = scenario.get("sequence") or []
        if not steps:
            raise SystemExit("the scenario has an empty `sequence`.")

        try:
            while not self.stopper.stopped:
                for index, step in enumerate(steps, 1):
                    if self.stopper.stopped:
                        break
                    label = step.get("name") or f"step {index}"
                    print(f"  [{index}/{len(steps)}] {label}")
                    if "wait" in step:
                        self.do_wait(float(step["wait"]))
                    if "set" in step:
                        self.do_set(step["set"])
                    if "ramp" in step:
                        self.do_ramp(step["ramp"])
                    if "cycle" in step:
                        self.do_cycle(step["cycle"])
                    if "simulate" in step:
                        self.do_simulate(step["simulate"])
                    if step.get("restore"):
                        self.restore()
                        self.snapshot.clear()
                if not loop:
                    break
                print("  -- looping --")
        finally:
            self.restore()
            if self.skipped:
                print(
                    "Roles the scenario asked for but this device does not "
                    f"expose: {', '.join(sorted(self.skipped))}"
                )
        return 0


# --------------------------------------------------------------------------- #
#   Reporting
# --------------------------------------------------------------------------- #


def print_devices(hass: HomeAssistant) -> int:
    """List every ReefBeat device the token can see, flagging the ATO ones."""
    devices = collect_devices(hass)
    if not devices:
        print("No entity carrying a reef_role attribute was found.")
        return 1
    ato = ato_devices(devices)
    width = max(len(slug) for slug in devices)
    print(f"{'device'.ljust(width)}  roles  type")
    for slug in sorted(devices):
        kind = "RSATO+" if slug in ato else "other"
        print(f"{slug.ljust(width)}  {len(devices[slug]):>5}  {kind}")
    return 0


def print_roles(slug: str, roles: dict[str, dict[str, Any]]) -> int:
    """Print the roles of one device with their current state."""
    width = max(len(role) for role in roles)
    value_width = max(
        len("state"), max(len(str(state["state"])) for state in roles.values())
    )
    missing = ATO_MARKER_ROLES - set(roles)
    verdict = (
        "RSATO+"
        if not missing
        else f"not an ATO (missing {', '.join(sorted(missing))})"
    )
    print(f"Device: {slug}  [{verdict}]\n")
    print(f"{'role'.ljust(width)}  {'state'.ljust(value_width)}  entity_id")
    for role in sorted(roles):
        state = roles[role]
        value = str(state["state"]).ljust(value_width)
        print(f"{role.ljust(width)}  {value}  {state['entity_id']}")
    return 0


# --------------------------------------------------------------------------- #
#   Entry point
# --------------------------------------------------------------------------- #


def find_config(explicit: str | None) -> str | None:
    """Locate the configuration file.

    :param explicit: the --config argument, or None
    :return: the path to read, or None when there is nothing to read
    """
    if explicit:
        path = os.path.expanduser(explicit)
        if not os.path.exists(path):
            # An explicit path that does not exist is a typo, not a fallback.
            raise SystemExit(f"{explicit}: no such configuration file.")
        return path
    from_env = os.environ.get("ATO_TIMELAPSE_CONFIG")
    if from_env:
        path = os.path.expanduser(from_env)
        if not os.path.exists(path):
            raise SystemExit(f"$ATO_TIMELAPSE_CONFIG points at {from_env!r}, missing.")
        return path
    for candidate in CONFIG_LOCATIONS:
        path = os.path.expanduser(candidate)
        if os.path.exists(path):
            return path
    return None


def load_config(path: str | None, profile: str) -> dict[str, str]:
    """Read one profile out of the INI configuration file.

    The file holds a long-lived token, so a readable-by-others file is worth a
    warning: that token is full access to the instance, with no expiry.

    :param path: the file to read, or None
    :param profile: the section to read, falling back to [default]
    :return: the settings of that profile, empty when there is no file
    """
    if not path:
        return {}

    try:
        mode = os.stat(path).st_mode
    except OSError:
        mode = 0
    if mode & 0o077:
        print(
            f"warning: {path} is readable by other users and holds a "
            f"long-lived token. chmod 600 it.",
            file=sys.stderr,
        )

    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error as err:
        raise SystemExit(f"{path}: {err}") from err

    if profile != "default" and not parser.has_section(profile):
        known = ", ".join(parser.sections()) or "none"
        raise SystemExit(f"{path}: no [{profile}] profile. Found: {known}")

    settings: dict[str, str] = {}
    # [default] is the base, the named profile overrides it, so a file can
    # share a url between profiles and only vary the token.
    for section in ("default", profile):
        if parser.has_section(section):
            settings.update(dict(parser.items(section)))
    return settings


def resolve_credentials(
    url: str | None, token: str | None, config: dict[str, str]
) -> tuple:
    """Work out which Home Assistant instance to talk to, and with what.

    Precedence is the usual one: command line, then environment, then the
    configuration file. The Supervisor token comes last: inside an add-on it
    is always present, so letting it win would quietly ignore a file written
    on purpose to target another instance.

    :param url: the --url argument, or None
    :param token: the --token argument, or None
    :param config: the settings read from the configuration file
    :return: the base URL, the token, and a label saying where the token came from
    """
    resolved_url = url or os.environ.get("HA_URL") or config.get("url") or DEFAULT_URL

    if token:
        return resolved_url, token, "--token"

    env_token = os.environ.get("HA_TOKEN")
    if env_token:
        return resolved_url, env_token, "$HA_TOKEN"

    file_token = config.get("token")
    if file_token:
        return resolved_url, file_token, "config file"

    supervisor = os.environ.get("SUPERVISOR_TOKEN")
    if supervisor:
        # Add-on context: the Supervisor proxies the core API, so no
        # long-lived token has to be created. An explicit url still wins.
        fallback_url = (
            url or os.environ.get("HA_URL") or config.get("url")
        ) or "http://supervisor/core"
        return fallback_url, supervisor, "$SUPERVISOR_TOKEN"

    return resolved_url, None, "none"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Play a scripted scenario on a ReefATO+ for a demo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        "--config",
        default=None,
        metavar="FILE",
        help=(
            "configuration file holding url/token/device/scenario "
            "(default: $ATO_TIMELAPSE_CONFIG, ./ato_timelapse.conf, "
            "~/.config/ato_timelapse.conf, ~/.ato_timelapse.conf)"
        ),
    )
    parser.add_argument(
        "--profile",
        default="default",
        help="section of the configuration file to use (default: default)",
    )
    parser.add_argument(
        "--device", default=None, help="substring of the ATO device to drive"
    )
    parser.add_argument(
        "--scenario", default=None, help="scenario file (.yaml, .yml or .json)"
    )
    parser.add_argument(
        "--list", action="store_true", help="list the ReefBeat devices and exit"
    )
    parser.add_argument(
        "--show-roles",
        action="store_true",
        help="list the roles of the selected device and exit",
    )
    parser.add_argument(
        "--capacity",
        type=float,
        default=None,
        metavar="FULL",
        help=(
            "value that 100%% refers to, in the same unit as volume_left "
            "(millilitres on a ReefATO+), when the scenario does not set it"
        ),
    )
    parser.add_argument(
        "--loop", action="store_true", help="replay the scenario until Ctrl-C"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be written without touching Home Assistant",
    )
    parser.add_argument("--verbose", action="store_true", help="print every write")

    args = parser.parse_args()

    config_path = find_config(args.config)
    config = load_config(config_path, args.profile)

    url, token, origin = resolve_credentials(args.url, args.token, config)
    if not token:
        parser.error(
            "no token: pass --token, set HA_TOKEN, put one in a configuration "
            "file, or run this from an add-on where SUPERVISOR_TOKEN is "
            "available"
        )

    # The file can also carry the two arguments typed on every run.
    args.device = args.device or config.get("device")
    args.scenario = args.scenario or config.get("scenario")

    if args.verbose:
        where = config_path or "no configuration file"
        print(f"Using {url} (token from {origin}, {where})")

    hass = HomeAssistant(url, token)

    if args.list:
        return print_devices(hass)

    if args.show_roles:
        slug, roles = pick_any_device(hass, args.device)
        return print_roles(slug, roles)

    slug, roles = pick_device(hass, args.device)

    if not args.scenario:
        parser.error("give a --scenario, or use --list / --show-roles")

    scenario = load_scenario(args.scenario)
    print(f"Device: {slug}")
    if scenario.get("name"):
        print(f"Scenario: {scenario['name']}")
    if args.dry_run:
        print("(dry run: nothing will be written)")

    player = Player(hass, roles, dry_run=args.dry_run, verbose=args.verbose)
    if scenario.get("capacity") is not None:
        player.override_capacity = float(scenario["capacity"])
    elif args.capacity is not None:
        player.override_capacity = args.capacity
    if scenario.get("days_when_full") is not None:
        player.days_when_full = float(scenario["days_when_full"])
    return player.play(scenario, loop=args.loop)


if __name__ == "__main__":
    sys.exit(main())
