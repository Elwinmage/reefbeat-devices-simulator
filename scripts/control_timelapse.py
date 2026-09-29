#!/usr/bin/env python3
"""Play a day of reef life on a simulated ReefControl and its power strip.

Where ato_timelapse.py writes display values into Home Assistant, this one
drives the simulator itself, so the whole chain runs as on real equipment:

    probes move  ->  the hub rules switch sockets and 12V ports
                 ->  the powered outputs act back on the water
                 ->  the probes move again

The water is modelled as a few physical quantities (temperature, pH, ORP,
salinity, level). Every probe reads one of them plus its own bias, so the
embedded temperatures of the pH, EC and ATO probes follow the temperature
probe, a little apart, as real ones do. Each tick:

  1. the virtual clock advances by `speed` simulated minutes per second and is
     pushed to the simulator (`PUT /sim/clock`), so the schedules follow the
     simulated day;
  2. the dashboards of the strip and of the hub are read: that is when the
     simulator evaluates the probe rules, with their hysteresis, and says
     which outputs are powered;
  3. the physics advance over the step: drift toward a target (the room air
     for the temperature, a day and a night value for pH and ORP), plus the
     effect of every powered actuator (a heater warms, a fan cools, an ATO
     pump raises the level and dilutes the salinity);
  4. the scripted events due are played (a leak, an unplugged probe, a
     drifting sensor...);
  5. the new readings are written back (`PUT /sim/probe`,
     `PUT /sim/temperature`).

Home Assistant only sees what the integration polls, so lower the scan
interval of both devices for the shoot (a few seconds). Nothing is sent to
Home Assistant: the card and the history charts show real polled data.

The scenario lives in a YAML or JSON file; see `control_demo.yaml`. Its
optional `setup` configures the outputs through the same endpoints as the
ReefBeat app and the reef card (probe rules, schedules, names). Those settings
stay in the simulator after the run: restart it to go back to the fixtures.
The probe readings, the clock and the simulated consumption are restored on
exit.

Usage:
    ./control_timelapse.py --scenario control_demo.yaml --show
    ./control_timelapse.py --scenario control_demo.yaml --dry-run
    ./control_timelapse.py --scenario control_demo.yaml
    ./control_timelapse.py --scenario control_demo.yaml --speed 4 --loop
    ./control_timelapse.py --hub http://192.168.0.247 --power http://192.168.0.245 ...

`--hub` / `--power` (or `hub:` / `power:` in the scenario) take a URL or the
name of a device of the simulator's config.json; without `power`, the strip
the hub is `paired_with` there is used.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import signal
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SIM_CONFIG = os.path.join(HERE, "..", "config", "config.json")

DAY = 24 * 60

# The ATO probe reports discrete marks; the model keeps a continuous level,
# one unit per mark: [0, 1) below, [1, 2) first mark, [2, 3) second, >= 3 above.
WATER_LEVELS = ("below", "desired_level_1", "desired_level_2", "above")
LEVEL_MAX = len(WATER_LEVELS) - 0.01

# Conductivity to salinity, fitted on the simulator fixture (53 mS/cm ->
# 34.7 ppt -> SG 1.0264). Close enough for a display at reef salinities.
PPT_PER_MS = 0.6547
SG_PER_PPT = 0.000761

# Physical quantities of the model, and what each probe type reads of them.
CHANNELS = ("temperature", "ph", "orp", "ec", "level")
PRIMARY_CHANNEL = {"temperature": "temperature", "ph": "ph", "orp": "orp", "ec": "ec"}
HAS_TEMP = {"ph", "ec", "ato"}

# Decimals each reading is written with, as the probes report them.
DIGITS = {"temperature": 2, "ph": 2, "orp": 0, "ec": 2}

LEAK_STATUSES = {
    "aquarium": "aquarium_water_leak",
    "aquarium_water_leak": "aquarium_water_leak",
    "rodi": "rodi_water_leak",
    "rodi_water_leak": "rodi_water_leak",
    "dry": "dry",
}


# --------------------------------------------------------------------------- #
#   Simulator HTTP
# --------------------------------------------------------------------------- #


class Device:
    """Minimal JSON client for one simulated device."""

    def __init__(self, url: str, label: str, timeout: float = 5.0) -> None:
        self.url = url.rstrip("/")
        self.label = label
        self.timeout = timeout

    def request(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            f"{self.url}{path}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as answer:
                raw = answer.read()
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace")
            raise SystemExit(
                f"{self.label}: HTTP {err.code} on {method} {path}: {detail}"
            ) from err
        except urllib.error.URLError as err:
            raise SystemExit(
                f"{self.label}: cannot reach {self.url}: {err.reason}"
            ) from err
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode(errors="replace")

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def put(self, path: str, body: Any) -> Any:
        return self.request("PUT", path, body)

    def post(self, path: str, body: Any = None) -> Any:
        return self.request("POST", path, {} if body is None else body)


def resolve_device(target: str, sim_config: str) -> tuple[str, str, dict[str, Any]]:
    """Turn a URL or a simulator device name into (url, label, config entry).

    :param target: an http(s) URL, or the `name` of a config.json device
    :param sim_config: path of the simulator's config.json
    :return: the base URL, a label for messages, the config entry ({} for a URL)
    """
    if target.startswith(("http://", "https://")):
        return target, target, {}
    try:
        with open(sim_config, encoding="utf-8") as handle:
            devices = json.load(handle).get("devices", [])
    except OSError as err:
        raise SystemExit(
            f"{target!r} is not a URL and {sim_config} cannot be read: {err}. "
            "Pass a URL, or --sim-config."
        ) from err
    for device in devices:
        if str(device.get("name", "")).lower() == target.lower():
            port = int(device.get("port", 80))
            host = device["ip"] if port == 80 else f"{device['ip']}:{port}"
            return f"http://{host}", device["name"], device
    names = ", ".join(str(d.get("name")) for d in devices)
    raise SystemExit(f"No device {target!r} in {sim_config}. Known: {names}")


# --------------------------------------------------------------------------- #
#   Scenario helpers
# --------------------------------------------------------------------------- #


def load_scenario(path: str) -> dict[str, Any]:
    """Read a scenario from YAML (PyYAML) or JSON."""
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
    if not isinstance(loaded, dict):
        raise SystemExit(f"{path}: expected a mapping at the top level.")
    return loaded


def parse_clock(value: Any) -> int:
    """`"HH:MM"` (or minutes as a number) to minutes."""
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().lstrip("+")
    try:
        hours, minutes = text.split(":")
        return int(hours) * 60 + int(minutes)
    except ValueError:
        raise SystemExit(f"{value!r} is not a time, expected HH:MM.") from None


def fmt_clock(minutes: float) -> str:
    day, minute = divmod(int(minutes), DAY)
    text = f"{minute // 60:02d}:{minute % 60:02d}"
    return f"d{day + 1} {text}" if day else text


def intervals(windows: Any) -> list[dict[str, int]]:
    """`[{from: "20:00", to: "08:00"}]` to the devices' `{time, duration}`."""
    out = []
    for window in windows or []:
        start = parse_clock(window["from"]) % DAY
        end = parse_clock(window["to"]) % DAY
        duration = (end - start) % DAY or DAY
        # The firmware stores a whole day as 1439 minutes
        out.append({"time": start, "duration": min(duration, DAY - 1)})
    return out


def in_window(minute: float, start: int, end: int) -> bool:
    """Whether a minute of the day falls in [start, end), wrapping midnight."""
    minute = int(minute) % DAY
    if start <= end:
        return start <= minute < end
    return minute >= start or minute < end


def level_mark(level: float) -> str:
    return WATER_LEVELS[max(0, min(len(WATER_LEVELS) - 1, int(level)))]


def mark_level(mark: Any) -> float:
    """Middle of a mark, where a level read from a probe starts."""
    try:
        return WATER_LEVELS.index(str(mark)) + 0.5
    except ValueError:
        return 1.5


# --------------------------------------------------------------------------- #
#   Model
# --------------------------------------------------------------------------- #


@dataclass
class Probe:
    """One probe of the hub, and how far it reads from the water."""

    ptype: str
    uid: str
    raw: dict[str, Any]
    bias: dict[str, float] = field(default_factory=dict)
    unplugged: bool = False

    @property
    def label(self) -> str:
        return f"{self.ptype} {self.uid}"


@dataclass
class Actuator:
    """An output of the strip or the hub, and what it does to the water."""

    name: str
    kind: str  # "socket" or "port"
    number: int  # 0-based, as the API numbers them
    watts: Optional[float]
    effect: dict[str, float]
    on: bool = False

    @property
    def label(self) -> str:
        return f"{self.kind} {self.number + 1} ({self.name})"


class Stopper:
    """Cooperative stop flag wired to SIGINT and SIGTERM."""

    def __init__(self) -> None:
        self.stopped = False
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def _handle(self, *_args: Any) -> None:
        self.stopped = True

    def sleep(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while not self.stopped and time.monotonic() < deadline:
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))


class Timelapse:
    """Run a scenario against a hub and, optionally, its power strip."""

    def __init__(
        self,
        scenario: dict[str, Any],
        hub: Device,
        power: Optional[Device],
        dry_run: bool = False,
        verbose: bool = False,
    ) -> None:
        self.scenario = scenario
        self.hub = hub
        self.power = power
        self.dry_run = dry_run
        self.verbose = verbose
        self.stopper = Stopper()
        self.random = random.Random(scenario.get("seed"))

        self.physics: dict[str, dict[str, Any]] = scenario.get("physics") or {}
        self.ambient: dict[str, Any] = scenario.get("ambient") or {}
        self.speed = float(scenario.get("speed", 8))
        self.tick = float(scenario.get("tick", 1))
        self.start = parse_clock(scenario.get("start", "06:00"))
        self.duration = parse_clock(scenario.get("duration", "24:00"))
        self.power_probe = str(scenario.get("power_probe", "water"))

        self.probes: list[Probe] = []
        self.water: dict[str, float] = {}
        self.ec_reference_level = 0.0
        self.actuators: list[Actuator] = []
        self.events: list[dict[str, Any]] = []
        self.power_temp: Optional[dict[str, Any]] = None
        self.power_bias = 0.0
        self.snapshot: list[dict[str, Any]] = []
        self.power_snapshot: Optional[float] = None
        self.minute = float(self.start)

    # -- writes ------------------------------------------------------------ #

    def send(self, device: Device, method: str, path: str, body: Any = None) -> Any:
        """A write, skipped in a dry run."""
        if self.dry_run:
            if self.verbose:
                print(f"      would {method} {device.label}{path} {json.dumps(body)}")
            return None
        if self.verbose:
            print(f"      {method} {device.label}{path} {json.dumps(body)}")
        return device.request(method, path, body)

    # -- discovery --------------------------------------------------------- #

    def load_probes(self) -> None:
        """Read the probes and their raw readings, and pin the water to them."""
        answer = self.hub.get("/sim/probes")
        if not isinstance(answer, dict) or "probes" not in answer:
            raise SystemExit(
                f"{self.hub.label} does not answer GET /sim/probes: is it a "
                "ReefControl, served by an up-to-date simulator?"
            )
        self.snapshot = [dict(p) for p in answer["probes"]]
        self.probes = [
            Probe(str(p["type"]), str(p["uid"]), dict(p)) for p in answer["probes"]
        ]
        if not self.probes:
            raise SystemExit(f"{self.hub.label} has no probe to animate.")

        declared = self.scenario.get("water") or {}

        def first(ptype: str, key: str) -> Optional[float]:
            for probe in self.probes:
                value = probe.raw.get(key)
                if probe.ptype == ptype and isinstance(value, (int, float)):
                    return float(value)
            return None

        temperature = first("temperature", "value")
        if temperature is None:
            temperature = next(
                (
                    float(p.raw["temp"])
                    for p in self.probes
                    if isinstance(p.raw.get("temp"), (int, float))
                ),
                25.0,
            )
        ato = next((p for p in self.probes if p.ptype == "ato"), None)
        self.water = {
            "temperature": float(declared.get("temperature", temperature)),
            "ph": float(declared.get("ph", first("ph", "value") or 8.1)),
            "orp": float(declared.get("orp", first("orp", "value") or 250)),
            "ec": float(declared.get("ec", first("ec", "value") or 53.0)),
            "level": float(
                declared.get(
                    "level",
                    mark_level(ato.raw.get("water_level")) if ato else 1.5,
                )
            ),
        }
        self.ec_reference_level = self.water["level"]

        # A probe keeps reading its own distance from the water: without a
        # declared starting point, that is 0 for the first probe of a kind and
        # the spread the fixtures carry for the others.
        for probe in self.probes:
            channel = PRIMARY_CHANNEL.get(probe.ptype)
            value = probe.raw.get("value")
            if channel and isinstance(value, (int, float)) and channel not in declared:
                probe.bias["value"] = float(value) - self.water[channel]
            temp = probe.raw.get("temp")
            if probe.ptype in HAS_TEMP and isinstance(temp, (int, float)):
                if "temperature" not in declared:
                    probe.bias["temp"] = float(temp) - self.water["temperature"]
            probe.unplugged = probe.raw.get("status") == "disconnected"

        if self.power is not None:
            answer = self.power.get("/sim/temperature")
            if isinstance(answer, dict):
                self.power_temp = answer
                if answer.get("installed"):
                    self.power_snapshot = float(answer["value"])
                    self.power_bias = self.power_snapshot - self.water["temperature"]

    def find_probe(self, ref: Any) -> Probe:
        """A probe by uid, or the first one of a type."""
        text = str(ref)
        for probe in self.probes:
            if probe.uid.lower() == text.lower():
                return probe
        for probe in self.probes:
            if probe.ptype == text:
                return probe
        known = ", ".join(p.label for p in self.probes)
        raise SystemExit(f"No probe {ref!r} on the hub. Known: {known}")

    def load_actuators(self) -> None:
        for spec in self.scenario.get("actuators") or []:
            if "socket" in spec:
                kind, number = "socket", int(spec["socket"]) - 1
                if self.power is None:
                    raise SystemExit(
                        f"actuator {spec.get('name')!r} is on a socket, but no "
                        "power strip is set (power: in the scenario, or --power)."
                    )
            elif "port" in spec:
                kind, number = "port", int(spec["port"]) - 1
            else:
                raise SystemExit(f"actuator {spec!r} needs a `socket` or a `port`.")
            effect = {str(k): float(v) for k, v in (spec.get("effect") or {}).items()}
            for channel in effect:
                if channel not in CHANNELS:
                    raise SystemExit(
                        f"actuator {spec.get('name')!r}: unknown effect "
                        f"{channel!r}, expected one of {', '.join(CHANNELS)}"
                    )
            watts = spec.get("watts")
            self.actuators.append(
                Actuator(
                    name=str(spec.get("name", f"{kind} {number + 1}")),
                    kind=kind,
                    number=number,
                    watts=None if watts is None else float(watts),
                    effect=effect,
                )
            )

    def load_events(self) -> None:
        """Place every event on the simulated timeline, in order."""
        events = []
        for event in self.scenario.get("events") or []:
            at = event.get("at")
            if at is None:
                raise SystemExit(f"event {event!r} needs an `at`.")
            if str(at).startswith("+"):
                when = self.start + parse_clock(at)
            else:
                # A clock time: its first occurrence from the start, on the
                # given day of the run (1 = the first)
                day = int(event.get("day", 1)) - 1
                when = self.start + (parse_clock(at) - self.start) % DAY + day * DAY
            events.append(dict(event, _when=when))
        self.events = sorted(events, key=lambda e: e["_when"])

    # -- setup ------------------------------------------------------------- #

    def rule(self, spec: dict[str, Any]) -> dict[str, Any]:
        """A probe rule, in the hub's words, from its scenario form."""
        probe = self.find_probe(spec["probe"])
        body: dict[str, Any] = {
            "type": probe.ptype,
            "uid": probe.uid,
            "sensor": str(spec.get("sensor", "primary")),
            "default_state": str(spec.get("default", "off")) == "on",
        }
        if probe.ptype == "ato":
            return body
        if probe.ptype != "leak":
            body["is_above"] = str(spec.get("when", "above")) == "above"
            body["value"] = float(spec["value"])
            body["hysteresis"] = float(spec.get("hysteresis", 0))
        body["trigger_op"] = str(spec.get("turn", "on")) == "on"
        return body

    def setup(self) -> None:
        """Configure the outputs the scenario lists, as the app would."""
        setup = self.scenario.get("setup") or {}
        for spec in setup.get("sockets") or []:
            if self.power is None:
                raise SystemExit("`setup.sockets` needs a power strip.")
            self.setup_socket(spec)
        for spec in setup.get("ports") or []:
            self.setup_port(spec)

    def setup_socket(self, spec: dict[str, Any]) -> None:
        assert self.power is not None
        number = int(spec["socket"]) - 1
        mode = str(spec.get("mode", "on"))
        print(f"  socket {number + 1}: {spec.get('name', '')} -> {mode}")
        if mode == "sensor":
            rule = self.rule(spec)
            # The order the ReefBeat app uses: the strip learns which probe
            # type to follow, then its mode; the hub keeps the probe and the
            # thresholds under the strip's socket number.
            self.send(
                self.power,
                "PUT",
                "/subscribe",
                {
                    "sockets": [
                        {
                            "number": number,
                            "default_state": rule["default_state"],
                            "app_cache": rule["type"],
                        }
                    ]
                },
            )
            self.send(self.hub, "PUT", f"/socket/{number}/subscribe", rule)
        elif mode == "schedule":
            self.send(
                self.power,
                "PUT",
                f"/socket/{number}/config/schedule",
                {"intervals": intervals(spec.get("schedule"))},
            )
        entry: dict[str, Any] = {"number": number, "mode": mode}
        if spec.get("name"):
            entry["name"] = str(spec["name"])
        self.send(self.power, "PUT", "/sockets/config", {"sockets": [entry]})

    def setup_port(self, spec: dict[str, Any]) -> None:
        number = int(spec["port"]) - 1
        mode = str(spec.get("mode", "on"))
        print(f"  port {number + 1}: {spec.get('name', '')} -> {mode}")
        # A factory-fresh port refuses every write until installed
        self.send(self.hub, "POST", f"/port/{number}/install", {"type": "other"})
        if mode == "sensor":
            rule = self.rule(spec)
            self.send(
                self.hub,
                "PUT",
                "/ports/subscribe",
                {"ports": [dict(rule, number=number)]},
            )
        elif mode == "schedule":
            self.send(
                self.hub,
                "PUT",
                f"/port/{number}/schedule",
                {"intervals": intervals(spec.get("schedule"))},
            )
        entry: dict[str, Any] = {
            "number": number,
            "mode": mode,
            "power_on_percent": int(spec.get("power", 100)),
        }
        if spec.get("name"):
            entry["name"] = str(spec["name"])
        self.send(self.hub, "PUT", "/ports/config", [entry])

    def push_watts(self) -> None:
        """Tell the simulator what each actuator draws while powered."""
        for device, kind in ((self.power, "socket"), (self.hub, "port")):
            table = {
                str(a.number): a.watts
                for a in self.actuators
                if a.kind == kind and a.watts is not None
            }
            if device is not None and table:
                self.send(device, "PUT", "/sim/watts", {"watts": table})

    # -- one step ---------------------------------------------------------- #

    def read_outputs(self) -> None:
        """Which actuators are powered, as the devices decide it now.

        Reading the dashboards is what makes the simulator evaluate the
        schedules and the probe rules against the current readings.
        """
        sockets: list[Any] = []
        ports: list[Any] = []
        if self.power is not None:
            sockets = (self.power.get("/dashboard") or {}).get("sockets") or []
        ports = (self.hub.get("/dashboard") or {}).get("ports") or []
        for actuator in self.actuators:
            outputs = sockets if actuator.kind == "socket" else ports
            entry = next(
                (
                    o
                    for o in outputs
                    if isinstance(o, dict) and o.get("number") == actuator.number
                ),
                None,
            )
            actuator.on = bool(entry) and entry.get("state") == "on"

    def target(self, channel: str) -> Optional[float]:
        """Where a quantity drifts to at the current simulated time."""
        spec = self.physics.get(channel) or {}
        toward = spec.get("toward")
        if toward is None:
            return None
        if toward == "ambient":
            return self.ambient_temperature()
        if isinstance(toward, dict):
            start = parse_clock(toward.get("from", "09:00"))
            end = parse_clock(toward.get("to", "21:00"))
            key = "day" if in_window(self.minute, start, end) else "night"
            return float(toward[key])
        return float(toward)

    def ambient_temperature(self) -> float:
        """Room air: a sine over the day, peaking at `peak`."""
        mean = float(self.ambient.get("mean", 24))
        swing = float(self.ambient.get("swing", 0))
        peak = parse_clock(self.ambient.get("peak", "15:00"))
        phase = 2 * math.pi * ((self.minute - peak) % DAY) / DAY
        return mean + swing * math.cos(phase)

    def advance(self, minutes: float) -> None:
        """Move the water forward by `minutes` of simulated time."""
        hours = minutes / 60.0
        for channel in CHANNELS:
            spec = self.physics.get(channel) or {}
            value = self.water[channel]
            goal = self.target(channel)
            rate = float(spec.get("rate", 0))
            if goal is not None and rate > 0:
                # Exact exponential approach, stable whatever the step
                value += (goal - value) * (1 - math.exp(-rate * hours))
            if channel == "level":
                value -= float(spec.get("evaporation", 0)) * hours
            value += sum(
                a.effect.get(channel, 0.0) * hours for a in self.actuators if a.on
            )
            self.water[channel] = value
        self.water["level"] = max(0.0, min(LEVEL_MAX, self.water["level"]))

    def reading(self, channel: str, bias: float) -> float:
        """What a probe of a quantity reports: water, bias and a little noise."""
        value = self.water[channel] + bias
        if channel == "ec":
            per_level = float((self.physics.get("ec") or {}).get("per_level", 0))
            # Evaporation concentrates the salt, a top-up dilutes it back
            value += per_level * (self.ec_reference_level - self.water["level"])
        noise = float((self.physics.get(channel) or {}).get("noise", 0))
        if noise:
            value += self.random.gauss(0, noise)
        return round(value, DIGITS.get(channel, 2))

    def write_probes(self) -> None:
        for probe in self.probes:
            if probe.ptype == "leak" or probe.unplugged:
                continue
            body: dict[str, Any] = {}
            channel = PRIMARY_CHANNEL.get(probe.ptype)
            if channel:
                body["value"] = self.reading(channel, probe.bias.get("value", 0.0))
                if probe.ptype == "orp":
                    body["value"] = int(body["value"])
            if probe.ptype in HAS_TEMP:
                body["temp"] = self.reading("temperature", probe.bias.get("temp", 0.0))
            if probe.ptype == "ato":
                body["water_level"] = level_mark(self.water["level"])
            if probe.ptype == "ec":
                ppt = body["value"] * PPT_PER_MS
                body["ppt"] = round(ppt, 1)
                body["sg"] = round(1 + ppt * SG_PER_PPT, 4)
            self.send(
                self.hub,
                "PUT",
                f"/sim/probe?type={probe.ptype}&uid={probe.uid}",
                body,
            )
        if (
            self.power is not None
            and self.power_temp
            and self.power_temp.get("installed")
            and self.power_probe == "water"
        ):
            value = self.reading("temperature", self.power_bias)
            self.send(self.power, "PUT", "/sim/temperature", {"value": value})

    # -- events ------------------------------------------------------------ #

    def play_due_events(self) -> None:
        while self.events and self.events[0]["_when"] <= self.minute:
            self.play_event(self.events.pop(0))

    def play_event(self, event: dict[str, Any]) -> None:
        label = event.get("name") or ", ".join(
            k for k in event if not k.startswith("_") and k not in ("at", "day")
        )
        print(f"  [{fmt_clock(event['_when'])}] {label}")
        if event.get("say"):
            print(f"      {event['say']}")
        if "leak" in event:
            spec = event["leak"]
            if not isinstance(spec, dict):
                spec = {"status": spec}
            status = LEAK_STATUSES.get(str(spec.get("status", "aquarium")))
            if status is None:
                raise SystemExit(f"unknown leak status {spec.get('status')!r}")
            probe = self.find_probe(spec.get("probe", "leak"))
            self.send(
                self.hub,
                "PUT",
                f"/sim/probe?type={probe.ptype}&uid={probe.uid}",
                {"leak_status": status},
            )
        for key, status in (("unplug", "disconnected"), ("plug", "auto")):
            if key in event:
                refs = event[key] if isinstance(event[key], list) else [event[key]]
                for ref in refs:
                    probe = self.find_probe(ref)
                    probe.unplugged = status == "disconnected"
                    self.send(
                        self.hub,
                        "PUT",
                        f"/sim/probe?type={probe.ptype}&uid={probe.uid}",
                        {"status": status},
                    )
        for channel, value in (event.get("set") or {}).items():
            self._check_channel(channel)
            self.water[channel] = float(value)
        for channel, delta in (event.get("nudge") or {}).items():
            self._check_channel(channel)
            self.water[channel] += float(delta)
        if "bias" in event:
            # A probe drifting away from the others, as a dirty or failing
            # one does: `sensor` is `value` (its main reading) or `temp`
            spec = event["bias"]
            probe = self.find_probe(spec["probe"])
            sensor = str(spec.get("sensor", "value"))
            probe.bias[sensor] = probe.bias.get(sensor, 0.0) + float(spec["delta"])
        if event.get("dismiss_buzzer"):
            self.send(self.hub, "PUT", "/sim/buzzer", {"dismissed": True})

    @staticmethod
    def _check_channel(channel: str) -> None:
        if channel not in CHANNELS:
            raise SystemExit(
                f"unknown quantity {channel!r}, expected one of {', '.join(CHANNELS)}"
            )

    # -- reporting --------------------------------------------------------- #

    def status_line(self) -> str:
        w = self.water
        on = [a.name for a in self.actuators if a.on] or ["-"]
        return (
            f"  {fmt_clock(self.minute):>9}  "
            f"air {self.ambient_temperature():5.2f}  "
            f"T {w['temperature']:5.2f}  pH {w['ph']:4.2f}  "
            f"ORP {w['orp']:5.0f}  EC {self.reading_quiet('ec'):5.2f}  "
            f"{level_mark(w['level']):<15}  on: {', '.join(on)}"
        )

    def reading_quiet(self, channel: str) -> float:
        per_level = float((self.physics.get("ec") or {}).get("per_level", 0))
        return self.water["ec"] + per_level * (
            self.ec_reference_level - self.water["level"]
        )

    def show(self) -> int:
        """Print what the scenario is about to drive, and exit."""
        print(f"Hub:   {self.hub.label} ({self.hub.url})")
        if self.power is not None:
            installed = bool(self.power_temp and self.power_temp.get("installed"))
            print(
                f"Power: {self.power.label} ({self.power.url})"
                f"{', local probe installed' if installed else ''}"
            )
        print("\nWater at start:")
        for channel in CHANNELS:
            print(f"  {channel:<12} {self.water[channel]:g}")
        print("\nProbes (bias from the water):")
        for probe in self.probes:
            bias = ", ".join(f"{k} {v:+.2f}" for k, v in probe.bias.items()) or "-"
            state = " unplugged" if probe.unplugged else ""
            print(f"  {probe.label:<18} {bias}{state}")
        print("\nActuators:")
        for actuator in self.actuators:
            effect = ", ".join(f"{k} {v:+g}/h" for k, v in actuator.effect.items())
            watts = f"{actuator.watts:g} W" if actuator.watts is not None else "-"
            print(f"  {actuator.label:<30} {watts:>7}  {effect}")
        print("\nEvents:")
        for event in self.events:
            keys = [
                k for k in event if not k.startswith("_") and k not in ("at", "day")
            ]
            print(f"  {fmt_clock(event['_when']):>9}  {', '.join(keys)}")
        real = self.duration / self.speed
        print(
            f"\n{fmt_clock(self.start)} + {self.duration // 60} h at "
            f"{self.speed:g} min/s: about {real / 60:.1f} real minutes."
        )
        return 0

    # -- driver ------------------------------------------------------------ #

    def restore(self) -> None:
        """Give the probes, the clock and the consumption back."""
        if self.dry_run:
            return
        for raw in self.snapshot:
            body = {
                k: v
                for k, v in raw.items()
                if k not in ("type", "uid") and v is not None
            }
            if raw.get("type") == "leak":
                body = {
                    "leak_status": raw.get("leak_status", "dry"),
                    "status": raw.get("status", "auto"),
                }
            self.hub.put(f"/sim/probe?type={raw['type']}&uid={raw['uid']}", body)
        if self.power is not None and self.power_snapshot is not None:
            self.power.put("/sim/temperature", {"value": self.power_snapshot})
        self.hub.put("/sim/clock", {"minute": None})
        for device in (self.hub, self.power):
            if device is not None:
                device.put("/sim/watts", {"watts": {}})
        print("Restored the probe readings, the clock and the consumption.")

    def run(self, loop: bool = False) -> int:
        if self.scenario.get("setup"):
            print("Setup:")
            self.setup()
        self.push_watts()
        step = self.speed * self.tick
        try:
            while not self.stopper.stopped:
                self.minute = float(self.start)
                end = self.start + self.duration
                self.load_events()
                print(f"Running {fmt_clock(self.start)} -> {fmt_clock(end)}")
                while not self.stopper.stopped and self.minute < end:
                    self.send(
                        self.hub, "PUT", "/sim/clock", {"minute": int(self.minute)}
                    )
                    self.read_outputs()
                    self.advance(step)
                    self.minute += step
                    self.play_due_events()
                    self.write_probes()
                    print(self.status_line())
                    self.stopper.sleep(self.tick)
                if not loop:
                    break
                print("  -- looping --")
        finally:
            self.restore()
        return 0


# --------------------------------------------------------------------------- #
#   Entry point
# --------------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Play a day of reef life on a simulated ReefControl.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--scenario", required=True, help="scenario (.yaml or .json)")
    parser.add_argument("--hub", help="hub URL or simulator device name")
    parser.add_argument("--power", help="power strip URL or simulator device name")
    parser.add_argument(
        "--no-power", action="store_true", help="ignore the power strip entirely"
    )
    parser.add_argument(
        "--sim-config",
        default=DEFAULT_SIM_CONFIG,
        help="simulator config.json, to resolve device names (default: %(default)s)",
    )
    parser.add_argument("--speed", type=float, help="simulated minutes per second")
    parser.add_argument("--start", help="simulated start time, HH:MM")
    parser.add_argument("--duration", help="simulated duration, HH:MM")
    parser.add_argument(
        "--no-setup", action="store_true", help="skip the `setup` block"
    )
    parser.add_argument("--show", action="store_true", help="print the plan and exit")
    parser.add_argument("--loop", action="store_true", help="replay until Ctrl-C")
    parser.add_argument(
        "--dry-run", action="store_true", help="read the devices, write nothing"
    )
    parser.add_argument("--verbose", action="store_true", help="print every write")
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    for key in ("speed", "start", "duration"):
        if getattr(args, key) is not None:
            scenario[key] = getattr(args, key)
    if args.no_setup:
        scenario.pop("setup", None)

    hub_ref = args.hub or scenario.get("hub")
    if not hub_ref:
        parser.error("no hub: pass --hub, or set `hub:` in the scenario")
    hub_url, hub_label, hub_conf = resolve_device(str(hub_ref), args.sim_config)
    hub = Device(hub_url, hub_label)

    power: Optional[Device] = None
    power_ref = (
        None
        if args.no_power
        else (args.power or scenario.get("power") or hub_conf.get("paired_with"))
    )
    if power_ref:
        power_url, power_label, _ = resolve_device(str(power_ref), args.sim_config)
        power = Device(power_url, power_label)

    timelapse = Timelapse(
        scenario, hub, power, dry_run=args.dry_run, verbose=args.verbose
    )
    timelapse.load_probes()
    timelapse.load_actuators()
    timelapse.load_events()

    if scenario.get("name"):
        print(f"Scenario: {scenario['name']}")
    if args.show:
        return timelapse.show()
    if args.dry_run:
        print("(dry run: the devices are read, nothing is written)")
    return timelapse.run(loop=args.loop)


if __name__ == "__main__":
    sys.exit(main())
