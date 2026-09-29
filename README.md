# reefbeat-devices-simulator

Simulate ReefBeat devices like ReefATO+, ReefDose, ReefLed, ReefRun, ReefWave,
ReefControl (Lite/Pro) and ReefPower (6/8-socket)

This repo has two distinct parts:

| Part             | Entrypoint            | Reads                              | Writes               | Purpose                                       |
| ---------------- | --------------------- | ---------------------------------- | -------------------- | --------------------------------------------- |
| Simulator        | `reefbeat-devices.py` | `config.json`, `devices/` fixtures | In-memory state only | Serve fixtures over HTTP like real devices    |
| Fixture exporter | `run.py`              | Real device/cloud endpoints        | `devices/` fixtures  | Capture + sanitize fixtures for the simulator |

Typical workflow:

1. Use `run.py` to export/sanitize fixtures into `devices/`.
2. Run `reefbeat-devices.py` to serve those fixtures as simulated devices.

---

## Installation

Both tools use the same Python environment and dependencies.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional .env file for cloud access (used by `run.py`):

```text
REEFBEAT_USERNAME=you@example.com
REEFBEAT_PASSWORD=yourpassword
```

## Simulator (Serve Fixtures)

`reefbeat-devices.py` runs the actual simulator.

It starts one HTTP server per configured device and serves responses from the
fixture tree under `devices/`.

Requests that include a JSON payload (POST/PUT) can either:

- Merge the payload into the in-memory state (using `jsonmerge`), or
- Trigger a configured `post_action` that computes a derived update.

---

### Usage

Run from the repo root so it can find `config.json` and the `devices/` tree:

```bash
./reefbeat-devices.py
```

Notes:

- If you bind to port `80` or need to add the configured IP to the host, you’ll
  typically need root privileges. The script attempts to re-run itself via
  `sudo` if startup fails.
- The IP auto-add logic is Linux-focused and assumes the interface is `eth0`
  (it uses `ip addr show/add`).

---

### Configuration (`config.json`)

The simulator reads `config.json` and expects a top-level `devices` array.
Each entry controls a single device server:

- `enabled`: Whether to start the server.
- `name`: Label used in logs.
- `base_url`: Fixture root for the device (e.g. `devices/DOSE4`).
- `ip` / `port`: Bind address.
- `access`: Per-endpoint HTTP method allow-list.
  - `no_GET`: List of paths that must not allow GET.
  - `PUT` / `POST`: Optional lists of paths that allow those methods.
- `post_actions`: Optional computed updates keyed by request path.
- `tls`: Serve over HTTPS (the cloud account). The certificate is
  `tls_cert` / `tls_key` when given, else a self-signed one made once with
  `openssl` under `config/tls/`.
- `username` / `password` (cloud account): credentials the token endpoint
  checks; left out, any credentials are accepted.
- `devices` (cloud account): names of the simulated devices the account
  lists; left out, the ReefLEDs.

`post_actions` example conceptually:

```jsonc
{
  "request": "/head/1/manual",
  "action": {
    "target": "/dashboard",
    "action": "{...python expression...}"
  }
}
```

Security note: `action` is evaluated with `eval()`. Only run configs you trust.

---

### Fixture Layout

The simulator serves one fixture file per endpoint:

```text
devices/<TYPE>/<endpoint>/data
```

For example:

```text
devices/DOSE4/device-info/data
devices/DOSE4/dashboard/data
devices/DOSE4/description.xml/data
```

`description.xml` is served as raw text; other endpoints are served as JSON.

---

### Device-Specific Write Behaviour

Some settings are written to one endpoint but reported on another, because the
real firmware exposes them twice under different names. For those, merging the
payload into the endpoint that received it is not enough: the simulator also
projects the write onto the endpoint a client polls.

| Device   | Write               | Also updates | Fields                                                                              |
| -------- | ------------------- | ------------ | ----------------------------------------------------------------------------------- |
| ReefRun  | `PUT /pump/settings` | `/dashboard` | Every field the two payloads share (`name`, `type`, `model`, `sensor_controlled`, …) |
| ReefATO+ | `PUT /configuration` | `/dashboard` | `leak.sensor_enabled` → `leak_sensor.enabled`, `buzzer.enabled` → `leak_sensor.buzzer_enabled` |

The ReefATO+ mapping is what makes the leak-sensor and buzzer enable/disable
switches usable against the simulator: they are written as `leak` and `buzzer`
on `/configuration`, but read back from `leak_sensor` on the polled
`/dashboard`. Partial payloads are supported, as on the device — a key left out
of the request keeps its previous value.

`leak_sensor.buzzer_on` is recomputed on each such write: the buzzer only
sounds while the probe is wet (`status` other than `dry`) **and** both the probe
and the buzzer are enabled, so disabling either one silences a ringing alarm.

---

### ReefATO+ Manual Fill

`POST /manual-pump` and `POST /stop` are simulated end to end, so the fill and
stop-fill buttons of a client can be exercised against the fixtures.

`is_pump_on` is the authoritative field — it goes `true` on `/manual-pump` and
`false` on `/stop`. `pump_state` and `prev_pump_state` are kept in step with it
so the three never contradict each other, and `last_pump_on_cause` becomes
`manual`.

While the pump runs, each `GET /dashboard` accounts the water dispensed since
the previous one:

| Field                                      | Behaviour                                                     |
| ------------------------------------------ | ------------------------------------------------------------- |
| `volume_left`                               | decreases, floored at 0                                       |
| `today_volume_usage` / `total_volume_usage` | increase by the same amount                                   |
| `today_fills` / `total_fills`               | increase by one when the fill ends                            |
| `last_fill_date`                            | set to the current epoch when the fill ends                   |

The volume comes from `flow_rate` on `/dashboard`, read as **milliliters per
minute** (`ATO_FLOW_RATE_PERIOD_S` in `reefbeat-devices.py` if that ever needs
revisiting). The fractional remainder is carried across polls, so a client
polling every second and one polling once dispense the same volume.

The pump stops on its own after `custom_pump_time` from `/configuration`
(30 s by default), or as soon as `volume_left` reaches 0. A fill only advances
when `/dashboard` is polled, so nothing runs away while no client is watching,
and polling faster does not dispense more water.

`days_till_empty` is deliberately left untouched: the firmware derives it from
a running average this simulator does not keep.

### ReefControl Hub (RSCONTROL Pro / Lite)

Handled in `function_extension/rs_control.py`. The probe state lives in
`/dashboard`'s `probes` list as canonical records (raw readings plus private
`_`-prefixed book-keeping); every endpoint projects what the firmware exposes.

| Area | Endpoints | Behaviour |
| ---- | --------- | --------- |
| Probes | `POST /probe/install?type=`, `POST /ble/off`, `PUT /probe/config` (array), `GET /probe/config`, `GET /probe?type&uid`, `GET /probe/info`, `POST\|DELETE /probe/disable`, `DELETE /probe`, `DELETE /setup-probes` | A new probe stays in `setup` until configured. A leak probe only takes its name in `/probe/config` (flags: 503). `GET /probe` answers in the per-type shape of a real hub. |
| Offsets | `GET\|POST\|DELETE /probe/offset?type&uid` | For the reading of temperature and ORP probes and the embedded temperature of pH, EC and ATO probes. `POST` **adds** to the current offset (captured), whole millivolts for ORP; every reading includes it. |
| Multi-point calibration | `POST /probe/calibration-enter`, `POST /probe/calibration-point-start`, `GET /probe/calibration-status`, `POST /probe/calibration-exit`, `GET /probe/calibration-log`, `POST /probe/calibration-restore`, `POST /probe/calibration-factory-reset` | pH (LOW / MID / HIGH) and EC (MID). A point is `in_progress` for `calibration_seconds` (device config, 180 s by default, as the ReefBeat app expects), with `time_left` and `stability_progress`, then `success`, or `fail_check_solution` (pH solution out of 3.5-4.5 / 6.5-7.5 / 9-10.5) / `fail_value_error` (EC out of 20-99). Exiting after a successful point dates the calibration (`last_adjustment_date`). |
| Leaks | `GET /probe?type=leak`, `GET\|PUT /leak/config`, `PUT /configuration` | `leak_status` (`dry`, `aquarium_water_leak`, `rodi_water_leak`) and the conductivity it measured. `leak_detector` is kept in step on `/configuration`, `/leak/config` and `/dashboard`. |
| Buzzer | `/dashboard.buzzer` | Sounds for a wet leak probe (detector and leak buzzer on) or a probe in danger with its buzzer on (danger buzzer on). `cause` is `leak`, `danger` or `none` (names not captured). A dismissed buzzer stays silent until the cause clears. |
| 12V ports | `PUT /ports/config` (array), `POST /port/<n>/install`, `DELETE /port/<n>`, `GET\|PUT /port/<n>/schedule`, `POST /port/<n>/toggle`, `PUT /ports/subscribe` | An uninstalled port answers 503. The state follows the schedule (`schedule` mode) or the probe rule (`sensor` mode), with hysteresis; a toggle from `off` returns to the previous automatic mode. |
| RSPower link | `POST /power/discover {"pair"}`, `POST /power/unpair`, `PUT /socket/<n>/subscribe`, `PUT /socket/<n>/unsubscribe`, `GET /subscription-info` | Pairs with the strip named in `paired_with` when it is free (no hub, no local probe), else the first free strip; both dashboards report each other. Unpairing drops the socket rules. |
| Misc | `POST /setup-finish`, `/sensor-log`, `/temperature-log` | `setup-finish` moves `/mode` and `/dashboard` to `auto`. |

Unplugged probe: `status` `disconnected` on `/dashboard`, and 503 on every
request about it (`GET /probe`, `/probe/offset`, calibration), as on a real
hub.

### ReefPower Strips (RSPOWER 6 / 8)

Handled in `function_extension/rs_power.py`, besides the fixture machinery
(toggles, schedules):

- `PUT /sockets/config` is partial, as on the strip: only the sockets sent
  change, merged by `number` into `/sockets/config` and mirrored onto
  `/dashboard` (a plain merge used to replace the whole `sockets` list);
- `DELETE /socket/<n>/config` puts the socket back to setup (`S<n+1>`) on
  both, and it stops following the local probe; the rule a paired hub keeps
  for it is removed on the hub (`PUT /socket/<n>/unsubscribe`);

- sockets in `schedule` mode follow the clock; sockets in `sensor` mode
  follow the rule the paired hub keeps for them (`/subscription-info`), else
  the rule of the local probe (`/temperature/subscriptions`), else their
  `default_state`;
- local temperature probe: `POST /sensor/install` (refused while paired
  with a hub: a strip takes one or the other), `DELETE /sensor`,
  `/temperature/config`, `/temperature/subscribe`, `/temperature`,
  `/temperature/log`, `/temperature-probe-info`, all 404 without a probe;
  `POST /probe/offset` **adds** to the offset;
- `DELETE /paired-device` unpairs both sides; `PUT /subscribe` records the
  probe type a socket follows, `PUT /unsubscribe {"sockets": [n]}` forgets
  it; `POST /setup-finish`.

Devices reach each other through `function_extension/registry.py`: all the
simulated devices run in one process.

### ReefLED Lamps (G1 / G2)

Handled in `function_extension/rs_led.py`, for the three lamps of
`config.json` (`LED_G1_160`, `LED_G2` an RSLED115, `LED_G1_90`), so a virtual
LED of the integration can group them:

- the week of programs, one per ISO weekday, written in the ReefBeat app's
  order: `POST /preset_name/<day>` `{"name"}`, the clouds, `POST /auto/<day>`,
  then `POST /auto/apply`. A program replaces the day's one as a whole:
  `{white, blue, moon}` on a G1, `{color, moon}` on a G2 (`color` points
  `{t, i1, k1, i2, k2}`), with its clouds inside on a G2 (also read back on
  `/clouds/<day>`);
- `POST /clouds/<day>` `{from, to, intensity, cloud_duration,
  no_cloud_duration}`; `DELETE /clouds/<day>` removes them (read back as
  `{}`);
- a program name lands on the endpoints the firmware has: per day
  (`/preset_name/<day>`), in the list (`/preset_name`), or both. The write is
  accepted even when only the list exists, as the app sends it to every lamp;
- the light follows the program: in `auto` mode `/manual` and the
  dashboard's `manual` give the levels of today's program at the current
  time (yesterday's one when it runs past midnight, the week wrapping from
  Sunday to Monday), dimmed while a cloud passes (Low 75 %, Medium 55 %,
  High 35 % of the light, for `cloud_duration` minutes every
  `cloud_duration + no_cloud_duration`) and during an acclimation. A G2
  reports its intensity and colour temperature, and white/blue sensors
  derived from them. The dashboard's `current_program` shows today's name;
- `POST /manual` (white/blue/moon, or kelvin/intensity on a G2) and
  `POST /timer` set the levels by hand and the mode; `POST /mode`;
  `POST /acclimation` and `/moonphase` are mirrored on the dashboard;
  `POST /identify`.

The lamps follow the clock of `/sim/clock`, like the schedules of the other
devices: pin it to watch a program play at any time of day.

### Cloud Account

Handled in `function_extension/rs_cloud.py`: the `CLOUD` entry of
`config.json` serves a ReefBeat account over HTTPS (port 443, self-signed
certificate), as `cloud.reef-beat.com` does. In ha-reefbeat-component,
create the local flag file that lets the account form ask for its server
(git-ignored, as for ha-aquamedic-component):

```bash
cp custom_components/redsea/simulator_enabled.example custom_components/redsea/.simulator_enabled
```

Restart Home Assistant, add a *ReefBeat Cloud API* device and give the
simulator's address (`192.168.0.251`) as the cloud server: any credentials
are accepted unless `username`/`password` are set.

| Request | Answer |
| ------- | ------ |
| `POST /oauth/token` | A bearer token (form body, password grant). |
| `GET /user`, `/aquarium` | Fixtures (`devices/CLOUD`): a sanitized user and one aquarium. |
| `GET /device` | The simulated devices, built from their `/device-info` (hwid, model, IP, firmware), all in the aquarium: the lamps by default, or the `devices` of the config. |
| `GET /reef-lights/library?include=all` | G1 programs `{id, uid, aquarium_id, aquarium_uid, name, program, clouds}`: the Red Sea ones (12K … 23K) and a user one. |
| `GET /v2/reef-lights/library` | G2 programs `{id, name, color, moon, clouds}`. |
| `POST <library>` | Adds a program (new `uid` / `id`), `201`. |
| `PUT <library>/<uid>` | Updates one: the whole program is sent, clouds left out are removed. |
| `DELETE <library>/<uid>` | Removes one. |
| `GET /reef-wave/library`, `/reef-dosing/supplement` | Fixtures. |
| `GET /firmware/api/<type>/latest` | The firmware the simulated devices of that type run: no update is offered. |

With the lamps linked to this account, the reef card's program editor lists
the library, saves new programs and updates or deletes the user's ones,
without touching a real account. What is written stays in memory until the
simulator restarts.

### Simulator Controls

Endpoints that exist only in the simulator, to play a scenario:

| Request | Effect |
| ------- | ------ |
| `PUT /sim/probe?type=<t>&uid=<u>` | Set what a hub probe measures: `value`, `temp`, `water_level`, `leak_status`, `ppt`, `sg`; or unplug / plug it: `status` `disconnected` / `connected`. Raw values: offsets still apply. |
| `PUT /sim/buzzer` | `{"dismissed": true}`, as when the hub button is pressed. |
| `GET /sim/probes` (hub) | Raw readings of every hub probe, before offsets: what a scenario reads back and restores. |
| `GET\|PUT /sim/clock` (hub, strip or lamp) | `{"minute": 0-1439}` pins the clock the schedules follow, for every simulated device of the process; `{"minute": null}` goes back to the real time. |
| `PUT /sim/watts` (hub or strip) | `{"watts": {"<n>": W}}`: what 12V port / socket `n` (0-based) draws while powered, reported as its `consumption`; `{}` stops it. |
| `GET\|PUT /sim/temperature` (strip) | `{"value": °C}`: what the strip's local probe measures, before its offset. |

```bash
curl -X PUT "http://192.168.0.247/sim/probe?type=leak&uid=0x0032B" \
     -d '{"leak_status": "aquarium_water_leak"}'
```

An ATO rule (port or socket following an ATO probe) powers its output while the
probe reads `below`, whatever `trigger_op` the hub stored: the ReefBeat app
sends that rule without one.

### ReefControl Timelapse

`scripts/control_timelapse.py` plays a day of reef life on the simulated hub
and its strip, for a demo or a screen recording of the reef card. Unlike
`ato_timelapse.py`, which writes display values into Home Assistant, it drives
the simulator, so the whole chain runs as on real equipment: the probes move,
the hub rules switch the sockets and 12V ports, the powered outputs act back on
the water, and the probes move again. Home Assistant only sees what the
integration polls.

The water is a handful of physical quantities (`temperature`, `ph`, `orp`,
`ec`, `level`). Every probe reads one of them plus its own bias, so the
embedded temperatures of the pH, EC and ATO probes follow the temperature probe
a little apart, as real ones do. Each tick the script advances a virtual clock
(`speed` simulated minutes per second, pushed with `PUT /sim/clock` so the
schedules follow the simulated day), reads both dashboards (which makes the
simulator evaluate the rules), moves the water by its drift and by the effect
of each powered actuator, plays the events due, and writes the readings back.

```bash
cd scripts
./control_timelapse.py --scenario control_demo.yaml --show     # the plan
./control_timelapse.py --scenario control_demo.yaml --dry-run  # read only
./control_timelapse.py --scenario control_demo.yaml            # shoot
./control_timelapse.py --scenario control_demo.yaml --speed 4 --loop
```

`control_demo.yaml` is a commented example: 24 hours in about 3 minutes, with a
heater and a fan on the temperature probe, a kalk reactor on the pH probe, a
reverse-lit refugium, an ATO pump on 12V port 1 following the ATO probe, a
leak, an acknowledged alarm, an unplugged probe and a drifting sensor that the
temperature fusion flags.

| Scenario key | Meaning |
| ------------ | ------- |
| `hub`, `power` | URL or `config.json` device name; `power` defaults to the hub's `paired_with` (`--hub`, `--power`, `--no-power` override) |
| `start`, `duration`, `speed`, `tick`, `seed` | Simulated start time and length (`HH:MM`), simulated minutes per real second, real seconds per frame, noise seed |
| `ambient` | Room air: `mean`, `swing`, `peak` (a sine over the day) |
| `water` | Starting point of each quantity; anything left out is read from the probes |
| `physics.<quantity>` | `toward` (a number, `ambient`, or `{day, night, from, to}`), `rate` (share of the gap closed per hour), `noise`; `level.evaporation` (marks per hour), `ec.per_level` (mS/cm gained per mark evaporated) |
| `actuators` | `socket` (strip) or `port` (hub), numbered from 1; `watts`; `effect` per quantity, per hour while powered |
| `setup` | `sockets` / `ports` to configure first, through the app's endpoints: `mode` (`on`, `off`, `schedule` with `schedule: [{from, to}]`, `sensor` with `probe`, `sensor`, `when`, `value`, `hysteresis`, `turn`, `default`) and `name` |
| `events` | `at` (`HH:MM`, optionally with `day`, or `+HH:MM` from the start) and one or more of: `leak` (`aquarium`, `rodi`, `dry`), `unplug` / `plug`, `set` / `nudge` a quantity, `bias` a probe (`probe`, `sensor`, `delta`), `dismiss_buzzer`, `say` |

On exit the probe readings, the clock and the simulated consumption are
restored. What `setup` configured stays in the simulator: restart it to go back
to the fixtures. Lower the integration's scan interval of both devices for the
shoot, a few seconds.

### Tests

```bash
pip install pytest
python -m pytest tests
```

The tests build the devices from the fixtures without binding the
configured IPs; `tests/test_http.py` serves two of them on localhost, and
`tests/test_rs_cloud.py` the cloud account over HTTPS (it needs `openssl`).

## Fixture Exporter (Create Fixtures)

`run.py` is a Python-based fixture exporter for the ReefBeat Devices Simulator.

It snapshots:

- Local ReefBeat device HTTP endpoints (by IP)
- Optionally ReefBeat cloud account endpoints

All outputs are written under the devices/ directory, with one folder per
device type. Each endpoint is stored as a data file.

Payloads are sanitized to remove secrets and personal data while preserving
stable relationships (aquarium ↔ device ↔ user), making the fixtures safe
to commit and suitable for automated testing.

---

### Discover Devices (Scan Mode)

Cloud-only scan (fast, no LAN probing):

```python
python run.py scan
```

LAN scan using a CIDR:

```python
python run.py scan --cidr 192.168.1.0/24
```

The output looks like this:

```bash
❯ python run.py scan --cidr 192.168.1.1/24
INFO     : LAN scanning 192.168.1.1/24...
INFO     : Enriching scan results from cloud...
```

| From      | Aquarium      | Device            | Type        | IP           | Model    | FW     |
| --------- | ------------- | ----------------- | ----------- | ------------ | -------- | ------ |
| LAN       |               | RSATO+000000000   |             | 192.168.1.92 |          |        |
| LAN+CLOUD | 80g Frag Tank | RSATO+0000000000  | reef-ato    | 192.168.1.96 | RSATO+   | 1.11.1 |
| LAN+CLOUD | 80g Frag Tank | RSDOSE4-000000000 | reef-dosing | 192.168.1.94 | RSDOSE4  | 3.0.0  |
| LAN+CLOUD | 80g Frag Tank | RSMAT-0000000000  | reef-mat    | 192.168.1.95 | RSMAT500 | 1.10.2 |
| LAN+CLOUD | Reefer 200XL  | RSATO+0000000000  | reef-ato    | 192.168.1.98 | RSATO+   | 1.11.0 |
| LAN+CLOUD | Reefer 200XL  | RSDOSE2-000000000 | reef-dosing | 192.168.1.93 | RSDOSE2  | 3.0.0  |
| LAN+CLOUD | Reefer 200XL  | RSMAT-000000000   | reef-mat    | 192.168.1.97 | RSMAT250 | 1.10.2 |

Multiple CIDRs are supported:

```python
python run.py scan --cidr 192.168.1.0/24 --cidr 192.168.1.0/24
```

Scan output is displayed as a table showing:

- Aquarium
- Device name
- Device type
- IP address
- Model
- Firmware

---

### Snapshot a Local Device

Snapshot all supported endpoints from a device by IP:

```python
python run.py --ip 192.168.1.95
```

The device type is auto-detected from `/device-info`.

To force a specific device type:

```python
python run.py --ip 192.168.1.95 --type DOSE2
```

Resulting structure:

```text
devices/
  DOSE2/
    device-info/
      data
    firmware/
      data
    description.xml/
      data
    ...
```

Each endpoint is stored in its own directory containing a `data` file.

---

### Snapshot Cloud Fixtures Only

```python
python run.py --cloud
```

Cloud fixtures are written to:

```text
devices/CLOUD/
  user/
    data
  aquarium/
    data
  device/
    data
  meta.json
```

Identifiers are sanitized, but relationships between user, aquarium,
and device are preserved. The simulated account serves its own `/device`
list (the simulated devices), not an exported one.

---

### Sanitization & ID Stability

The script maintains a local sanitize-map file to keep identifiers stable
and unique across runs.

This ensures:

- aquarium_id matches across cloud and device payloads
- aquarium_uid and user_uid remain consistent
- device hwid, mac, ip, and serials are deterministic but anonymized

The sanitize map is local-only and should be gitignored:

```text
.reefbeat_sanitize_map.json
```

The file contains no recoverable personal data and exists only to keep
fixtures internally consistent for testing.

---

### Supported Device Types

```text
ATO
DOSE2
DOSE4
MAT
LED
RUN
WAVE
POWER6         (RSPOWER6, hw_type=reef-power, 6 AC sockets)
POWER8         (RSPOWER8, hw_type=reef-power, 8 AC sockets)
CONTROLPRO     (RSCONTROLPRO, hw_type=reef-control, 4-7 probes + 2x 12V)
CONTROLLITE    (RSCONTROLLITE, hw_type=reef-control, 2 probes + 1x 12V)
```

Existing fixture trees are also used to infer endpoint lists, allowing
snapshots to remain config-driven.

---

### Summary

```text
scan        → discover devices (LAN and/or cloud)
--ip        → snapshot a local device
--cloud     → snapshot cloud endpoints only
devices/    → final simulator fixture tree
```
