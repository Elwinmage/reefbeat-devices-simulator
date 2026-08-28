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
and device are preserved.

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
