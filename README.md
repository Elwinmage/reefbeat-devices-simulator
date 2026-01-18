# reefbeat-devices-simulator
Simulate ReefBeat devices like ReefATO+, ReefDose, ReefLed,  ReefRun and ReefWave

## Simulator

`reefbeat-devices.py`

## Fixture Exporter

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

### Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional .env file for cloud access:

```text
REEFBEAT_USERNAME=you@example.com
REEFBEAT_PASSWORD=yourpassword
```

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
| LAN       |               | RSATO+000000000   |             | 192.168.1.92 |
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
