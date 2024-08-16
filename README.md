### Ruckus SmartZone KPI Probe (REST API)

A simple Python script to log in to SmartZone, query core resources (APs, clients, alarms, cluster health), and print KPI-oriented summaries to support dashboard prototyping.

- Uses service ticket auth against the public REST API.
- SSL verification can be disabled for lab/test controllers.

#### Setup

```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

#### Configuration
Set via environment variables (defaults included for your lab):

- `RUCKUS_BASE_URL` (e.g., `https://3.12.57.221:8443`)
- `RUCKUS_USERNAME`
- `RUCKUS_PASSWORD`
- `RUCKUS_DOMAIN` (e.g., `System`)
- `RUCKUS_VERIFY_SSL` (`true`/`false`)
- `RUCKUS_API_VERSION` (e.g., `v9_1`, `v10_0`, `v12_0`) – optional; script will try a common list if not set.

Example (PowerShell):
```powershell
$env:RUCKUS_BASE_URL = "https://3.12.57.221:8443"
$env:RUCKUS_USERNAME = "apireadonly"
$env:RUCKUS_PASSWORD = "SBAedge2112#"
$env:RUCKUS_DOMAIN   = "System"
$env:RUCKUS_VERIFY_SSL = "false"
```

#### Run
```bash
python ruckus_kpi_probe.py
```

The script prints a compact summary: AP availability, top alarms, client counts, basic experience signals if exposed by the API, and placeholders for Level-2 KPIs (RxDesense, idle APs) where REST data is available in your firmware.

Notes:
- Some KPIs (RxDesense, per-radio utilization) can come from telemetry/MQTT or advanced REST endpoints depending on SmartZone version and licenses. This script fetches what’s broadly available; extend the `RuckusClient` to add site-specific endpoints.














