import os
import sys
import json
import warnings
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests import Session
from urllib3.exceptions import InsecureRequestWarning

# Lab/controller configuration (hardcoded)
RUCKUS_BASE_URL = "https://3.12.57.221:8443"
RUCKUS_USERNAME = "sshrivastava"
RUCKUS_PASSWORD = "SBAedge2112#"
RUCKUS_DOMAIN = "System"
RUCKUS_VERIFY_SSL = False
RUCKUS_API_VERSION = "v9_1"

# Verbose logging
LOG_VERBOSE = True


def log(message: str) -> None:
    if LOG_VERBOSE:
        print(f"[LOG] {message}")


# Suppress SSL warnings when VERIFY_SSL is false (lab environments)
warnings.simplefilter("ignore", InsecureRequestWarning)


def getenv_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "y"}


class RuckusClient:
    """Minimal SmartZone REST API client using serviceTicket auth."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        domain: str = "System",
        verify_ssl: bool = True,
        api_versions_to_try: Optional[List[str]] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.domain = domain or "System"
        self.session: Session = requests.Session()
        self.session.verify = verify_ssl
        self.service_ticket: Optional[str] = None
        # Force v9_1 for your environment
        self.api_version = RUCKUS_API_VERSION
        self.api_versions_to_try = [RUCKUS_API_VERSION]
        log(
            "Client initialized base_url="
            + self.base_url
            + " api_version="
            + self.api_version
        )

    def _api_root(self, version: str) -> str:
        return f"{self.base_url}/wsg/api/public/{version}"

    def _url(self, version: str, path: str) -> str:
        path = path.lstrip("/")
        return f"{self._api_root(version)}/{path}"

    def _headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/json"}

    def login(self) -> str:
        """
        Obtain a serviceTicket for the configured API version.
        v9.1 expects only username/password (no domain in payload).
        """
        last_err: Optional[str] = None
        for version in self.api_versions_to_try:
            try:
                payload = {
                    "username": self.username,
                    "password": self.password,
                }
                log(
                    "POST serviceTicket version="
                    + version
                    + " user="
                    + self.username
                )
                resp = self.session.post(
                    self._url(version, "serviceTicket"),
                    headers=self._headers(),
                    data=json.dumps(payload),
                    timeout=20,
                )
                log("serviceTicket status=" + str(resp.status_code))
                if resp.status_code == 200:
                    body = resp.json()
                    self.service_ticket = body.get("serviceTicket")
                    if not self.service_ticket:
                        raise RuntimeError("No serviceTicket in response")
                    self.api_version = version
                    st_preview = (self.service_ticket or "")[:8] + "..."
                    log(
                        "Login OK version="
                        + version
                        + " ticket="
                        + st_preview
                    )
                    return self.service_ticket
                else:
                    last_err = f"{resp.status_code} {resp.text}"
                    log(
                        "Login failed version="
                        + version
                        + " error="
                        + last_err
                    )
            except Exception as e:  # noqa: BLE001
                last_err = str(e)
                log("Login exception: " + last_err)
        raise RuntimeError(
            "Login failed for version "
            + str(self.api_versions_to_try)
            + ": "
            + str(last_err)
        )

    def _get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.service_ticket:
            raise RuntimeError("Not logged in")
        params = dict(params or {})
        params["serviceTicket"] = self.service_ticket
        url = self._url(self.api_version, path)
        log("GET " + url + " params=" + str(params))
        resp = self.session.get(
            url,
            headers=self._headers(),
            params=params,
            timeout=30,
        )
        log("GET " + path + " status=" + str(resp.status_code))
        if resp.status_code != 200:
            raise RuntimeError(
                f"GET {path} failed: {resp.status_code} {resp.text}"
            )
        try:
            data = resp.json() if resp.text else {}
            size = (
                len(data.get("list", []))
                if isinstance(data, dict) and "list" in data
                else (len(data) if isinstance(data, list) else 1)
            )
            log("GET " + path + " ok items=" + str(size))
            return data
        except Exception:
            log("GET " + path + " ok (non-JSON)")
            return {}

    # Public helpers for arbitrary endpoint testing
    def get_any(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._get(path, params)

    def get_any_raw(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        if not self.service_ticket:
            raise RuntimeError("Not logged in")
        q = dict(params or {})
        q["serviceTicket"] = self.service_ticket
        url = self._url(self.api_version, path)
        log("GET RAW " + url + " params=" + str(q))
        resp = self.session.get(
            url,
            headers=self._headers(),
            params=q,
            timeout=60,
        )
        headers = {k: v for k, v in resp.headers.items()}
        log(
            "GET RAW "
            + path
            + " status="
            + str(resp.status_code)
            + " bytes="
            + str(len(resp.content))
        )
        return resp.status_code, headers, resp.content

    def get_zones(self, list_size: int = 1000) -> List[Dict[str, Any]]:
        log("Fetching zones")
        data = self._get("rkszones", params={"listSize": min(list_size, 1000)})
        zones = data.get("list", []) if isinstance(data, dict) else []
        log("Zones discovered=" + str(len(zones)))
        return zones

    def get_aps(self, list_size: int = 1000) -> List[Dict[str, Any]]:
        try:
            log("Fetching global APs")
            data = self._get("aps", params={"listSize": min(list_size, 1000)})
            aps = data.get(
                "list",
                data.get("data", data if isinstance(data, list) else []),
            )
            log("Global APs count=" + str(len(aps)))
            return aps
        except RuntimeError as e:
            # Fallback to zone-scoped if lacking privilege
            if "403" not in str(e):
                log("Global APs error (non-403): " + str(e))
                raise
            log("Global APs 403 -> fallback to per-zone APs")
            zones = self.get_zones()
            all_aps: List[Dict[str, Any]] = []
            for z in zones:
                zid = z.get("id") or z.get("zoneId")
                if not zid:
                    continue
                try:
                    zdata = self._get(
                        f"rkszones/{zid}/aps",
                        params={"listSize": min(list_size, 1000)},
                    )
                    zlist = zdata.get("list", [])
                    log("Zone " + str(zid) + " aps=" + str(len(zlist)))
                    all_aps.extend(zlist)
                except Exception as ze:  # noqa: BLE001
                    log("Zone " + str(zid) + " AP fetch error: " + str(ze))
                    continue
            log("Aggregated APs total=" + str(len(all_aps)))
            return all_aps

    def get_clients(self, list_size: int = 1000) -> List[Dict[str, Any]]:
        try:
            log("Fetching global clients")
            data = self._get(
                "clients", params={"listSize": min(list_size, 1000)}
            )
            clients = data.get(
                "list",
                data.get("data", data if isinstance(data, list) else []),
            )
            log("Global clients count=" + str(len(clients)))
            return clients
        except RuntimeError as e:
            if "403" not in str(e):
                log("Global clients error (non-403): " + str(e))
                raise
            log("Global clients 403 -> fallback to per-zone clients")
            zones = self.get_zones()
            all_clients: List[Dict[str, Any]] = []
            for z in zones:
                zid = z.get("id") or z.get("zoneId")
                if not zid:
                    continue
                try:
                    zdata = self._get(
                        f"rkszones/{zid}/clients",
                        params={"listSize": min(list_size, 1000)},
                    )
                    zlist = zdata.get("list", [])
                    log("Zone " + str(zid) + " clients=" + str(len(zlist)))
                    all_clients.extend(zlist)
                except Exception as ze:  # noqa: BLE001
                    log(
                        "Zone "
                        + str(zid)
                        + " clients fetch error: "
                        + str(ze)
                    )
                    continue
            log("Aggregated clients total=" + str(len(all_clients)))
            return all_clients

    def get_alarms(self, list_size: int = 100) -> List[Dict[str, Any]]:
        # Some versions expose /alarms or /alarms/active
        try:
            log("Fetching active alarms")
            data = self._get(
                "alarms/active", params={"listSize": min(list_size, 1000)}
            )
            alarms = data.get("list", data.get("data", []))
            log("Active alarms count=" + str(len(alarms)))
            return alarms
        except Exception as e:  # noqa: BLE001
            log("Active alarms endpoint failed: " + str(e) + " -> try /alarms")
            data = self._get(
                "alarms", params={"listSize": min(list_size, 1000)}
            )
            alarms = data.get("list", data.get("data", []))
            log("Alarms count=" + str(len(alarms)))
            return alarms

    def get_cluster(self) -> Dict[str, Any]:
        try:
            log("Fetching cluster summary")
            data = self._get("cluster")
            log("Cluster summary fetched")
            return data
        except Exception as e:  # noqa: BLE001
            log("Cluster fetch failed: " + str(e))
            return {}

    def get_ap_radios(self, ap_id: str) -> List[Dict[str, Any]]:
        # Optional: per-AP radio stats if supported
        try:
            log("Fetching radios for AP " + str(ap_id))
            data = self._get(f"aps/{ap_id}/radios")
            radios = data.get("list", data.get("data", []))
            log("AP " + str(ap_id) + " radios count=" + str(len(radios)))
            return radios
        except Exception as e:  # noqa: BLE001
            log("AP " + str(ap_id) + " radios fetch failed: " + str(e))
            return []

    def logout(self) -> None:
        if not self.service_ticket:
            log("Logout skipped (no ticket)")
            return
        try:
            ticket_path = f"serviceTicket/{self.service_ticket}"
            log("DELETE " + ticket_path)
            self.session.delete(
                self._url(self.api_version, ticket_path),
                headers=self._headers(),
                timeout=10,
            )
        except Exception as e:  # noqa: BLE001
            log("Logout error: " + str(e))
        finally:
            log("Session closed")
            self.service_ticket = None


def summarize_aps(aps: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(aps)
    online = 0
    firmware_versions: Dict[str, int] = {}
    channels: Dict[str, int] = {}
    for ap in aps:
        status = str(
            ap.get("connectionState") or ap.get("status") or ""
        ).lower()
        if status in {"connected", "online", "up"}:
            online += 1
        fw = ap.get("firmwareVersion") or ap.get("version") or "unknown"
        firmware_versions[fw] = firmware_versions.get(fw, 0) + 1
        channel_value = None
        radio_info = ap.get("radioInfo") or {}
        if isinstance(radio_info, dict):
            channel_value = radio_info.get("channel")
        channel_value = channel_value or ap.get("channel") or "?"
        channels[str(channel_value)] = channels.get(str(channel_value), 0) + 1
    availability = (online / total * 100.0) if total else 0.0
    result = {
        "totalAPs": total,
        "onlineAPs": online,
        "apAvailabilityPct": round(availability, 2),
        "firmwareMix": firmware_versions,
        "channelDistribution": channels,
    }
    log(
        "AP summary: total="
        + str(total)
        + " online="
        + str(online)
        + " availability="
        + str(result["apAvailabilityPct"])
        + "%"
    )
    return result


def summarize_clients(clients: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(clients)
    by_ssid: Dict[str, int] = {}
    by_band: Dict[str, int] = {}
    rssi_values: List[int] = []
    snr_values: List[int] = []
    roaming_fails = 0
    for c in clients:
        ssid = c.get("ssid") or "unknown"
        by_ssid[ssid] = by_ssid.get(ssid, 0) + 1
        band = str(c.get("band") or c.get("bandType") or "?")
        by_band[band] = by_band.get(band, 0) + 1
        rssi = c.get("rssi") or c.get("signalStrength")
        if isinstance(rssi, (int, float)):
            rssi_values.append(int(rssi))
        snr = c.get("snr")
        if isinstance(snr, (int, float)):
            snr_values.append(int(snr))
        if str(c.get("lastRoamResult") or "").lower() in {"fail", "failed"}:
            roaming_fails += 1
    avg_rssi = sum(rssi_values) / len(rssi_values) if rssi_values else None
    avg_snr = sum(snr_values) / len(snr_values) if snr_values else None
    result = {
        "totalClients": total,
        "clientsBySsid": by_ssid,
        "clientsByBand": by_band,
        "avgRssi": round(avg_rssi, 1) if avg_rssi is not None else None,
        "avgSnr": round(avg_snr, 1) if avg_snr is not None else None,
        "roamingFailCount": roaming_fails,
    }
    log(
        "Client summary: total="
        + str(total)
        + " avgRssi="
        + str(result["avgRssi"])
        + " avgSnr="
        + str(result["avgSnr"])
    )
    return result


def print_section(title: str) -> None:
    print("")
    print(f"=== {title} ===")


def main() -> int:
    # Use hardcoded config
    base_url = RUCKUS_BASE_URL
    username = RUCKUS_USERNAME
    password = RUCKUS_PASSWORD
    domain = RUCKUS_DOMAIN
    verify_ssl = RUCKUS_VERIFY_SSL

    client = RuckusClient(
        base_url=base_url,
        username=username,
        password=password,
        domain=domain,
        verify_ssl=verify_ssl,
    )

    print_section("SmartZone Login")
    try:
        client.login()
        print(f"API version: {client.api_version}")
        print("Service ticket acquired")
    except Exception as e:  # noqa: BLE001
        print(f"Login failed: {e}")
        return 2

    try:
        print_section("Cluster Summary")
        cluster = client.get_cluster()
        if cluster:
            name = cluster.get("name") or cluster.get("clusterName")
            health = cluster.get("healthStatus") or cluster.get("status")
            print(f"Cluster: {name} | Health: {health}")
        else:
            print("No cluster data available")

        print_section("AP Inventory")
        aps = client.get_aps(list_size=1000)
        ap_sum = summarize_aps(aps)
        print(json.dumps(ap_sum, indent=2))

        print_section("Clients")
        clients = client.get_clients(list_size=1000)
        client_sum = summarize_clients(clients)
        print(json.dumps(client_sum, indent=2))

        print_section("Alarms (Active)")
        alarms = client.get_alarms(list_size=50)
        if alarms:
            for a in alarms[:10]:
                sev = a.get("severity") or a.get("severityType")
                msg = (
                    a.get("message")
                    or a.get("eventType")
                    or a.get("description")
                )
                ts = a.get("createTime") or a.get("timestamp")
                print(f"- [{sev}] {msg} ({ts})")
        else:
            print("No active alarms")

        # Level-2 KPI probes (best-effort from REST endpoints)
        print_section("Level-2 KPI Probes (best-effort)")
        # RxDesense often requires radio stats; attempt for a few APs.
        rx_desense_samples: List[Tuple[str, float]] = []
        for ap in aps[:5]:
            ap_id = ap.get("id") or ap.get("apId") or ap.get("serialNumber")
            if not ap_id:
                continue
            radios = client.get_ap_radios(str(ap_id))
            for r in radios:
                # Common fields vary by version: rxDesense or rxDesensePct
                val = r.get("rxDesense") or r.get("rxDesensePct")
                if isinstance(val, (int, float)):
                    rx_desense_samples.append(
                        (
                            str(ap.get("name") or ap_id),
                            float(val),
                        )
                    )
        if rx_desense_samples:
            print("RxDesense samples (name,value):")
            for name, val in rx_desense_samples:
                print(f"  {name}: {val}%")
        else:
            print("RxDesense data not available via current REST endpoints.")

        # Idle AP heuristic: zero clients joined (using current snapshot)
        ap_client_counts: Dict[str, int] = {}
        for c in clients:
            ap_id_for_client = (
                c.get("apId")
                or c.get("apMac")
                or c.get("apName")
            )
            if ap_id_for_client:
                key = str(ap_id_for_client)
                ap_client_counts[key] = ap_client_counts.get(key, 0) + 1
        idle_aps: List[str] = []
        for ap in aps:
            ap_key = (
                ap.get("id")
                or ap.get("apId")
                or ap.get("serialNumber")
                or ap.get("mac")
                or ap.get("name")
            )
            if ap_key and ap_client_counts.get(str(ap_key), 0) == 0:
                idle_aps.append(ap.get("name") or str(ap_key))
        msg_idle = (
            "Idle APs (current snapshot, zero clients): "
            + str(len(idle_aps))
        )
        print(msg_idle)
        for name in idle_aps[:10]:
            print(f"  - {name}")

    finally:
        client.logout()
        print("")
        print("Logged out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
