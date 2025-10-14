import sys
import json
from typing import Dict, List, Optional

from ruckus_kpi_probe import (
    RuckusClient,
    RUCKUS_BASE_URL,
    RUCKUS_USERNAME,
    RUCKUS_PASSWORD,
    RUCKUS_DOMAIN,
    RUCKUS_VERIFY_SSL,
)


def print_header(title: str) -> None:
    print("")
    print(f"=== {title} ===")


def show_result_json(name: str, data: Dict) -> None:
    try:
        # Print compact summary if list present
        if isinstance(data, dict) and "list" in data:
            items = data.get("list") or []
            print(f"{name}: OK (items={len(items)})")
            return
        print(f"{name}: OK")
        print(json.dumps(data, indent=2))
    except Exception as exc:  # noqa: BLE001
        print(f"{name}: OK but printing failed: {exc}")


def show_result_raw(
    name: str,
    status: int,
    headers: Dict[str, str],
    content: bytes,
) -> None:
    ctype = headers.get("Content-Type")
    print(f"{name}: status={status}, content-type={ctype}")
    print(f"{name}: bytes={len(content)}")


def main(argv: Optional[List[str]] = None) -> int:
    client = RuckusClient(
        base_url=RUCKUS_BASE_URL,
        username=RUCKUS_USERNAME,
        password=RUCKUS_PASSWORD,
        domain=RUCKUS_DOMAIN,
        verify_ssl=RUCKUS_VERIFY_SSL,
    )

    print_header("Login")
    try:
        client.login()
        print(f"API version: {client.api_version}")
    except Exception as e:  # noqa: BLE001
        print(f"Login failed: {e}")
        return 2

    try:
        # Cluster
        print_header("Cluster")
        try:
            cluster = client.get_any("cluster")
            show_result_json("cluster", cluster)
        except Exception as e:  # noqa: BLE001
            print(f"cluster: ERROR {e}")

        # Alarms (active + all)
        print_header("Alarms")
        for path in ["alarms/active", "alarms"]:
            try:
                alarms = client.get_any(path, params={"listSize": 100})
                name = path.replace("/", "_")
                show_result_json(name, alarms)
            except Exception as e:  # noqa: BLE001
                print(f"{path}: ERROR {e}")

        # APs and Clients (cap listSize at 1000)
        print_header("APs")
        ap_list: List[Dict] = []
        try:
            aps = client.get_any("aps", params={"listSize": 1000})
            show_result_json("aps", aps)
            # Extract list for subresource testing
            ap_list = aps.get("list", []) if isinstance(aps, dict) else []
        except Exception as e:  # noqa: BLE001
            print(f"aps: ERROR {e}")

        print_header("Clients")
        try:
            clients = client.get_any("clients", params={"listSize": 1000})
            show_result_json("clients", clients)
        except Exception as e:  # noqa: BLE001
            print(f"clients: ERROR {e}")

        # Test per-AP subresources for up to 3 APs
        print_header("Per-AP subresources")
        for ap in ap_list[:3]:
            ap_id = ap.get("id") or ap.get("apId") or ap.get("serialNumber")
            ap_name = ap.get("name") or ap_id
            if not ap_id:
                continue
            # AP details
            try:
                data = client.get_any(f"aps/{ap_id}")
                show_result_json(f"aps_{ap_name}", data)
            except Exception as e:  # noqa: BLE001
                print(f"aps/{ap_id}: ERROR {e}")
            # Radios
            try:
                data = client.get_any(f"aps/{ap_id}/radios")
                show_result_json(f"aps_{ap_name}_radios", data)
            except Exception as e:  # noqa: BLE001
                print(f"aps/{ap_id}/radios: ERROR {e}")
            # Picture (raw)
            try:
                status, headers, content = client.get_any_raw(
                    f"aps/{ap_id}/picture"
                )
                show_result_raw(
                    f"aps_{ap_name}_picture",
                    status,
                    headers,
                    content,
                )
            except Exception as e:  # noqa: BLE001
                print(f"aps/{ap_id}/picture: ERROR {e}")

    finally:
        print_header("Logout")
        client.logout()
    return 0


if __name__ == "__main__":
    sys.exit(main())
