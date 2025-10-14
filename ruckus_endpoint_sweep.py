import sys
import json
import argparse
from typing import Dict, List, Optional, Tuple

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


def build_endpoints(
    zone_id: Optional[str],
    ap_id: Optional[str],
    ap_mac: Optional[str],
) -> List[Tuple[str, Optional[Dict[str, str]], bool, str]]:
    """
    Returns list of (path, params, is_raw, label)
    """
    items: List[Tuple[str, Optional[Dict[str, str]], bool, str]] = []

    # Global endpoints (may require higher privilege; still attempt)
    items.append(("cluster", None, False, "cluster"))
    items.append((
        "alarms",
        {"listSize": "100"},
        False,
        "alarms",
    ))
    items.append((
        "alarms/active",
        {"listSize": "100"},
        False,
        "alarms_active",
    ))
    items.append((
        "aps",
        {"listSize": "1000"},
        False,
        "aps",
    ))
    items.append((
        "clients",
        {"listSize": "1000"},
        False,
        "clients",
    ))

    # Zone-scoped if zoneId provided
    if zone_id:
        items.append((f"rkszones/{zone_id}", None, False, "zone"))
        items.append((
            f"rkszones/{zone_id}/aps",
            {"listSize": "1000"},
            False,
            "zone_aps",
        ))
        items.append((
            f"rkszones/{zone_id}/clients",
            {"listSize": "1000"},
            False,
            "zone_clients",
        ))
        items.append((
            f"rkszones/{zone_id}/wlans",
            {"listSize": "1000"},
            False,
            "zone_wlans",
        ))

        if ap_id:
            items.append((
                f"rkszones/{zone_id}/aps/{ap_id}",
                None,
                False,
                "zone_ap_detail_by_id",
            ))
            items.append((
                f"rkszones/{zone_id}/aps/{ap_id}/radios",
                None,
                False,
                "zone_ap_radios_by_id",
            ))
        if ap_mac:
            items.append((
                f"rkszones/{zone_id}/aps/{ap_mac}/picture",
                None,
                True,
                "zone_ap_picture_by_mac",
            ))

    return items


def parse_endpoints_file(
    path: str,
    zone_id: Optional[str],
    ap_id: Optional[str],
    ap_mac: Optional[str],
) -> List[Tuple[str, Optional[Dict[str, str]], bool, str]]:
    """
    Parse a simple endpoints file. Each non-empty, non-comment line is either:
    - <PATH>
    - <PATH> RAW
    Placeholders {zoneId}, {apId}, {apMac} will be substituted.
    """
    result: List[Tuple[str, Optional[Dict[str, str]], bool, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split()
                raw = False
                p = parts[0]
                if len(parts) > 1 and parts[1].upper() == "RAW":
                    raw = True
                p = (
                    p.replace("{zoneId}", zone_id or "")
                    .replace("{apId}", ap_id or "")
                    .replace("{apMac}", ap_mac or "")
                )
                label = p.replace("/", "_") or "endpoint"
                result.append((p, None, raw, label))
    except Exception as e:  # noqa: BLE001
        print(f"Failed to read endpoints file: {e}")
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Sweep common SmartZone endpoints; supports zone-scoped tests"
            " and custom endpoints file."
        ),
    )
    parser.add_argument(
        "--zone-id",
        help="Zone ID to test zone-scoped endpoints.",
    )
    parser.add_argument(
        "--ap-id",
        help="AP ID for per-AP endpoints (detail, radios).",
    )
    parser.add_argument(
        "--ap-mac",
        help="AP MAC for picture endpoint.",
    )
    parser.add_argument(
        "--extra",
        action="append",
        help="Extra endpoint path to GET (repeatable).",
    )
    parser.add_argument(
        "--endpoints-file",
        help=(
            "Path to a file with endpoints to test. Use placeholders "
            "{zoneId}, {apId}, {apMac}; append 'RAW' to fetch binary."
        ),
    )
    args = parser.parse_args(argv)

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

    total = 0
    ok = 0
    errors = 0

    try:
        tests = build_endpoints(args.zone_id, args.ap_id, args.ap_mac)
        if args.extra:
            for p in args.extra:
                tests.append((
                    p,
                    None,
                    False,
                    f"extra_{p.replace('/', '_')}",
                ))
        if args.endpoints_file:
            tests.extend(
                parse_endpoints_file(
                    args.endpoints_file,
                    args.zone_id,
                    args.ap_id,
                    args.ap_mac,
                )
            )

        for path, params, is_raw, label in tests:
            total += 1
            print_header(label)
            try:
                if is_raw:
                    status, headers, content = client.get_any_raw(
                        path,
                        params=params,
                    )
                    show_result_raw(label, status, headers, content)
                else:
                    data = client.get_any(path, params=params)
                    show_result_json(label, data)
                ok += 1
            except Exception as e:  # noqa: BLE001
                print(f"{label}: ERROR {e}")
                errors += 1

    finally:
        print_header("Logout")
        client.logout()
        print_header("Summary")
        print(f"Total: {total}, OK: {ok}, Errors: {errors}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
