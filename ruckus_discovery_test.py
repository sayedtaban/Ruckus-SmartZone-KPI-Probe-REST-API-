#!/usr/bin/env python3
"""
Ruckus SmartZone Discovery Test
Tests various endpoint patterns to discover what's accessible.
"""

import sys
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


def test_endpoint(
    client: RuckusClient,
    path: str,
    params: Optional[Dict[str, str]] = None,
    is_raw: bool = False,
) -> Tuple[bool, str]:
    """Test a single endpoint and return (success, message)"""
    try:
        if is_raw:
            status, headers, content = client.get_any_raw(path, params=params)
            return True, f"OK (status={status}, bytes={len(content)})"
        else:
            data = client.get_any(path, params=params)
            if isinstance(data, dict) and "list" in data:
                items = data.get("list", [])
                return True, f"OK (items={len(items)})"
            return True, "OK"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Discover accessible SmartZone endpoints."
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output for each test.",
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
        print(f"Username: {RUCKUS_USERNAME}")
    except Exception as e:  # noqa: BLE001
        print(f"Login failed: {e}")
        return 2

    accessible_endpoints = []
    failed_endpoints = []

    try:
        # Test basic system endpoints
        print_header("System Endpoints")
        system_endpoints = [
            ("cluster", None, False),
            ("system", None, False),
            ("system/info", None, False),
            ("system/status", None, False),
            ("system/health", None, False),
            ("clusters", None, False),
            ("clusters/info", None, False),
            ("licenses", None, False),
            ("domains", None, False),
        ]

        for path, params, is_raw in system_endpoints:
            success, msg = test_endpoint(client, path, params, is_raw)
            if success:
                accessible_endpoints.append((path, msg))
                if args.verbose:
                    print(f"✓ {path}: {msg}")
            else:
                failed_endpoints.append((path, msg))
                if args.verbose:
                    print(f"✗ {path}: {msg}")

        # Test alarm endpoints
        print_header("Alarm Endpoints")
        alarm_endpoints = [
            ("alarms", {"listSize": "50"}, False),
            ("alarms/active", {"listSize": "50"}, False),
            ("events", {"listSize": "50"}, False),
            ("system/alarms", {"listSize": "50"}, False),
            ("system/events", {"listSize": "50"}, False),
        ]

        for path, params, is_raw in alarm_endpoints:
            success, msg = test_endpoint(client, path, params, is_raw)
            if success:
                accessible_endpoints.append((path, msg))
                if args.verbose:
                    print(f"✓ {path}: {msg}")
            else:
                failed_endpoints.append((path, msg))
                if args.verbose:
                    print(f"✗ {path}: {msg}")

        # Test zone discovery
        print_header("Zone Discovery")
        zone_patterns = ["rkszones", "zones", "system/zones", "clusters/zones"]
        zones_found = False

        for pattern in zone_patterns:
            success, msg = test_endpoint(client, pattern, {"listSize": "100"})
            if success:
                accessible_endpoints.append((pattern, msg))
                zones_found = True
                if args.verbose:
                    print(f"✓ {pattern}: {msg}")
                break
            else:
                failed_endpoints.append((pattern, msg))
                if args.verbose:
                    print(f"✗ {pattern}: {msg}")

        if not zones_found:
            print("No zones discovered")

        # Test other common endpoints
        print_header("Other Endpoints")
        other_endpoints = [
            ("aps", {"listSize": "50"}, False),
            ("clients", {"listSize": "50"}, False),
            ("wlans", {"listSize": "50"}, False),
            ("ssids", {"listSize": "50"}, False),
            ("apgroups", {"listSize": "50"}, False),
            ("rogueaps", {"listSize": "50"}, False),
            ("mesh", {"listSize": "50"}, False),
            ("portals", {"listSize": "50"}, False),
            ("aaa", {"listSize": "50"}, False),
            ("profiles", {"listSize": "50"}, False),
            ("templates", {"listSize": "50"}, False),
        ]

        for path, params, is_raw in other_endpoints:
            success, msg = test_endpoint(client, path, params, is_raw)
            if success:
                accessible_endpoints.append((path, msg))
                if args.verbose:
                    print(f"✓ {path}: {msg}")
            else:
                failed_endpoints.append((path, msg))
                if args.verbose:
                    print(f"✗ {path}: {msg}")

    finally:
        print_header("Summary")
        print(f"Accessible endpoints: {len(accessible_endpoints)}")
        print(f"Failed endpoints: {len(failed_endpoints)}")

        if accessible_endpoints:
            print("\n✓ Accessible endpoints:")
            for path, msg in accessible_endpoints:
                print(f"  {path}: {msg}")

        if failed_endpoints and args.verbose:
            print("\n✗ Failed endpoints:")
            for path, msg in failed_endpoints:
                print(f"  {path}: {msg}")

        print_header("Logout")
        client.logout()

    return 0


if __name__ == "__main__":
    sys.exit(main())