import os
import sys
import argparse
import json
from typing import Optional

from ruckus_kpi_probe import RuckusClient, getenv_bool


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Test Ruckus SmartZone REST endpoint (GET)."
    )
    parser.add_argument(
        "path",
        help=(
            "Relative REST path under /wsg/api/public/<version>/ "
            "(e.g., 'aps' or 'aps/{id}/picture')"
        ),
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Do not parse JSON; print status and headers.",
    )
    parser.add_argument(
        "--out",
        help=(
            "If set, save response body to this file "
            "(for binary endpoints like pictures)."
        ),
    )
    parser.add_argument(
        "--params",
        help=(
            "Optional query params as JSON string, merged with serviceTicket."
        ),
    )
    args = parser.parse_args(argv)

    base_url = os.getenv("RUCKUS_BASE_URL", "https://3.12.57.221:8443")
    username = os.getenv("RUCKUS_USERNAME", "apireadonly")
    password = os.getenv("RUCKUS_PASSWORD", "SBAedge2112#")
    domain = os.getenv("RUCKUS_DOMAIN", "System")
    verify_ssl = getenv_bool("RUCKUS_VERIFY_SSL", False)

    client = RuckusClient(
        base_url=base_url,
        username=username,
        password=password,
        domain=domain,
        verify_ssl=verify_ssl,
    )

    try:
        client.login()
        if args.raw or args.out:
            status, headers, content = client.get_any_raw(
                args.path,
                params=json.loads(args.params) if args.params else None,
            )
            print(f"Status: {status}")
            print("Headers:")
            for k, v in headers.items():
                print(f"  {k}: {v}")
            if args.out:
                with open(args.out, "wb") as f:
                    f.write(content)
                print(f"Saved body to {args.out}")
            else:
                # Try to print as utf-8 text if decodable; else show length
                try:
                    print(content.decode("utf-8"))
                except Exception:
                    print(f"<{len(content)} bytes>")
        else:
            data = client.get_any(
                args.path,
                params=json.loads(args.params) if args.params else None,
            )
            print(json.dumps(data, indent=2))
    except Exception as e:  # noqa: BLE001
        print(f"Error: {e}")
        return 2
    finally:
        client.logout()
    return 0


if __name__ == "__main__":
    sys.exit(main())



















