#!/usr/bin/env python3
"""
Wazuh Log Generator
-------------------
Generates realistic log samples for testing Wazuh detection rules.

Sources covered:
  - Active Directory (Windows Event XML: 4624/4625/4720/4732/4740/4768/4769)
  - Microsoft SQL Server audit logs
  - MySQL general/error logs
  - Palo Alto firewall logs (CSV: TRAFFIC, THREAT, URL)
  - Web application logs (Apache combined: SQLi, XSS, LFI, brute force)
  - Authentication / alert scenarios (failed logins, privilege escalation)

Usage:
    python3 generate_logs.py --all
    python3 generate_logs.py --source ad --count 50
    python3 generate_logs.py --source paloalto --attack-scenario port_scan
"""
import argparse
import os
import sys
from pathlib import Path

# Local generator modules
from generators import (
    active_directory,
    mssql_db,
    mysql_db,
    paloalto,
    web_app,
    auth_alerts,
)

OUTPUT_DIR = Path(__file__).parent / "output"


def banner(title: str) -> None:
    bar = "=" * 70
    print(f"\n{bar}\n  {title}\n{bar}")


def run_all(count: int) -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)

    banner("1/6  Active Directory  (XML Windows Events)")
    active_directory.generate(OUTPUT_DIR / "active_directory.xml", count=count)

    banner("2/6  Microsoft SQL Server  (audit log)")
    mssql_db.generate(OUTPUT_DIR / "mssql_audit.log", count=count)

    banner("3/6  MySQL  (general + error log)")
    mysql_db.generate(OUTPUT_DIR / "mysql.log", count=count)

    banner("4/6  Palo Alto Networks  (CSV: TRAFFIC + THREAT + URL)")
    paloalto.generate(OUTPUT_DIR / "paloalto.csv", count=count)

    banner("5/6  Web Application  (Apache combined log)")
    web_app.generate(OUTPUT_DIR / "web_access.log", count=count)

    banner("6/6  Authentication Alerts  (syslog auth.log)")
    auth_alerts.generate(OUTPUT_DIR / "auth.log", count=count)

    banner("DONE")
    print(f"\nAll log files written to: {OUTPUT_DIR}\n")
    for f in sorted(OUTPUT_DIR.iterdir()):
        size = f.stat().st_size
        print(f"  {f.name:<28} {size:>8,} bytes")


SOURCE_MAP = {
    "ad":         (active_directory, "active_directory.xml"),
    "mssql":      (mssql_db,         "mssql_audit.log"),
    "mysql":      (mysql_db,         "mysql.log"),
    "paloalto":   (paloalto,         "paloalto.csv"),
    "web":        (web_app,          "web_access.log"),
    "auth":       (auth_alerts,      "auth.log"),
}


def run_one(source: str, count: int) -> None:
    if source not in SOURCE_MAP:
        print(f"Unknown source '{source}'. Valid: {', '.join(SOURCE_MAP)}")
        sys.exit(1)
    OUTPUT_DIR.mkdir(exist_ok=True)
    module, filename = SOURCE_MAP[source]
    out = OUTPUT_DIR / filename
    banner(f"Generating: {source}")
    module.generate(out, count=count)
    print(f"\nWrote: {out}\n")


def main():
    p = argparse.ArgumentParser(description="Wazuh log generator")
    p.add_argument("--all", action="store_true",
                   help="Generate all log sources")
    p.add_argument("--source", choices=list(SOURCE_MAP.keys()),
                   help="Generate one specific source")
    p.add_argument("--count", type=int, default=40,
                   help="Number of events per source (default: 40)")
    args = p.parse_args()

    if args.all:
        run_all(args.count)
    elif args.source:
        run_one(args.source, args.count)
    else:
        p.print_help()
        print("\nQuick start:  python3 generate_logs.py --all")


if __name__ == "__main__":
    main()
