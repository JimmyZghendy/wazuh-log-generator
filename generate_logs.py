#!/usr/bin/env python3
"""
Wazuh Log Generator (banking SOC simulation)
--------------------------------------------
Generates correlated log samples across multiple sources, so the same attacker
IPs and victim usernames appear consistently across:

  - Active Directory  (Windows Event XML: 4624/4625/4720/4732/4740/4768/4769/...)
  - Microsoft SQL Server audit logs
  - MySQL general/error logs
  - Palo Alto firewall logs (TRAFFIC/THREAT/URL)
  - Web application logs (Apache combined)
  - Linux auth.log (sshd, sudo, PAM)
  - EDR / Ransomware (FIM + Sysmon + VirusTotal + Active Response)

Each run picks N incidents (default 2). An incident is:
    attacker_ip + victim_user + victim_host + target_db
Every generator pulls those values from generators.shared_state, so a single
search in Wazuh Discover (data.srcip:<IP> or victim_user:<user>) reveals the
entire kill-chain across log sources.

Usage:
    python3 generate_logs.py --all
    python3 generate_logs.py --all --count 50 --incidents 3
    python3 generate_logs.py --source ad --count 50
"""
import argparse
import importlib
import sys
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent / "output"


def banner(title: str) -> None:
    bar = "=" * 70
    print(f"\n{bar}\n  {title}\n{bar}")


def _reinit_incidents(n: int) -> None:
    """
    Force shared_state to pick `n` incidents instead of the default.
    Called before any generator imports so the new INCIDENTS list is
    visible everywhere.
    """
    from generators import shared_state
    shared_state.INCIDENTS = shared_state._build_incidents(n=n)
    shared_state.ATTACKER_IPS_ACTIVE = [i["attacker_ip"]
                                        for i in shared_state.INCIDENTS]
    shared_state.VICTIM_USERS_ACTIVE = [i["victim_user"]
                                        for i in shared_state.INCIDENTS]
    shared_state.VICTIM_HOSTS_ACTIVE = [i["victim_host"]
                                        for i in shared_state.INCIDENTS]


def run_all(count: int, incidents: int) -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)

    # 1) Initialize incidents FIRST (before importing generators that read them)
    _reinit_incidents(incidents)

    # 2) Print scenario summary so the user knows what to search for
    from generators import shared_state
    shared_state.print_incidents()

    # 3) Import generators (they will all see the same INCIDENTS list)
    from generators import (
        active_directory, mssql_db, mysql_db,
        paloalto, web_app, auth_alerts, edr_ransomware,
    )

    banner("1/7  Active Directory  (XML Windows Events)")
    active_directory.generate(OUTPUT_DIR / "active_directory.xml", count=count)

    banner("2/7  Microsoft SQL Server  (audit log)")
    mssql_db.generate(OUTPUT_DIR / "mssql_audit.log", count=count)

    banner("3/7  MySQL  (general + error log)")
    mysql_db.generate(OUTPUT_DIR / "mysql.log", count=count)

    banner("4/7  Palo Alto Networks  (CSV: TRAFFIC + THREAT + URL)")
    paloalto.generate(OUTPUT_DIR / "paloalto.csv", count=count)

    banner("5/7  Web Application  (Apache combined log)")
    web_app.generate(OUTPUT_DIR / "web_access.log", count=count)

    banner("6/7  Linux Authentication  (syslog auth.log)")
    auth_alerts.generate(OUTPUT_DIR / "auth.log", count=count)

    banner("7/7  EDR / Ransomware  (FIM + Sysmon + VirusTotal + AR)")
    edr_ransomware.generate(OUTPUT_DIR / "edr_ransomware.json", count=incidents)

    banner("DONE")
    print(f"\nAll log files written to: {OUTPUT_DIR}\n")
    for f in sorted(OUTPUT_DIR.iterdir()):
        size = f.stat().st_size
        print(f"  {f.name:<28} {size:>10,} bytes")

    print("\n--- Quick correlation hints (search these in Wazuh Discover) ---")
    for inc in shared_state.INCIDENTS:
        print(f"  {inc['id']}:")
        print(f"     data.srcip: \"{inc['attacker_ip']}\"")
        print(f"     data.dstuser: \"{inc['victim_user']}\"  "
              f"  (or targetUserName / TargetUser)")
        print(f"     agent.name: \"{inc['victim_host'].split('.')[0]}\"")
    print()


SOURCE_MAP = {
    "ad":        ("active_directory", "active_directory.xml"),
    "mssql":     ("mssql_db",         "mssql_audit.log"),
    "mysql":     ("mysql_db",         "mysql.log"),
    "paloalto":  ("paloalto",         "paloalto.csv"),
    "web":       ("web_app",          "web_access.log"),
    "auth":      ("auth_alerts",      "auth.log"),
    "edr":       ("edr_ransomware",   "edr_ransomware.json"),
}


def run_one(source: str, count: int, incidents: int) -> None:
    if source not in SOURCE_MAP:
        print(f"Unknown source '{source}'. Valid: {', '.join(SOURCE_MAP)}")
        sys.exit(1)

    OUTPUT_DIR.mkdir(exist_ok=True)
    _reinit_incidents(incidents)

    from generators import shared_state
    shared_state.print_incidents()

    module_name, filename = SOURCE_MAP[source]
    module = importlib.import_module(f"generators.{module_name}")
    out = OUTPUT_DIR / filename

    banner(f"Generating: {source}")
    module.generate(out, count=count)
    print(f"\nWrote: {out}\n")


def main():
    p = argparse.ArgumentParser(description="Wazuh banking-SOC log generator")
    p.add_argument("--all", action="store_true",
                   help="Generate all log sources")
    p.add_argument("--source", choices=list(SOURCE_MAP.keys()),
                   help="Generate one specific source")
    p.add_argument("--count", type=int, default=40,
                   help="Number of events per source (default: 40)")
    p.add_argument("--incidents", type=int, default=2,
                   help="Number of coordinated incidents to simulate (default: 2)")
    args = p.parse_args()

    if args.incidents < 1:
        print("--incidents must be >= 1"); sys.exit(1)

    if args.all:
        run_all(args.count, args.incidents)
    elif args.source:
        run_one(args.source, args.count, args.incidents)
    else:
        p.print_help()
        print("\nQuick start:  python3 generate_logs.py --all")
        print("More noise:   python3 generate_logs.py --all --count 80 --incidents 3")


if __name__ == "__main__":
    main()