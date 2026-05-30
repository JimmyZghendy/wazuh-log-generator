# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
Wazuh Log Generator (banking SOC simulation)
--------------------------------------------
Generates correlated log samples across multiple sources so the same attacker
IPs and victim usernames appear consistently across:

  - Active Directory  (Windows Event XML: 4624/4625/4720/4732/4740/4768/4769...)
  - Microsoft SQL Server audit logs
  - MySQL general/error logs
  - Palo Alto firewall logs (TRAFFIC/THREAT/URL)
  - Web application logs (Apache combined)
  - Linux auth.log (sshd, sudo, PAM)
  - EDR / Sysmon (JSON, full kill-chains with attacker IP)

Target ratio: 60% benign baseline events, 40% attack/suspicious events.
Within the 40%: ~70% tied to incident kill-chains (correlatable),
                ~30% standalone attack noise (isolated alerts).

Usage:
    python3 generate_logs.py --all
    python3 generate_logs.py --all --count 80 --incidents 3
    python3 generate_logs.py --source ad --count 80
"""
import argparse
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

OUTPUT_DIR = Path(__file__).parent / "output"


def banner(title: str) -> None:
    bar = "=" * 70
    print(f"\n{bar}\n  {title}\n{bar}")


def _reinit_incidents(n: int) -> None:
    """
    Force shared_state to use n incidents, mutating the list in-place so
    all generators that already imported INCIDENTS see the updated values.
    """
    from generators import shared_state
    new = shared_state._build_incidents(n=n)
    shared_state.INCIDENTS[:]            = new
    shared_state.ATTACKER_IPS_ACTIVE[:]  = [i["attacker_ip"] for i in new]
    shared_state.VICTIM_USERS_ACTIVE[:]  = [i["victim_user"] for i in new]
    shared_state.VICTIM_HOSTS_ACTIVE[:]  = [i["victim_host"] for i in new]


def _print_summary(output_dir: Path) -> None:
    """Print file sizes and correlation hints."""
    print(f"\nAll log files written to: {output_dir}\n")
    for f in sorted(output_dir.iterdir()):
        if not f.name.startswith("."):
            size = f.stat().st_size
            lines = sum(1 for _ in f.open("rb"))
            print(f"  {f.name:<32} {size:>10,} bytes  {lines:>6,} lines")


def run_all(count: int, incidents: int) -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)

    # 1) Set up incidents BEFORE importing generators
    _reinit_incidents(incidents)

    from generators import shared_state
    shared_state.print_incidents()

    print(f"\n  Target ratio: 60% benign baseline / 40% attack events")
    print(f"  Within attack slice: ~70% correlated to incidents / ~30% standalone\n")

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

    banner("7/7  EDR / Sysmon  (full kill-chains, JSON)")
    edr_ransomware.generate(OUTPUT_DIR / "edr_ransomware.json",
                             count=count, normal_ratio=0.60)

    banner("DONE")
    _print_summary(OUTPUT_DIR)

    print("\n--- Correlation pivots (search these in Wazuh Discover) ---")
    for inc in shared_state.INCIDENTS:
        print(f"\n  {inc['id']} ({inc['attacker_label'].upper()}) "
              f"priv={inc['victim_priv']}")
        print(f"    Attacker IP  : \"{inc['attacker_ip']}\"")
        print(f"    Victim user  : \"{inc['victim_user']}\"")
        print(f"    Victim host  : \"{inc['victim_host'].split('.')[0]}\"")
        print(f"    Target DB    : \"{inc['target_db']}\"")
        print(f"    Expected chain: auth brute → AD lockout → AD 4624 → "
              f"MSSQL sa-login → PA threat → EDR kill-chain")
    print()


SOURCE_MAP = {
    "ad":       ("active_directory", "active_directory.xml"),
    "mssql":    ("mssql_db",         "mssql_audit.log"),
    "mysql":    ("mysql_db",         "mysql.log"),
    "paloalto": ("paloalto",         "paloalto.csv"),
    "web":      ("web_app",          "web_access.log"),
    "auth":     ("auth_alerts",      "auth.log"),
    "edr":      ("edr_ransomware",   "edr_ransomware.json"),
}


def run_one(source: str, count: int, incidents: int) -> None:
    if source not in SOURCE_MAP:
        print(f"Unknown source '{source}'. Valid: {', '.join(SOURCE_MAP)}")
        sys.exit(1)
    OUTPUT_DIR.mkdir(exist_ok=True)
    _reinit_incidents(incidents)
    from generators import shared_state
    shared_state.print_incidents()
    import importlib
    module_name, filename = SOURCE_MAP[source]
    module = importlib.import_module(f"generators.{module_name}")
    out = OUTPUT_DIR / filename
    banner(f"Generating: {source}")
    if source == "edr":
        module.generate(out, count=count, normal_ratio=0.60)
    else:
        module.generate(out, count=count)
    print(f"\nWrote: {out}\n")


def main():
    p = argparse.ArgumentParser(description="Wazuh banking-SOC log generator")
    p.add_argument("--all", action="store_true",
                   help="Generate all log sources")
    p.add_argument("--source", choices=list(SOURCE_MAP.keys()),
                   help="Generate one specific log source")
    p.add_argument("--count", type=int, default=80,
                   help="Baseline event count per source (default: 80)")
    p.add_argument("--incidents", type=int, default=2,
                   help="Number of coordinated incidents (default: 2)")
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
        print("Thesis eval:  python3 generate_logs.py --all --count 100 --incidents 3")


if __name__ == "__main__":
    main()
