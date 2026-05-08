"""
Palo Alto Networks log generator.

PAN-OS syslog format is comma-separated, one record per line, leading
metadata "FUTURE_USE,RECEIVE_TIME,SERIAL,TYPE,SUBTYPE,...".

We generate three subtypes that drive most Wazuh PAN rules:
  - TRAFFIC : connection allow/deny -> port-scan, drop-burst rules
  - THREAT  : IPS/AV/WildFire hits   -> critical / high severity rules
  - URL     : URL filtering blocks   -> malicious-category rules
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    INTERNAL_IPS, EXTERNAL_IPS, ATTACKER_IPS,
    rand_recent, palo_ts, pick,
)

SERIAL = "012345678901"     # firewall serial
DEVICE = "PA-VM-FW01"

THREAT_SIGS = [
    ("SQL Injection Evasion Attempt", "40021", "critical"),
    ("Suspicious DNS Query", "12345", "high"),
    ("Cobalt Strike Beacon", "86001", "critical"),
    ("Mimikatz Credential Dumper", "86002", "critical"),
    ("ZeroLogon CVE-2020-1472", "57777", "critical"),
    ("Log4Shell CVE-2021-44228", "91991", "critical"),
    ("EternalBlue SMB Exploit", "39001", "high"),
    ("Brute Force HTTP Basic Authentication", "40015", "medium"),
]

URL_CATEGORIES_BAD = [
    "malware", "command-and-control", "phishing", "newly-registered-domain",
    "cryptocurrency", "hacking", "proxy-avoidance-and-anonymizers",
]
URL_CATEGORIES_OK = ["business-and-economy", "computer-and-internet-info", "news"]


def _traffic(ts, action="allow", attacker=False):
    """TRAFFIC log line."""
    src = pick(ATTACKER_IPS) if attacker else pick(INTERNAL_IPS)
    dst = pick(INTERNAL_IPS) if attacker else pick(INTERNAL_IPS + EXTERNAL_IPS)
    sport = random.randint(49152, 65535)
    dport = pick([22, 80, 443, 445, 3389, 3306, 1433, 8080])
    proto = "tcp"
    app = pick(["web-browsing", "ssl", "ssh", "ms-sql-db", "mysql", "ms-ds-smb"])
    rule_name = "Allow-Internal" if action == "allow" else "Block-Suspicious"
    bytes_sent = random.randint(100, 50000)
    bytes_recv = random.randint(100, 500000)
    fields = [
        "1",                          # FUTURE_USE
        palo_ts(ts),                  # Receive Time
        SERIAL,                       # Serial #
        "TRAFFIC",                    # Type
        "end",                        # Subtype
        "2049",                       # FUTURE_USE
        palo_ts(ts),                  # Generated Time
        src, dst,                     # src ip / dst ip
        "0.0.0.0", "0.0.0.0",         # NAT src / dst
        rule_name,                    # rule
        "", "",                       # src user / dst user
        app,                          # application
        "vsys1",                      # vsys
        "trust", "untrust",           # src zone / dst zone
        "ethernet1/1", "ethernet1/2", # ingress / egress IF
        "default",                    # log forwarding profile
        palo_ts(ts),                  # FUTURE_USE
        str(random.randint(100000, 999999)),  # session id
        "1",                          # repeat count
        str(sport), str(dport),       # src port / dst port
        "0", "0",                     # NAT ports
        "0x400000",                   # flags
        proto,                        # protocol
        action,                       # action
        str(bytes_sent + bytes_recv), # bytes
        str(bytes_sent), str(bytes_recv),  # bytes sent / recv
        str(random.randint(2, 50)),   # packets
        palo_ts(ts),                  # start time
        str(random.randint(1, 600)),  # elapsed time (s)
        "any",                        # category
    ]
    return ",".join(fields)


def _threat(ts):
    """THREAT log line."""
    src = pick(ATTACKER_IPS + EXTERNAL_IPS)
    dst = pick(INTERNAL_IPS)
    name, sid, sev = pick(THREAT_SIGS)
    sport = random.randint(49152, 65535)
    dport = pick([80, 443, 445, 3389, 22])
    fields = [
        "1", palo_ts(ts), SERIAL, "THREAT",
        pick(["vulnerability", "spyware", "virus", "wildfire"]),
        "2049", palo_ts(ts), src, dst,
        "0.0.0.0", "0.0.0.0",
        "Block-Threats",
        "", "",
        pick(["web-browsing", "ssl", "ms-ds-smb"]),
        "vsys1", "untrust", "trust",
        "ethernet1/2", "ethernet1/1",
        "default", palo_ts(ts),
        str(random.randint(100000, 999999)), "1",
        str(sport), str(dport),
        "0", "0", "0x80004000", "tcp",
        "reset-both",
        f"\"{name}\"",           # threat name (quoted because it has spaces)
        f"http://malicious.example/{sid}",  # URL or filename
        sid,                     # threat id
        sev,                     # severity  <-- WAZUH MAPS TO LEVEL
        "client-to-server",      # direction
        str(random.randint(100000, 999999)),
        "any",
    ]
    return ",".join(fields)


def _url(ts, blocked=False):
    """URL filtering log line."""
    src = pick(INTERNAL_IPS)
    dst = pick(EXTERNAL_IPS)
    cat = pick(URL_CATEGORIES_BAD) if blocked else pick(URL_CATEGORIES_OK)
    action = "block-url" if blocked else "alert"
    host = pick([
        "malicious-site.example.com",
        "phishing-login.example.net",
        "c2-server.evil.example",
        "github.com",
        "stackoverflow.com",
    ])
    uri = pick(["/", "/login", "/wp-admin", "/api/v1/data", "/download/x.exe"])
    fields = [
        "1", palo_ts(ts), SERIAL, "THREAT", "url",
        "2049", palo_ts(ts), src, dst,
        "0.0.0.0", "0.0.0.0",
        "URL-Filter",
        "", "",
        "web-browsing",
        "vsys1", "trust", "untrust",
        "ethernet1/1", "ethernet1/2",
        "default", palo_ts(ts),
        str(random.randint(100000, 999999)), "1",
        str(random.randint(49152, 65535)), "443",
        "0", "0", "0x402000", "tcp",
        action,
        f"\"{host}{uri}\"",
        "(9999)",
        "informational" if not blocked else "medium",
        "client-to-server",
        str(random.randint(100000, 999999)),
        cat,
    ]
    return ",".join(fields)


def generate(path: Path, count: int = 40) -> None:
    events = []

    # Normal traffic
    for _ in range(count):
        ts = rand_recent(60)
        events.append((ts, _traffic(ts, action="allow")))

    # Port-scan burst from one attacker (many denies, varied dst ports)
    base = rand_recent(20)
    scanner = pick(ATTACKER_IPS)
    for i in range(25):
        ts = base + timedelta(seconds=i)
        # Hand-craft so source IP is consistent
        line = _traffic(ts, action="deny", attacker=True)
        # Force src to the scanner for the burst (replace src field index 7)
        parts = line.split(",")
        parts[7] = scanner
        parts[19] = str(random.randint(1, 65535))  # dst port varies
        events.append((ts, ",".join(parts)))

    # Threat events
    for _ in range(8):
        ts = rand_recent(30)
        events.append((ts, _threat(ts)))

    # URL filtering (mix of allowed + blocked-malicious)
    for _ in range(6):
        ts = rand_recent(60)
        events.append((ts, _url(ts, blocked=False)))
    for _ in range(6):
        ts = rand_recent(30)
        events.append((ts, _url(ts, blocked=True)))

    events.sort(key=lambda x: x[0])

    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} Palo Alto events -> {path.name}")
