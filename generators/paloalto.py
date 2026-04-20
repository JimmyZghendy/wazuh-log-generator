"""
Palo Alto Networks log generator (PAN-OS 10.x syslog, ~70 fields per record).

Subtypes produced:
  - TRAFFIC : connection allow/deny -> port-scan, drop-burst rules
  - THREAT  : IPS/AV/WildFire hits   -> critical / high severity rules
  - URL     : URL filtering blocks   -> malicious-category rules

NEW: same scenario attacker IPs from shared_state appear as the SOURCE of
THREAT signatures (port scans, exploit attempts, C2 callbacks). The scenario
victim hosts appear as the DESTINATION. Pivot in Wazuh on the attacker IP
and you'll see the firewall threats alongside SSH/AD/MSSQL events.
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    INTERNAL_IPS, EXTERNAL_IPS, ATTACKER_IPS, SERVER_IPS,
    pick_normal_user, pick_noisy_user, USERNAMES, HOSTS_BANKING,
    rand_recent, palo_ts, pick,
)
from .shared_state import INCIDENTS


SERIAL = "012345678901"
DEVICE = "PA-VM-FW01"


# Expanded threat signature catalog — enough variety that the AI doesn't
# learn "all threats look the same"
THREAT_SIGS = [
    # (name, signature_id, severity, subtype)
    ("SQL Injection Evasion Attempt",            "40021", "critical", "vulnerability"),
    ("Suspicious DNS Query - DGA",               "12345", "high",     "spyware"),
    ("DNS Tunneling Detected",                   "12346", "high",     "spyware"),
    ("Cobalt Strike Beacon",                     "86001", "critical", "spyware"),
    ("Mimikatz Credential Dumper",               "86002", "critical", "virus"),
    ("ZeroLogon CVE-2020-1472",                  "57777", "critical", "vulnerability"),
    ("Log4Shell CVE-2021-44228",                 "91991", "critical", "vulnerability"),
    ("EternalBlue SMB Exploit",                  "39001", "high",     "vulnerability"),
    ("Brute Force HTTP Basic Authentication",    "40015", "medium",   "vulnerability"),
    ("PowerShell Empire C2",                     "86003", "critical", "spyware"),
    ("Metasploit Reverse Shell",                 "86004", "critical", "spyware"),
    ("Ransomware Activity Detected",             "86005", "critical", "wildfire-virus"),
    ("Suspicious Outbound to TOR",               "30001", "medium",   "spyware"),
    ("ProxyShell Exchange Exploit",              "91002", "critical", "vulnerability"),
    ("Apache Struts RCE CVE-2017-5638",          "31001", "critical", "vulnerability"),
    ("Suspicious File Upload to External",       "40050", "high",     "vulnerability"),
    ("SWIFT Anomalous Traffic Pattern",          "40090", "high",     "vulnerability"),
    ("Web Shell Detected",                       "86010", "critical", "virus"),
]

URL_CATEGORIES_BAD = [
    "malware", "command-and-control", "phishing", "newly-registered-domain",
    "cryptocurrency", "hacking", "proxy-avoidance-and-anonymizers",
    "dynamic-dns",
]
URL_CATEGORIES_OK = [
    "business-and-economy", "computer-and-internet-info", "news",
    "financial-services", "government", "reference-and-research",
]
URL_HOSTS_BAD = [
    "malicious-site.example.com", "phishing-login.example.net",
    "c2-server.evil.example", "exfil.attacker-controlled.example",
    "ransomware-payment.onion.example", "drop-zone.fake-cdn.example",
]
URL_HOSTS_OK = [
    "www.reuters.com", "github.com", "stackoverflow.com",
    "docs.microsoft.com", "developer.mozilla.org",
]


# =========================================================================
# Line builders — PAN-OS field ordering matters for the Wazuh decoder
# =========================================================================
def _traffic(ts, src_ip=None, dst_ip=None, action="allow", attacker=False):
    src = src_ip or (pick(ATTACKER_IPS) if attacker else pick(INTERNAL_IPS))
    dst = dst_ip or (pick(INTERNAL_IPS) if attacker
                     else pick(INTERNAL_IPS + EXTERNAL_IPS))
    sport = random.randint(49152, 65535)
    dport = pick([22, 80, 443, 445, 3389, 3306, 1433, 8080, 8443, 53])
    app = pick(["web-browsing", "ssl", "ssh", "ms-sql-db", "mysql",
                "ms-ds-smb", "dns", "swift-protocol", "ldap"])
    rule_name = "Allow-Internal" if action == "allow" else "Block-Suspicious"
    bytes_sent = random.randint(100, 50000)
    bytes_recv = random.randint(100, 500000)

    fields = [
        "1", palo_ts(ts), SERIAL, "TRAFFIC", "end", "2049", palo_ts(ts),
        src, dst, "0.0.0.0", "0.0.0.0", rule_name, "", "", app, "vsys1",
        "trust", "untrust", "ethernet1/1", "ethernet1/2", "default",
        palo_ts(ts), str(random.randint(100000, 999999)), "1",
        str(sport), str(dport), "0", "0", "0x400000", "tcp", action,
        str(bytes_sent + bytes_recv), str(bytes_sent), str(bytes_recv),
        str(random.randint(2, 50)), palo_ts(ts), str(random.randint(1, 600)),
        "any", "", str(random.randint(1000000, 9999999)), "0x0",
        "10.0.0.0-10.255.255.255", "United States", "",
        str(random.randint(1, 25)), str(random.randint(1, 25)),
        "n/a", "0", "0", "0", "0", "", DEVICE, "from-policy", "", "",
        "0", "", "0", "", "N/A", "0", "0", "0", "0",
        f"{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}-"
        f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-"
        f"{random.randint(100000000000, 999999999999)}", "0",
    ]
    return ",".join(fields)


def _threat(ts, src_ip=None, dst_ip=None, sig=None, src_user=None):
    src = src_ip or pick(ATTACKER_IPS + EXTERNAL_IPS)
    dst = dst_ip or pick(INTERNAL_IPS)
    name, sid, sev, subtype = sig or pick(THREAT_SIGS)
    src_user = src_user or ""
    sport = random.randint(49152, 65535)
    dport = pick([80, 443, 445, 3389, 22, 53])

    miscellaneous = f'"http://malicious.example/{sid}"'
    threat_name_quoted = f'"{name}({sid})"'

    fields = [
        "1", palo_ts(ts), SERIAL, "THREAT", subtype, "2049", palo_ts(ts),
        src, dst, "0.0.0.0", "0.0.0.0", "Block-Threats", src_user, "",
        pick(["web-browsing", "ssl", "ms-ds-smb", "dns"]), "vsys1",
        "untrust", "trust", "ethernet1/2", "ethernet1/1", "default",
        palo_ts(ts), str(random.randint(100000, 999999)), "1",
        str(sport), str(dport), "0", "0", "0x80004000", "tcp",
        "reset-both", miscellaneous, threat_name_quoted, "any", sev,
        "client-to-server", str(random.randint(1000000, 9999999)),
        "0xa000000000000000", "United States",
        "10.0.0.0-10.255.255.255", "", "0", "0", "0", "", "", "", "",
        "", "", "", "", "0", "0", "0", "0", "", DEVICE, "", "", "",
        "", "", "", "", "", "N/A", subtype, "", "0",
        f"{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}-"
        f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-"
        f"{random.randint(100000000000, 999999999999)}", "0",
    ]
    return ",".join(fields)


def _url(ts, src_ip=None, blocked=False, src_user=None):
    src = src_ip or pick(INTERNAL_IPS)
    dst = pick(EXTERNAL_IPS)
    src_user = src_user or ""
    cat = pick(URL_CATEGORIES_BAD) if blocked else pick(URL_CATEGORIES_OK)
    action = "block-url" if blocked else "alert"
    severity = "high" if blocked else "informational"
    host = pick(URL_HOSTS_BAD) if blocked else pick(URL_HOSTS_OK)
    uri = pick(["/", "/login", "/wp-admin", "/api/v1/data", "/download/x.exe",
                "/admin", "/upload"])

    fields = [
        "1", palo_ts(ts), SERIAL, "THREAT", "url", "2049", palo_ts(ts),
        src, dst, "0.0.0.0", "0.0.0.0", "URL-Filter", src_user, "",
        "web-browsing", "vsys1", "trust", "untrust",
        "ethernet1/1", "ethernet1/2", "default",
        palo_ts(ts), str(random.randint(100000, 999999)), "1",
        str(random.randint(49152, 65535)), "443", "0", "0", "0x402000",
        "tcp", action, f'"{host}{uri}"', '"(9999)"', cat, severity,
        "client-to-server", str(random.randint(1000000, 9999999)),
        "0x8000000000000000", "United States", "10.0.0.0-10.255.255.255",
        "", "0", "0", "0", "", "", "Mozilla/5.0", "", "", "", "", "", "",
        "0", "0", "0", "0", "", DEVICE, "", "", "", "GET", "", "", "",
        "", "N/A", cat, "", "0",
        f"{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}-"
        f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-"
        f"{random.randint(100000000000, 999999999999)}", "0",
    ]
    return ",".join(fields)


def _dns_tunneling(ts, src_ip, src_user=""):
    """High-frequency, high-entropy DNS queries — classic tunneling pattern."""
    sig = ("DNS Tunneling Detected", "12346", "high", "spyware")
    return _threat(ts, src_ip=src_ip, dst_ip=pick(INTERNAL_IPS),
                   sig=sig, src_user=src_user)


# =========================================================================
# Main generator
# =========================================================================
def generate(path: Path, count: int = 40) -> None:
    events = []

    # --- Baseline normal allow traffic --------------------------------
    for _ in range(count * 2):
        ts = rand_recent(60)
        events.append((ts, _traffic(ts, action="allow")))

    # --- Normal URL browsing -----------------------------------------
    for _ in range(15):
        ts = rand_recent(60)
        events.append((ts, _url(ts, blocked=False)))

    # ----------------------------------------------------------------
    # SCENARIO-DRIVEN: threats from each incident's attacker IP
    # ----------------------------------------------------------------
    for incident in INCIDENTS:
        attacker_ip = incident["attacker_ip"]
        victim_user = incident["victim_user"]
        victim_host = incident["victim_host"]
        # Use a server-VLAN IP as the destination so it's clearly an "inside" hit
        dst_ip = pick(SERVER_IPS)

        # Port scan: 20 denied TRAFFIC entries from the attacker to varied dst ports
        base = rand_recent(25)
        for i in range(20):
            ts = base + timedelta(seconds=i)
            line = _traffic(ts, src_ip=attacker_ip, dst_ip=dst_ip,
                            action="deny", attacker=True)
            # Override dst port for the scan illusion
            parts = line.split(",")
            parts[25] = str(random.randint(1, 65535))
            events.append((ts, ",".join(parts)))

        # Exploit attempt: a critical THREAT signature from attacker to victim
        ts = base + timedelta(seconds=30)
        sig = pick([s for s in THREAT_SIGS if s[2] == "critical"])
        events.append((ts, _threat(ts, src_ip=attacker_ip, dst_ip=dst_ip,
                                   sig=sig, src_user="")))

        # Second-stage: web shell or beacon
        ts = base + timedelta(seconds=60)
        sig = pick([("Cobalt Strike Beacon", "86001", "critical", "spyware"),
                    ("Web Shell Detected",   "86010", "critical", "virus")])
        events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=attacker_ip,
                                   sig=sig, src_user=victim_user)))

        # C2 callback (outbound URL block) by compromised host
        ts = base + timedelta(seconds=90)
        events.append((ts, _url(ts, src_ip=dst_ip, blocked=True,
                                src_user=victim_user)))

        # DNS tunneling from victim host (data exfil via DNS)
        for i in range(5):
            ts = base + timedelta(seconds=120 + i * 3)
            events.append((ts, _dns_tunneling(ts, src_ip=dst_ip,
                                              src_user=victim_user)))

        # Outbound suspicious file upload (exfil)
        ts = base + timedelta(seconds=180)
        sig = ("Suspicious File Upload to External", "40050", "high", "vulnerability")
        events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=attacker_ip,
                                   sig=sig, src_user=victim_user)))

    # ----------------------------------------------------------------
    # STANDALONE: assorted critical/high threats (rule coverage)
    # ----------------------------------------------------------------
    for _ in range(20):
        ts = rand_recent(30)
        events.append((ts, _threat(ts)))

    # Random URL filtering blocks
    for _ in range(15):
        ts = rand_recent(30)
        events.append((ts, _url(ts, blocked=True)))

    events.sort(key=lambda x: x[0])
    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} Palo Alto events -> {path.name}")
    print(f"  scenario-driven Palo Alto chains: {len(INCIDENTS)} "
          f"(attackers: {[i['attacker_ip'] for i in INCIDENTS]})")