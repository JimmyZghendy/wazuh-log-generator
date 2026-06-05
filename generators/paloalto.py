"""
Palo Alto Networks log generator (enhanced, PAN-OS 10.x).

Mirrors the EDR generator's per-incident scenario types so that the
firewall side of the kill chain matches what EDR/auth show:

  service victim   →  Webshell / ransomware (EDR) →
                     port scan → SQL injection / web exploit on the DMZ host
  admin victim     →  Mimikatz / credential dump (EDR) →
                     port scan → ZeroLogon CVE-2020-1472 / SMB exploit
  manager victim   →  C2 beacon (EDR) →
                     port scan → Cobalt Strike beacon → DNS tunneling → exfil
  user victim      →  Ransomware (EDR) →
                     port scan → drive-by download → ransomware C2

Log format (real syslog wire form):
    May 21 10:30:45 PA-VM-FW01 1,2026/05/21 10:30:45,012345678901,THREAT,...

Subtypes:
  - TRAFFIC  allow/deny  → port-scan / drop-burst rules
  - THREAT   IPS/AV/WildFire
  - URL      URL filtering blocks
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    INTERNAL_IPS, EXTERNAL_IPS, ATTACKER_IPS, SERVER_IPS,
    pick_normal_user, pick_noisy_user, USERNAMES, HOSTS_BANKING,
    rand_recent, palo_ts, syslog_ts, pick,
)
from .shared_state import INCIDENTS


SERIAL = "012345678901"
DEVICE = "PA-VM-FW01"

# Catalog grouped by attack archetype so we can pick by scenario type.
THREAT_SIGS_WEB = [
    ("SQL Injection Evasion Attempt",            "40021", "critical", "vulnerability"),
    ("Apache Struts RCE CVE-2017-5638",          "31001", "critical", "vulnerability"),
    ("ProxyShell Exchange Exploit",              "91002", "critical", "vulnerability"),
    ("Web Shell Detected",                       "86010", "critical", "virus"),
    ("Log4Shell CVE-2021-44228",                 "91991", "critical", "vulnerability"),
    ("Brute Force HTTP Basic Authentication",    "40015", "medium",   "vulnerability"),
]
THREAT_SIGS_CRED = [
    ("Mimikatz Credential Dumper",               "86002", "critical", "virus"),
    ("ZeroLogon CVE-2020-1472",                  "57777", "critical", "vulnerability"),
    ("EternalBlue SMB Exploit",                  "39001", "high",     "vulnerability"),
    ("Kerberos Golden Ticket Anomaly",           "57010", "critical", "vulnerability"),
]
THREAT_SIGS_C2 = [
    ("Cobalt Strike Beacon",                     "86001", "critical", "spyware"),
    ("PowerShell Empire C2",                     "86003", "critical", "spyware"),
    ("Metasploit Reverse Shell",                 "86004", "critical", "spyware"),
    ("DNS Tunneling Detected",                   "12346", "high",     "spyware"),
    ("Suspicious DNS Query - DGA",               "12345", "high",     "spyware"),
    ("Suspicious Outbound to TOR",               "30001", "medium",   "spyware"),
]
THREAT_SIGS_RANSOM = [
    ("Ransomware Activity Detected",             "86005", "critical", "wildfire-virus"),
    ("Suspicious File Upload to External",       "40050", "high",     "vulnerability"),
    ("Ransomware C2 Communication",              "86006", "critical", "spyware"),
]
THREAT_SIGS_ALL = (THREAT_SIGS_WEB + THREAT_SIGS_CRED +
                   THREAT_SIGS_C2 + THREAT_SIGS_RANSOM)

URL_CATEGORIES_BAD = [
    "malware", "command-and-control", "phishing", "newly-registered-domain",
    "cryptocurrency", "hacking", "proxy-avoidance-and-anonymizers", "dynamic-dns",
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
# Low-level builders
# =========================================================================
def _syslog_wrap(ts, csv_payload):
    """Prefix PAN-OS CSV with a real syslog header so the decoder fires."""
    return f"{syslog_ts(ts)} {DEVICE} {csv_payload}"


def _traffic_csv(ts, src_ip=None, dst_ip=None, action="allow", attacker=False,
                 dport=None, app=None):
    src = src_ip or (pick(ATTACKER_IPS) if attacker else pick(INTERNAL_IPS))
    dst = dst_ip or (pick(INTERNAL_IPS) if attacker
                     else pick(INTERNAL_IPS + EXTERNAL_IPS))
    sport = random.randint(49152, 65535)
    dport = dport or pick([22, 80, 443, 445, 3389, 3306, 1433, 8080, 8443, 53])
    app = app or pick(["web-browsing", "ssl", "ssh", "ms-sql-db", "mysql",
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


def _threat_csv(ts, src_ip=None, dst_ip=None, sig=None, src_user=None,
                dport=None):
    src = src_ip or pick(ATTACKER_IPS + EXTERNAL_IPS)
    dst = dst_ip or pick(INTERNAL_IPS)
    name, sid, sev, subtype = sig or pick(THREAT_SIGS_ALL)
    src_user = src_user or ""
    sport = random.randint(49152, 65535)
    dport = dport or pick([80, 443, 445, 3389, 22, 53])

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


def _url_csv(ts, src_ip=None, dst_ip=None, blocked=False, src_user=None,
             host=None, category=None):
    src = src_ip or pick(INTERNAL_IPS)
    dst = dst_ip or pick(EXTERNAL_IPS)
    src_user = src_user or ""
    cat = category or (pick(URL_CATEGORIES_BAD) if blocked
                       else pick(URL_CATEGORIES_OK))
    action = "block-url" if blocked else "alert"
    severity = "high" if blocked else "informational"
    host = host or (pick(URL_HOSTS_BAD) if blocked else pick(URL_HOSTS_OK))
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


def _traffic(ts, **kw):
    return _syslog_wrap(ts, _traffic_csv(ts, **kw))


def _threat(ts, **kw):
    return _syslog_wrap(ts, _threat_csv(ts, **kw))


def _url(ts, **kw):
    return _syslog_wrap(ts, _url_csv(ts, **kw))


def _port_scan(events, base, attacker_ip, dst_ip, n_ports=20):
    """Generate a port-scan burst of denied TRAFFIC events."""
    for i in range(n_ports):
        ts = base + timedelta(seconds=i)
        csv = _traffic_csv(ts, src_ip=attacker_ip, dst_ip=dst_ip,
                           action="deny", attacker=True)
        # Override the destination port to spread across ports
        parts = csv.split(",")
        parts[25] = str(random.randint(1, 65535))
        events.append((ts, _syslog_wrap(ts, ",".join(parts))))


# =========================================================================
# Per-scenario chains
# =========================================================================
def _chain_web_compromise(base, attacker_ip, victim_user, dst_ip, events):
    """service victim — web/server exploit chain."""
    _port_scan(events, base, attacker_ip, dst_ip, n_ports=25)

    # Web exploit attempts on common HTTP services
    ts = base + timedelta(seconds=30)
    sig = pick(THREAT_SIGS_WEB)
    events.append((ts, _threat(ts, src_ip=attacker_ip, dst_ip=dst_ip,
                               sig=sig, dport=443)))

    # SQL injection attempts
    ts = base + timedelta(seconds=45)
    sql_sig = ("SQL Injection Evasion Attempt", "40021", "critical", "vulnerability")
    events.append((ts, _threat(ts, src_ip=attacker_ip, dst_ip=dst_ip,
                               sig=sql_sig, dport=443)))

    # Webshell drop confirmation — same hash that EDR sees
    ts = base + timedelta(seconds=60)
    shell_sig = ("Web Shell Detected", "86010", "critical", "virus")
    events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=attacker_ip,
                               sig=shell_sig, src_user=victim_user)))

    # Suspicious file upload outbound
    ts = base + timedelta(seconds=90)
    upload_sig = ("Suspicious File Upload to External", "40050", "high",
                  "vulnerability")
    events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=attacker_ip,
                               sig=upload_sig, src_user=victim_user)))
    return "web-compromise"


def _chain_credential_dump(base, attacker_ip, victim_user, dst_ip, events):
    """admin victim — credential-theft chain (mirrors Mimikatz EDR)."""
    _port_scan(events, base, attacker_ip, dst_ip, n_ports=15)

    # Inbound SMB exploit attempts (445)
    ts = base + timedelta(seconds=25)
    sig = pick([s for s in THREAT_SIGS_CRED if "SMB" in s[0] or "ZeroLogon" in s[0]])
    events.append((ts, _threat(ts, src_ip=attacker_ip, dst_ip=dst_ip,
                               sig=sig, dport=445)))

    # Mimikatz signature seen on outbound (process trying to call home)
    ts = base + timedelta(seconds=45)
    mk_sig = ("Mimikatz Credential Dumper", "86002", "critical", "virus")
    events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=attacker_ip,
                               sig=mk_sig, src_user=victim_user)))

    # Kerberos golden-ticket anomaly
    ts = base + timedelta(seconds=70)
    kerb_sig = ("Kerberos Golden Ticket Anomaly", "57010", "critical",
                "vulnerability")
    events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=pick(INTERNAL_IPS),
                               sig=kerb_sig, src_user=victim_user)))
    return "credential-dump"


def _chain_c2_exfil(base, attacker_ip, victim_user, dst_ip, events):
    """manager victim — C2 beacon + DNS tunneling + exfil (mirrors Cobalt Strike EDR)."""
    _port_scan(events, base, attacker_ip, dst_ip, n_ports=15)

    # Cobalt Strike beacon on 443
    ts = base + timedelta(seconds=30)
    cs_sig = ("Cobalt Strike Beacon", "86001", "critical", "spyware")
    events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=attacker_ip,
                               sig=cs_sig, src_user=victim_user, dport=443)))

    # PowerShell Empire signature
    ts = base + timedelta(seconds=60)
    emp_sig = ("PowerShell Empire C2", "86003", "critical", "spyware")
    events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=attacker_ip,
                               sig=emp_sig, src_user=victim_user, dport=443)))

    # Repeated DNS tunneling
    dns_sig = ("DNS Tunneling Detected", "12346", "high", "spyware")
    for i in range(8):
        ts = base + timedelta(seconds=90 + i * 5)
        events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=pick(EXTERNAL_IPS),
                                   sig=dns_sig, src_user=victim_user, dport=53)))

    # URL-block: outbound to TOR / C2 site (correlated to EDR)
    ts = base + timedelta(seconds=150)
    events.append((ts, _url(ts, src_ip=dst_ip, blocked=True,
                            src_user=victim_user,
                            host="c2-server.evil.example",
                            category="command-and-control")))

    # Final: suspicious file upload outbound
    ts = base + timedelta(seconds=180)
    upload_sig = ("Suspicious File Upload to External", "40050", "high",
                  "vulnerability")
    events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=attacker_ip,
                               sig=upload_sig, src_user=victim_user)))
    return "c2-exfil"


def _chain_ransomware(base, attacker_ip, victim_user, dst_ip, events):
    """user victim — drive-by download → ransomware C2 (mirrors ransomware EDR)."""
    # Drive-by drop: URL block to malicious site
    ts = base + timedelta(seconds=5)
    events.append((ts, _url(ts, src_ip=dst_ip, blocked=True,
                            src_user=victim_user,
                            host="drop-zone.fake-cdn.example",
                            category="malware")))

    # The download itself: TRAFFIC allow on 80 to the attacker_ip
    ts = base + timedelta(seconds=10)
    events.append((ts, _traffic(ts, src_ip=dst_ip, dst_ip=attacker_ip,
                                action="allow", dport=80, app="web-browsing")))

    # WildFire / AV catches the binary
    ts = base + timedelta(seconds=20)
    ransom_sig = pick(THREAT_SIGS_RANSOM)
    events.append((ts, _threat(ts, src_ip=attacker_ip, dst_ip=dst_ip,
                               sig=ransom_sig, src_user=victim_user)))

    # Ransomware C2 beacon
    ts = base + timedelta(seconds=60)
    cs_sig = ("Ransomware C2 Communication", "86006", "critical", "spyware")
    events.append((ts, _threat(ts, src_ip=dst_ip, dst_ip=attacker_ip,
                               sig=cs_sig, src_user=victim_user, dport=443)))

    # Several URL blocks as ransomware tries different C2 hosts
    for i in range(4):
        ts = base + timedelta(seconds=90 + i * 30)
        events.append((ts, _url(ts, src_ip=dst_ip, blocked=True,
                                src_user=victim_user,
                                host=pick(URL_HOSTS_BAD),
                                category="command-and-control")))
    return "ransomware"


# =========================================================================
# Scenario dispatch (mirrors EDR)
# =========================================================================
def _dispatch_scenario(incident, events):
    """Pick PA-side chain to match the EDR scenario for this victim_priv."""
    priv = incident.get("victim_priv", "user")
    base = rand_recent(25)
    attacker_ip = incident["attacker_ip"]
    victim_user = incident["victim_user"]
    dst_ip = pick(SERVER_IPS)

    if priv == "service":
        return _chain_web_compromise(base, attacker_ip, victim_user,
                                     dst_ip, events)
    elif priv == "admin":
        return _chain_credential_dump(base, attacker_ip, victim_user,
                                      dst_ip, events)
    elif priv == "manager":
        return _chain_c2_exfil(base, attacker_ip, victim_user, dst_ip, events)
    else:
        return _chain_ransomware(base, attacker_ip, victim_user, dst_ip, events)


# =========================================================================
# Main
# =========================================================================
def generate(path: Path, count: int = 40) -> None:
    events = []

    # ----------------------------------------------------------------
    # Baseline traffic
    # ----------------------------------------------------------------
    for _ in range(count * 2):
        ts = rand_recent(60)
        events.append((ts, _traffic(ts, action="allow")))

    for _ in range(15):
        ts = rand_recent(60)
        events.append((ts, _url(ts, blocked=False)))

    # ----------------------------------------------------------------
    # CORRELATED chains — per-incident, mirror EDR scenario type
    # ----------------------------------------------------------------
    chain_types = []
    for incident in INCIDENTS:
        chain_type = _dispatch_scenario(incident, events)
        chain_types.append(
            f"{chain_type:18s} {incident['attacker_ip']:>16s} → "
            f"{incident['victim_user']}")

    # ----------------------------------------------------------------
    # Standalone (uncorrelated) noise
    # ----------------------------------------------------------------
    # Random threat events (mix of severities)
    for _ in range(20):
        ts = rand_recent(30)
        events.append((ts, _threat(ts)))

    # URL blocks (random users hitting bad categories)
    for _ in range(15):
        ts = rand_recent(30)
        events.append((ts, _url(ts, blocked=True)))

    # Brute-force HTTP auth on internet-exposed apps
    for _ in range(6):
        ts = rand_recent(45)
        sig = ("Brute Force HTTP Basic Authentication", "40015", "medium",
               "vulnerability")
        events.append((ts, _threat(ts, sig=sig, dport=443)))

    # Outbound to TOR (low-priority background)
    for _ in range(4):
        ts = rand_recent(60)
        tor_sig = ("Suspicious Outbound to TOR", "30001", "medium", "spyware")
        events.append((ts, _threat(ts, src_ip=pick(INTERNAL_IPS), sig=tor_sig)))

    # Sort + write
    events.sort(key=lambda x: x[0])
    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} Palo Alto events -> {path.name}")
    print(f"  correlated chains ({len(INCIDENTS)}):")
    for ct in chain_types:
        print(f"    {ct}")
