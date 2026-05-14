"""
Palo Alto Networks log generator (corrected field positions).

Real PAN-OS 8.x-10.x syslog format has ~70 fields per record. The Wazuh
paloalto decoder maps fields by position, so the column count and ordering
matter precisely.

Fields are documented at:
  https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions

Subtypes produced:
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

SERIAL = "012345678901"
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
    """
    TRAFFIC log line.

    PAN-OS TRAFFIC has 65+ fields. Common positions:
      FUTURE_USE, RECEIVE_TIME, SERIAL, TYPE, SUBTYPE, FUTURE_USE, GENERATED_TIME,
      SRC, DST, NAT_SRC, NAT_DST, RULE, SRC_USER, DST_USER, APP, VSYS, FROM_ZONE,
      TO_ZONE, INBOUND_IF, OUTBOUND_IF, LOG_PROFILE, FUTURE_USE, SESSION_ID,
      REPEAT_COUNT, SRC_PORT, DST_PORT, NAT_SRC_PORT, NAT_DST_PORT, FLAGS, PROTO,
      ACTION, BYTES, BYTES_SENT, BYTES_RECV, PACKETS, START_TIME, ELAPSED,
      CATEGORY, FUTURE_USE, SEQNO, ACTION_FLAGS, SRC_LOC, DST_LOC, FUTURE_USE,
      PKTS_SENT, PKTS_RECV, SESSION_END_REASON, DG_HIER_LVL_1, DG_HIER_LVL_2,
      DG_HIER_LVL_3, DG_HIER_LVL_4, VSYS_NAME, DEVICE_NAME, ACTION_SOURCE,
      SRC_VM_UUID, DST_VM_UUID, TUNNEL_ID/IMSI, MONITOR_TAG/IMEI, PARENT_SESSION_ID,
      PARENT_START_TIME, TUNNEL, ASSOC_ID, CHUNKS, CHUNKS_SENT, CHUNKS_RECV,
      RULE_UUID, HTTP/2 CONNECTION
    """
    src = pick(ATTACKER_IPS) if attacker else pick(INTERNAL_IPS)
    dst = pick(INTERNAL_IPS) if attacker else pick(INTERNAL_IPS + EXTERNAL_IPS)
    sport = random.randint(49152, 65535)
    dport = pick([22, 80, 443, 445, 3389, 3306, 1433, 8080])
    app = pick(["web-browsing", "ssl", "ssh", "ms-sql-db", "mysql", "ms-ds-smb"])
    rule_name = "Allow-Internal" if action == "allow" else "Block-Suspicious"
    bytes_sent = random.randint(100, 50000)
    bytes_recv = random.randint(100, 500000)

    fields = [
        "1",                          # 1  FUTURE_USE
        palo_ts(ts),                  # 2  Receive Time
        SERIAL,                       # 3  Serial #
        "TRAFFIC",                    # 4  Type
        "end",                        # 5  Subtype
        "2049",                       # 6  FUTURE_USE
        palo_ts(ts),                  # 7  Generated Time
        src,                          # 8  Source IP
        dst,                          # 9  Destination IP
        "0.0.0.0",                    # 10 NAT Source IP
        "0.0.0.0",                    # 11 NAT Destination IP
        rule_name,                    # 12 Rule Name
        "",                           # 13 Source User
        "",                           # 14 Destination User
        app,                          # 15 Application
        "vsys1",                      # 16 Virtual System
        "trust",                      # 17 Source Zone
        "untrust",                    # 18 Destination Zone
        "ethernet1/1",                # 19 Inbound Interface
        "ethernet1/2",                # 20 Outbound Interface
        "default",                    # 21 Log Action
        palo_ts(ts),                  # 22 FUTURE_USE
        str(random.randint(100000, 999999)),  # 23 Session ID
        "1",                          # 24 Repeat Count
        str(sport),                   # 25 Source Port
        str(dport),                   # 26 Destination Port
        "0",                          # 27 NAT Source Port
        "0",                          # 28 NAT Destination Port
        "0x400000",                   # 29 Flags
        "tcp",                        # 30 IP Protocol
        action,                       # 31 Action  <-- CRITICAL FIELD
        str(bytes_sent + bytes_recv), # 32 Bytes
        str(bytes_sent),              # 33 Bytes Sent
        str(bytes_recv),              # 34 Bytes Received
        str(random.randint(2, 50)),   # 35 Packets
        palo_ts(ts),                  # 36 Start Time
        str(random.randint(1, 600)),  # 37 Elapsed Time
        "any",                        # 38 Category
        "",                           # 39 FUTURE_USE
        str(random.randint(1000000, 9999999)),  # 40 Sequence Number
        "0x0",                        # 41 Action Flags
        "10.0.0.0-10.255.255.255",    # 42 Source Country
        "United States",              # 43 Destination Country
        "",                           # 44 FUTURE_USE
        str(random.randint(1, 25)),   # 45 Packets Sent
        str(random.randint(1, 25)),   # 46 Packets Received
        "n/a",                        # 47 Session End Reason
        "0",                          # 48 DG Hierarchy Level 1
        "0",                          # 49 DG Hierarchy Level 2
        "0",                          # 50 DG Hierarchy Level 3
        "0",                          # 51 DG Hierarchy Level 4
        "",                           # 52 Virtual System Name
        DEVICE,                       # 53 Device Name
        "from-policy",                # 54 Action Source
        "",                           # 55 Source VM UUID
        "",                           # 56 Destination VM UUID
        "0",                          # 57 Tunnel ID/IMSI
        "",                           # 58 Monitor Tag/IMEI
        "0",                          # 59 Parent Session ID
        "",                           # 60 Parent Start Time
        "N/A",                        # 61 Tunnel Type
        "0",                          # 62 SCTP Association ID
        "0",                          # 63 SCTP Chunks
        "0",                          # 64 SCTP Chunks Sent
        "0",                          # 65 SCTP Chunks Received
        f"{random.randint(10000000,99999999)}-{random.randint(1000,9999)}-"
        f"{random.randint(1000,9999)}-{random.randint(1000,9999)}-"
        f"{random.randint(100000000000,999999999999)}",  # 66 Rule UUID
        "0",                          # 67 HTTP/2 Connection
    ]
    return ",".join(fields)


def _threat(ts):
    """
    THREAT log line. PAN-OS THREAT has ~70+ fields. Severity (position 33)
    is the field Wazuh uses to determine alert level.

    Positions reference (1-indexed):
      31 = miscellaneous (URL/filename),  32 = threat ID,  33 = severity,
      34 = direction,  35 = sequence number,  36 = action flags,
      37 = source country,  38 = dest country,  39 = future_use,
      40 = content-type,  41 = pcap-id, ...
    """
    src = pick(ATTACKER_IPS + EXTERNAL_IPS)
    dst = pick(INTERNAL_IPS)
    name, sid, sev = pick(THREAT_SIGS)
    sport = random.randint(49152, 65535)
    dport = pick([80, 443, 445, 3389, 22])

    subtype = pick(["vulnerability", "spyware", "virus", "wildfire-virus"])
    miscellaneous = f'"http://malicious.example/{sid}"'   # URL or filename (must be quoted)
    threat_name_quoted = f'"{name}({sid})"'

    fields = [
        "1",                          # 1  FUTURE_USE
        palo_ts(ts),                  # 2  Receive Time
        SERIAL,                       # 3  Serial #
        "THREAT",                     # 4  Type
        subtype,                      # 5  Threat/Content Type (subtype)
        "2049",                       # 6  FUTURE_USE
        palo_ts(ts),                  # 7  Generated Time
        src,                          # 8  Source IP
        dst,                          # 9  Destination IP
        "0.0.0.0",                    # 10 NAT Source IP
        "0.0.0.0",                    # 11 NAT Destination IP
        "Block-Threats",              # 12 Rule
        "",                           # 13 Source User
        "",                           # 14 Destination User
        pick(["web-browsing", "ssl", "ms-ds-smb"]),  # 15 Application
        "vsys1",                      # 16 Virtual System
        "untrust",                    # 17 Source Zone
        "trust",                      # 18 Destination Zone
        "ethernet1/2",                # 19 Inbound Interface
        "ethernet1/1",                # 20 Outbound Interface
        "default",                    # 21 Log Action
        palo_ts(ts),                  # 22 FUTURE_USE
        str(random.randint(100000, 999999)),  # 23 Session ID
        "1",                          # 24 Repeat Count
        str(sport),                   # 25 Source Port
        str(dport),                   # 26 Destination Port
        "0",                          # 27 NAT Source Port
        "0",                          # 28 NAT Destination Port
        "0x80004000",                 # 29 Flags
        "tcp",                        # 30 IP Protocol
        "reset-both",                 # 31 Action  (was 'reset-server' / 'reset-both' / 'drop')
        miscellaneous,                # 32 Miscellaneous (URL/filename)
        threat_name_quoted,           # 33 Threat ID / name
        "any",                        # 34 Category
        sev,                          # 35 Severity   <-- HOW WAZUH PICKS RULE LEVEL
        "client-to-server",           # 36 Direction
        str(random.randint(1000000, 9999999)),  # 37 Sequence Number
        "0xa000000000000000",         # 38 Action Flags
        "United States",              # 39 Source Country
        "10.0.0.0-10.255.255.255",    # 40 Destination Country
        "",                           # 41 FUTURE_USE
        "0",                          # 42 Content-Type
        "0",                          # 43 PCAP ID
        "0",                          # 44 File Digest
        "",                           # 45 Cloud
        "",                           # 46 URL Index
        "",                           # 47 User Agent
        "",                           # 48 File Type
        "",                           # 49 X-Forwarded-For
        "",                           # 50 Referer
        "",                           # 51 Sender
        "",                           # 52 Subject
        "",                           # 53 Recipient
        "",                           # 54 Report ID
        "0",                          # 55 DG Hierarchy Level 1
        "0",                          # 56 DG Hierarchy Level 2
        "0",                          # 57 DG Hierarchy Level 3
        "0",                          # 58 DG Hierarchy Level 4
        "",                           # 59 Virtual System Name
        DEVICE,                       # 60 Device Name
        "",                           # 61 FUTURE_USE
        "",                           # 62 Source VM UUID
        "",                           # 63 Destination VM UUID
        "",                           # 64 HTTP Method
        "",                           # 65 Tunnel ID
        "",                           # 66 Monitor Tag
        "",                           # 67 Parent Session ID
        "",                           # 68 Parent Start Time
        "N/A",                        # 69 Tunnel Type
        subtype,                      # 70 Threat Category
        "",                           # 71 Content Version
        "0",                          # 72 FUTURE_USE
        f"{random.randint(10000000,99999999)}-{random.randint(1000,9999)}-"
        f"{random.randint(1000,9999)}-{random.randint(1000,9999)}-"
        f"{random.randint(100000000000,999999999999)}",  # 73 Rule UUID
        "0",                          # 74 HTTP/2 Connection
    ]
    return ",".join(fields)


def _url(ts, blocked=False):
    """URL filtering log line. Same THREAT structure but subtype=url."""
    src = pick(INTERNAL_IPS)
    dst = pick(EXTERNAL_IPS)
    cat = pick(URL_CATEGORIES_BAD) if blocked else pick(URL_CATEGORIES_OK)
    action = "block-url" if blocked else "alert"
    severity = "high" if blocked else "informational"
    host = pick([
        "malicious-site.example.com",
        "phishing-login.example.net",
        "c2-server.evil.example",
        "github.com",
        "stackoverflow.com",
    ])
    uri = pick(["/", "/login", "/wp-admin", "/api/v1/data", "/download/x.exe"])

    fields = [
        "1",
        palo_ts(ts),
        SERIAL,
        "THREAT",
        "url",                        # subtype = url
        "2049",
        palo_ts(ts),
        src,
        dst,
        "0.0.0.0",
        "0.0.0.0",
        "URL-Filter",
        "",
        "",
        "web-browsing",
        "vsys1",
        "trust",
        "untrust",
        "ethernet1/1",
        "ethernet1/2",
        "default",
        palo_ts(ts),
        str(random.randint(100000, 999999)),
        "1",
        str(random.randint(49152, 65535)),
        "443",
        "0",
        "0",
        "0x402000",
        "tcp",
        action,                       # 31 Action
        f'"{host}{uri}"',             # 32 Miscellaneous = URL
        '"(9999)"',                   # 33 Threat ID
        cat,                          # 34 Category   <-- URL CATEGORY
        severity,                     # 35 Severity
        "client-to-server",
        str(random.randint(1000000, 9999999)),
        "0x8000000000000000",
        "United States",
        "10.0.0.0-10.255.255.255",
        "",
        "0",
        "0",
        "0",
        "",
        "",
        "Mozilla/5.0",                # 47 User Agent
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "0", "0", "0", "0",
        "",
        DEVICE,
        "",
        "",
        "",
        "GET",                        # 64 HTTP Method
        "",
        "",
        "",
        "",
        "N/A",
        cat,                          # threat category = url category
        "",
        "0",
        f"{random.randint(10000000,99999999)}-{random.randint(1000,9999)}-"
        f"{random.randint(1000,9999)}-{random.randint(1000,9999)}-"
        f"{random.randint(100000000000,999999999999)}",
        "0",
    ]
    return ",".join(fields)


def generate(path: Path, count: int = 40) -> None:
    events = []

    # Normal allow traffic
    for _ in range(count):
        ts = rand_recent(60)
        events.append((ts, _traffic(ts, action="allow")))

    # Port-scan burst from one attacker (deny actions)
    base = rand_recent(20)
    scanner = pick(ATTACKER_IPS)
    for i in range(25):
        ts = base + timedelta(seconds=i)
        line = _traffic(ts, action="deny", attacker=True)
        parts = line.split(",")
        parts[7] = scanner                          # source IP field #8
        parts[25] = str(random.randint(1, 65535))   # dst port field #26
        events.append((ts, ",".join(parts)))

    # HEAVY: critical/high threats so high-severity rules fire
    for _ in range(80):
        ts = rand_recent(30)
        events.append((ts, _threat(ts)))

    # URL filtering - mostly blocked-malicious for visibility
    for _ in range(5):
        ts = rand_recent(60)
        events.append((ts, _url(ts, blocked=False)))
    for _ in range(40):
        ts = rand_recent(30)
        events.append((ts, _url(ts, blocked=True)))

    events.sort(key=lambda x: x[0])

    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} Palo Alto events -> {path.name}")