"""
MySQL log generator.

Mixes general query log + error log style. Wazuh's mysql_log decoder + rules:

  - "Access denied for user 'root'@'X' (using password: YES)"  -> auth-failure
  - Repeated denied access from same host                      -> brute force
  - GRANT / DROP DATABASE on production                        -> privilege escalation
  - Suspicious UNION SELECT / LOAD_FILE / SLEEP() in queries   -> SQLi behind app

NEW: same attacker IPs as auth.log / mssql_audit.log / paloalto.csv appear
here as MY-010926 Access-denied bursts. Same scenario victim users show up
running GRANT/CREATE USER/DROP statements.
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    USERNAMES, INTERNAL_IPS, ATTACKER_IPS,
    DATABASES_BANKING, DATABASES_SENSITIVE,
    pick_normal_user, pick_noisy_user,
    rand_recent, iso_z, pick,
)
from .shared_state import INCIDENTS


# MySQL 8.x error log format:  2026-05-11T10:30:45.123456Z 12 [Note] [MY-010914] ...
def _err_ts(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}Z"


# General query log:  2026-05-11T10:30:45.123Z   12 Query   SELECT ...
def _gen_ts(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


# =========================================================================
# Line builders
# =========================================================================
def _access_denied(ts, user=None, ip=None, with_password=True):
    user = user or pick(USERNAMES)
    ip = ip or pick(INTERNAL_IPS)
    pw = "YES" if with_password else "NO"
    tid = random.randint(10, 999)
    return (f"{_err_ts(ts)} {tid} [Note] [MY-010926] [Server] "
            f"Access denied for user '{user}'@'{ip}' (using password: {pw})")


def _connect_ok(ts, user=None, ip=None):
    user = user or pick_normal_user()["username"]
    ip = ip or pick(INTERNAL_IPS)
    tid = random.randint(10, 999)
    return f"{_gen_ts(ts)}\t{tid:>3} Connect\t{user}@{ip} on  using TCP/IP"


def _query(ts, sql, user=None):
    tid = random.randint(10, 999)
    return f"{_gen_ts(ts)}\t{tid:>3} Query\t{sql}"


def _normal_query(ts, user=None, db=None):
    """Realistic banking app query (baseline noise)."""
    db = db or pick(DATABASES_BANKING).lower()
    sql = pick([
        f"SELECT id, name FROM {db}.customers WHERE active=1 LIMIT 50",
        f"UPDATE {db}.orders SET status='shipped' WHERE id={random.randint(1000, 9999)}",
        f"INSERT INTO {db}.audit_log(user, action, ts) VALUES ('{pick_normal_user()['username']}', 'login', NOW())",
        f"SELECT COUNT(*) FROM {db}.sessions WHERE expires_at > NOW()",
        f"SELECT balance FROM {db}.accounts WHERE customer_id={random.randint(1000, 9999)}",
        f"CALL {db}.sp_eod_settlement()",
    ])
    return _query(ts, sql, user=user)


def _sqli_query(ts, user=None, db=None):
    db = db or pick(DATABASES_SENSITIVE).lower()
    sql = pick([
        f"SELECT * FROM {db}.users WHERE id=1 UNION SELECT user,password FROM mysql.user-- ",
        f"SELECT * FROM {db}.products WHERE name='' OR '1'='1' -- ",
        "SELECT load_file('/etc/passwd')",
        "SELECT load_file('/etc/mysql/my.cnf')",
        f"SELECT * FROM {db}.users WHERE id=1 AND SLEEP(5)",
        f"SELECT * FROM {db}.users WHERE id=1 INTO OUTFILE '/tmp/users.txt'",
        f"SELECT @@version, @@datadir, @@hostname FROM {db}.users",
        f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db}'",
    ])
    return _query(ts, sql)


def _privilege_change(ts, actor=None, target=None):
    actor = actor or pick(["root", "admin", "svc_mysql"])
    target = target or pick(USERNAMES)
    sql = pick([
        f"GRANT ALL PRIVILEGES ON *.* TO '{target}'@'%' WITH GRANT OPTION",
        f"CREATE USER 'backdoor_{random.randint(100, 999)}'@'%' IDENTIFIED BY 'Pa$$w0rd!'",
        f"GRANT FILE ON *.* TO '{target}'@'%'",
        f"GRANT SUPER, REPLICATION CLIENT ON *.* TO '{target}'@'%'",
        f"ALTER USER '{target}'@'%' IDENTIFIED BY 'NewPa$$w0rd!'",
    ])
    return _query(ts, sql)


def _destructive_ddl(ts, db=None):
    db = db or pick(DATABASES_BANKING).lower()
    sql = pick([
        f"DROP DATABASE {db}",
        f"DROP TABLE {db}.fraud_rules",
        f"TRUNCATE TABLE {db}.audit_log",
        f"DELETE FROM {db}.transactions WHERE 1=1",
    ])
    return _query(ts, sql)


def _data_export(ts, db=None):
    """Bulk data export — exfil indicator."""
    db = db or pick(DATABASES_SENSITIVE).lower()
    sql = pick([
        f"SELECT * FROM {db}.card_data INTO OUTFILE '/tmp/cards.csv' "
        f"FIELDS TERMINATED BY ','",
        f"SELECT card_number, cvv, expiry FROM {db}.cards LIMIT 100000",
    ])
    return _query(ts, sql)


def _slow_query(ts, db=None):
    """Slow query — sometimes benign (poor join), sometimes scraping."""
    db = db or pick(DATABASES_BANKING).lower()
    qtime = random.randint(10, 120)
    tid = random.randint(10, 999)
    return (f"{_gen_ts(ts)}\t{tid:>3} Query\t"
            f"# Time: {qtime} Lock_time: 0.001 Rows_sent: {random.randint(10000, 1000000)} "
            f"SELECT * FROM {db}.transactions WHERE ts > '2024-01-01'")


def _replication_event(ts):
    tid = random.randint(10, 999)
    return (f"{_err_ts(ts)} {tid} [Note] [MY-010583] [Repl] "
            f"Slave I/O thread: Connected to master 'repl@10.20.1.11:3306' "
            f"replication started in log 'mysql-bin.000123' at position {random.randint(1000, 99999)}")


def _shutdown_event(ts):
    return (f"{_err_ts(ts)} 0 [System] [MY-010910] [Server] "
            f"/usr/sbin/mysqld: Shutdown complete (mysqld 8.0.36)")


def _startup_event(ts):
    return (f"{_err_ts(ts)} 0 [System] [MY-010931] [Server] "
            f"/usr/sbin/mysqld: ready for connections. "
            f"Version: '8.0.36'  socket: '/var/run/mysqld/mysqld.sock'  port: 3306")


# =========================================================================
# Main generator
# =========================================================================
def generate(path: Path, count: int = 40) -> None:
    events = []

    # --- Baseline: connections + normal queries -----------------------
    for _ in range(count // 2):
        ts = rand_recent(60)
        events.append((ts, _connect_ok(ts)))
    for _ in range(count):
        ts = rand_recent(60)
        events.append((ts, _normal_query(ts)))

    # Periodic replication / slow query noise
    for _ in range(3):
        ts = rand_recent(60)
        events.append((ts, _replication_event(ts)))
    for _ in range(4):
        ts = rand_recent(60)
        events.append((ts, _slow_query(ts)))

    # ----------------------------------------------------------------
    # SCENARIO-DRIVEN: brute-force from each incident attacker
    # ----------------------------------------------------------------
    for incident in INCIDENTS:
        attacker_ip = incident["attacker_ip"]
        victim_user = incident["victim_user"]
        target_db   = incident["target_db"].lower()

        # 12-16 Access-denied bursts from attacker IP against 'root'
        base = rand_recent(25)
        n_attempts = random.randint(12, 16)
        for i in range(n_attempts):
            ts = base + timedelta(seconds=i * 2)
            events.append((ts, _access_denied(
                ts, user="root", ip=attacker_ip, with_password=True)))

        # A few "no password" attempts (common scanner behavior)
        for _ in range(3):
            ts = base + timedelta(seconds=n_attempts * 2 + random.randint(1, 8))
            events.append((ts, _access_denied(
                ts, user=pick(["admin", "mysql", "test"]),
                ip=attacker_ip, with_password=False)))

        # Then a successful connection by the scenario victim user
        ts = base + timedelta(seconds=n_attempts * 2 + 25)
        events.append((ts, _connect_ok(ts, user=victim_user, ip=attacker_ip)))

        # If privileged victim, do damage
        if incident["victim_priv"] in ("admin", "manager", "service"):
            # Privilege escalation
            ts = base + timedelta(seconds=n_attempts * 2 + 40)
            events.append((ts, _privilege_change(
                ts, actor=victim_user, target=victim_user)))

            # SQLi-style probing on the target DB
            ts = base + timedelta(seconds=n_attempts * 2 + 60)
            events.append((ts, _sqli_query(ts, user=victim_user, db=target_db)))

            # Data exfil via OUTFILE
            ts = base + timedelta(seconds=n_attempts * 2 + 80)
            events.append((ts, _data_export(ts, db=target_db)))

            # Slow query — bulk dump
            ts = base + timedelta(seconds=n_attempts * 2 + 100)
            events.append((ts, _slow_query(ts, db=target_db)))

            # Destructive DDL — destroy evidence
            ts = base + timedelta(seconds=n_attempts * 2 + 140)
            events.append((ts, _destructive_ddl(ts, db="audit_log")))

    # ----------------------------------------------------------------
    # STANDALONE attacks (rule coverage)
    # ----------------------------------------------------------------

    # Scattered access-denied events
    for _ in range(5):
        ts = rand_recent(60)
        events.append((ts, _access_denied(ts)))

    # Standalone SQL injection probes
    for _ in range(5):
        ts = rand_recent(20)
        events.append((ts, _sqli_query(ts)))

    # Standalone privilege escalation / destructive DDL
    for _ in range(2):
        ts = rand_recent(15)
        events.append((ts, _privilege_change(ts)))
    ts = rand_recent(15); events.append((ts, _destructive_ddl(ts)))
    ts = rand_recent(15); events.append((ts, _data_export(ts)))

    # Single startup or shutdown event
    ts = rand_recent(120)
    events.append((ts, _startup_event(ts)))

    events.sort(key=lambda x: x[0])
    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} MySQL events -> {path.name}")
    print(f"  scenario-driven MySQL chains: {len(INCIDENTS)} "
          f"(attackers: {[i['attacker_ip'] for i in INCIDENTS]})")
