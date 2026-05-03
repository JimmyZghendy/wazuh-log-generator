"""
MySQL log generator.

Mixes general query log + error log style. Wazuh's mysql_log decoder + custom
rules catch:

  - "Access denied for user 'root'@'X' (using password: YES)"  -> auth-failure rule
  - Repeated denied access from same host                      -> brute force
  - GRANT / DROP DATABASE on production                        -> privilege escalation
  - Suspicious UNION SELECT in query log                       -> SQLi behind app
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    USERNAMES, INTERNAL_IPS, ATTACKER_IPS,
    rand_recent, iso_z, pick,
)

# MySQL 8.x error log format:  2026-05-11T10:30:45.123456Z 12 [Note] [MY-010914] ...
def _err_ts(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}Z"

# General query log format:  2026-05-11T10:30:45.123Z   12 Query   SELECT ...
def _gen_ts(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _access_denied(ts, attacker=False):
    user = pick(["root", "admin", "mysql"]) if attacker else pick(USERNAMES)
    ip = pick(ATTACKER_IPS) if attacker else pick(INTERNAL_IPS)
    tid = random.randint(10, 999)
    return (f"{_err_ts(ts)} {tid} [Note] [MY-010926] [Server] "
            f"Access denied for user '{user}'@'{ip}' (using password: YES)")


def _connect_ok(ts):
    tid = random.randint(10, 999)
    user = pick(USERNAMES)
    ip = pick(INTERNAL_IPS)
    return f"{_gen_ts(ts)}\t{tid:>3} Connect\t{user}@{ip} on  using TCP/IP"


def _query(ts, sql):
    tid = random.randint(10, 999)
    return f"{_gen_ts(ts)}\t{tid:>3} Query\t{sql}"


def _normal_query(ts):
    sql = pick([
        "SELECT id, name FROM customers WHERE active=1",
        "UPDATE orders SET status='shipped' WHERE id=4711",
        "INSERT INTO audit_log(user, action) VALUES('jsmith', 'login')",
        "SELECT COUNT(*) FROM sessions",
    ])
    return _query(ts, sql)


def _sqli_query(ts):
    sql = pick([
        "SELECT * FROM users WHERE id=1 UNION SELECT user,password FROM mysql.user-- ",
        "SELECT * FROM products WHERE name='' OR '1'='1' -- ",
        "SELECT load_file('/etc/passwd')",
        "SELECT * FROM users WHERE id=1 AND SLEEP(5)",
    ])
    return _query(ts, sql)


def _privilege_change(ts):
    target = pick(USERNAMES)
    sql = pick([
        f"GRANT ALL PRIVILEGES ON *.* TO '{target}'@'%' WITH GRANT OPTION",
        f"CREATE USER 'backdoor_{random.randint(100,999)}'@'%' IDENTIFIED BY 'Pa$$w0rd!'",
        "DROP DATABASE production",
        "GRANT FILE ON *.* TO 'webapp'@'%'",
    ])
    return _query(ts, sql)


def _shutdown_event(ts):
    return (f"{_err_ts(ts)} 0 [System] [MY-010910] [Server] "
            f"/usr/sbin/mysqld: Shutdown complete (mysqld 8.0.36)")


def generate(path: Path, count: int = 40) -> None:
    events = []

    # Baseline: connections + normal queries
    for _ in range(count // 2):
        ts = rand_recent(60)
        events.append((ts, _connect_ok(ts)))
    for _ in range(count // 2):
        ts = rand_recent(60)
        events.append((ts, _normal_query(ts)))

    # Brute-force burst against root from one attacker IP
    base = rand_recent(20)
    attacker_ip = pick(ATTACKER_IPS)
    for i in range(12):
        ts = base + timedelta(seconds=i * 2)
        tid = random.randint(10, 999)
        events.append((ts,
            f"{_err_ts(ts)} {tid} [Note] [MY-010926] [Server] "
            f"Access denied for user 'root'@'{attacker_ip}' (using password: YES)"))

    # Scattered access-denied events
    for _ in range(4):
        ts = rand_recent(60)
        events.append((ts, _access_denied(ts, attacker=False)))

    # Privilege escalation / dangerous DDL
    for _ in range(3):
        ts = rand_recent(15)
        events.append((ts, _privilege_change(ts)))

    # SQL-injection-style queries (as they would look in the general log)
    for _ in range(4):
        ts = rand_recent(20)
        events.append((ts, _sqli_query(ts)))

    # One shutdown event
    ts = rand_recent(10)
    events.append((ts, _shutdown_event(ts)))

    events.sort(key=lambda x: x[0])

    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} MySQL events -> {path.name}")
