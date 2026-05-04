"""
Linux auth.log / syslog generator.

Covers events that have direct, well-known Wazuh rule IDs in ruleset/sshd
and ruleset/pam:

  5710 - sshd "Failed password" / "Invalid user"  (per-event)
  5712 - sshd brute force (frequency)
  5715 - sshd successful login
  5402 - sudo command executed
  5401 - sudo failed (incorrect password)
  5503 - PAM authentication failure
  5404 - root login refused
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    USERNAMES, PRIV_USERS, INTERNAL_IPS, ATTACKER_IPS,
    rand_recent, syslog_ts, pick,
)

HOST = "srv-app01"


def _sshd_invalid_user(ts, ip, user):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {HOST} sshd[{pid}]: "
            f"Invalid user {user} from {ip} port {random.randint(40000,60000)}")


def _sshd_failed_password(ts, ip, user):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {HOST} sshd[{pid}]: "
            f"Failed password for {'invalid user ' if user not in USERNAMES else ''}"
            f"{user} from {ip} port {random.randint(40000,60000)} ssh2")


def _sshd_accepted(ts, ip, user):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {HOST} sshd[{pid}]: "
            f"Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2")


def _sshd_pubkey(ts, ip, user):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {HOST} sshd[{pid}]: "
            f"Accepted publickey for {user} from {ip} port "
            f"{random.randint(40000,60000)} ssh2: RSA SHA256:abc123...")


def _root_login_refused(ts, ip):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {HOST} sshd[{pid}]: "
            f"User root from {ip} not allowed because not listed in AllowUsers")


def _sudo_ok(ts):
    user = pick(USERNAMES)
    cmd = pick(["/usr/bin/apt update", "/bin/systemctl restart nginx",
                "/usr/bin/cat /var/log/syslog", "/bin/ls /root"])
    return (f"{syslog_ts(ts)} {HOST} sudo: "
            f" {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")


def _sudo_fail(ts):
    user = pick(USERNAMES)
    return (f"{syslog_ts(ts)} {HOST} sudo:  {user} : "
            f"{random.randint(1,3)} incorrect password attempts ; "
            f"TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
            f"COMMAND=/usr/bin/cat /etc/shadow")


def _pam_failure(ts):
    user = pick(USERNAMES)
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {HOST} sshd[{pid}]: "
            f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
            f"tty=ssh ruser= rhost={pick(ATTACKER_IPS)}  user={user}")


def _useradd(ts):
    new = f"oper_{random.randint(100,999)}"
    return (f"{syslog_ts(ts)} {HOST} useradd[{random.randint(1000,9999)}]: "
            f"new user: name={new}, UID=1050, GID=1050, home=/home/{new}, "
            f"shell=/bin/bash, from=/dev/pts/0")


def generate(path: Path, count: int = 40) -> None:
    events = []

    # --- Normal logins ---------------------------------------------------
    for _ in range(count // 2):
        ts = rand_recent(60)
        events.append((ts, _sshd_accepted(ts, pick(INTERNAL_IPS), pick(USERNAMES))))
    for _ in range(5):
        ts = rand_recent(60)
        events.append((ts, _sshd_pubkey(ts, pick(INTERNAL_IPS), pick(USERNAMES))))

    # --- SSH brute force from one external IP (20 failures in ~1 minute) -
    base = rand_recent(20)
    attacker = pick(ATTACKER_IPS)
    bf_users = ["root", "admin", "test", "ubuntu", "postgres", "oracle"]
    for i in range(20):
        ts = base + timedelta(seconds=i * 3)
        user = pick(bf_users)
        if user not in USERNAMES:
            events.append((ts, _sshd_invalid_user(ts, attacker, user)))
        events.append((ts, _sshd_failed_password(ts, attacker, user)))

    # ...ending with one success (compromise!)
    ts = base + timedelta(seconds=70)
    events.append((ts, _sshd_accepted(ts, attacker, "ubuntu")))

    # --- Scattered routine failures --------------------------------------
    for _ in range(6):
        ts = rand_recent(60)
        events.append((ts, _sshd_failed_password(ts, pick(INTERNAL_IPS), pick(USERNAMES))))

    # --- Root direct-login attempts --------------------------------------
    for _ in range(3):
        ts = rand_recent(45)
        events.append((ts, _root_login_refused(ts, pick(ATTACKER_IPS))))

    # --- Sudo activity (ok + failed) -------------------------------------
    for _ in range(8):
        ts = rand_recent(45)
        events.append((ts, _sudo_ok(ts)))
    for _ in range(3):
        ts = rand_recent(20)
        events.append((ts, _sudo_fail(ts)))

    # --- PAM failures ----------------------------------------------------
    for _ in range(4):
        ts = rand_recent(30)
        events.append((ts, _pam_failure(ts)))

    # --- Useradd (post-compromise persistence) ---------------------------
    ts = rand_recent(10)
    events.append((ts, _useradd(ts)))

    events.sort(key=lambda x: x[0])

    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} auth events -> {path.name}")
