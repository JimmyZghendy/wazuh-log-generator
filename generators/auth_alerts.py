"""
Linux auth.log / syslog generator.

Covers events with direct Wazuh rule IDs:
  5710 - sshd "Failed password" / "Invalid user"  (per-event)
  5712 - sshd brute force (frequency)
  5715 - sshd successful login
  5402 - sudo command executed
  5401 - sudo failed (incorrect password)
  5503 - PAM authentication failure
  5404 - root login refused
  5901 - new group added
  5902 - new user added

NEW: pulls attacker IPs and victim usernames from generators.shared_state so
that the same IP and same username appear across MULTIPLE log sources. An
analyst (or AI agent) searching `data.srcip: <attacker>` will find the SSH
brute-force here, plus the AD failures, plus the MSSQL failures, plus the
firewall threats — all from the same attacker.
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    USERNAMES, PRIV_USERS, INTERNAL_IPS, VPN_IPS, ATTACKER_IPS,
    NOISY_USERS, NORMAL_USERS, pick_normal_user, pick_noisy_user,
    rand_recent, syslog_ts, pick, maybe,
)
from .shared_state import INCIDENTS


# Pick a banking-themed SSH host (the server they're attacking) for this run
SSH_HOSTS = [
    "ibank-app01", "ibank-app02",   # internet banking app tier
    "loan-app01",                   # loan origination
    "ops-jump01",                   # bastion / jump host
    "swift-gw01",                   # SWIFT gateway (Linux side)
    "backup01",
    "monitor01",
    "logaggr01",
]


# =========================================================================
# Low-level line builders
# =========================================================================
def _sshd_invalid_user(ts, ip, user, host):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} sshd[{pid}]: "
            f"Invalid user {user} from {ip} port {random.randint(40000, 60000)}")


def _sshd_failed_password(ts, ip, user, host, invalid=False):
    pid = random.randint(1000, 9999)
    inv = "invalid user " if invalid else ""
    return (f"{syslog_ts(ts)} {host} sshd[{pid}]: "
            f"Failed password for {inv}{user} from {ip} "
            f"port {random.randint(40000, 60000)} ssh2")


def _sshd_accepted(ts, ip, user, host, method="password"):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} sshd[{pid}]: "
            f"Accepted {method} for {user} from {ip} "
            f"port {random.randint(40000, 60000)} ssh2")


def _sshd_pubkey(ts, ip, user, host):
    pid = random.randint(1000, 9999)
    fpr = "SHA256:" + "".join(random.choices(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/", k=43))
    return (f"{syslog_ts(ts)} {host} sshd[{pid}]: "
            f"Accepted publickey for {user} from {ip} port "
            f"{random.randint(40000, 60000)} ssh2: RSA {fpr}")


def _sshd_disconnect(ts, ip, user, host):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} sshd[{pid}]: "
            f"Disconnected from user {user} {ip} "
            f"port {random.randint(40000, 60000)}")


def _root_login_refused(ts, ip, host):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} sshd[{pid}]: "
            f"User root from {ip} not allowed because not listed in AllowUsers")


def _sudo_ok(ts, user, host):
    cmd = pick([
        "/usr/bin/apt update",
        "/bin/systemctl restart nginx",
        "/bin/systemctl status wazuh-agent",
        "/usr/bin/cat /var/log/syslog",
        "/bin/ls /var/log/banking/",
        "/usr/bin/tail -f /var/log/audit/audit.log",
        "/usr/bin/journalctl -u corebank-api",
    ])
    return (f"{syslog_ts(ts)} {host} sudo: "
            f" {user} : TTY=pts/{random.randint(0,5)} ; "
            f"PWD=/home/{user} ; USER=root ; COMMAND={cmd}")


def _sudo_fail(ts, user, host):
    cmd = pick([
        "/usr/bin/cat /etc/shadow",
        "/bin/bash",
        "/usr/bin/passwd root",
        "/usr/sbin/visudo",
    ])
    return (f"{syslog_ts(ts)} {host} sudo:  {user} : "
            f"{random.randint(1, 3)} incorrect password attempts ; "
            f"TTY=pts/{random.randint(0,5)} ; PWD=/home/{user} ; "
            f"USER=root ; COMMAND={cmd}")


def _pam_failure(ts, user, ip, host):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} sshd[{pid}]: "
            f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
            f"tty=ssh ruser= rhost={ip}  user={user}")


def _useradd(ts, host, by_user="root"):
    """Persistence: ransomware/attacker adds a backdoor account."""
    new = f"oper_{random.randint(100, 999)}"
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} useradd[{pid}]: "
            f"new user: name={new}, UID=1050, GID=1050, home=/home/{new}, "
            f"shell=/bin/bash, from=/dev/pts/0")


def _groupadd_admin(ts, host, target_user):
    """Adding the new account to sudo group."""
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} usermod[{pid}]: "
            f"add '{target_user}' to group 'sudo'")


def _sftp_session(ts, ip, user, host, action="open"):
    """Vendor or back-office user moving files via SFTP."""
    pid = random.randint(1000, 9999)
    if action == "open":
        return (f"{syslog_ts(ts)} {host} sftp-server[{pid}]: "
                f"session opened for local user {user} from [{ip}]")
    elif action == "download":
        f = pick(["/data/payments/eod_batch.csv",
                  "/data/swift/mt103_outbound.xml",
                  "/data/reports/customer_report.pdf",
                  "/etc/passwd"])  # last one is suspicious
        return (f"{syslog_ts(ts)} {host} sftp-server[{pid}]: "
                f"sent handle {random.randint(0,9)}: file {f}")
    else:
        return (f"{syslog_ts(ts)} {host} sftp-server[{pid}]: "
                f"session closed for local user {user}")


def _cron_run(ts, host):
    user = pick(["root", "wazuh", "postgres", "backup"])
    cmd = pick([
        "/usr/local/bin/eod_settlement.sh",
        "/usr/local/bin/backup_corebank.sh",
        "/usr/bin/find /tmp -mtime +7 -delete",
        "/usr/local/bin/swift_sanity_check.py",
    ])
    return (f"{syslog_ts(ts)} {host} CRON[{random.randint(1000,9999)}]: "
            f"({user}) CMD ({cmd})")


def _su_event(ts, host, user, success=True):
    pid = random.randint(1000, 9999)
    if success:
        return (f"{syslog_ts(ts)} {host} su[{pid}]: "
                f"(to root) {user} on pts/{random.randint(0,5)}")
    else:
        return (f"{syslog_ts(ts)} {host} su[{pid}]: "
                f"FAILED su for root by {user}")


# =========================================================================
# Main generator
# =========================================================================
def generate(path: Path, count: int = 40) -> None:
    events = []
    primary_host = pick(SSH_HOSTS)

    # ----------------------------------------------------------------
    # Baseline: normal logins by ordinary users from internal/VPN IPs
    # ----------------------------------------------------------------
    for _ in range(count // 2):
        ts = rand_recent(60)
        user = pick_normal_user()["username"]
        ip   = pick(INTERNAL_IPS + VPN_IPS)
        host = pick(SSH_HOSTS)
        events.append((ts, _sshd_accepted(ts, ip, user, host)))

    for _ in range(8):
        ts = rand_recent(60)
        user = pick_normal_user()["username"]
        ip   = pick(VPN_IPS)
        host = pick(SSH_HOSTS)
        events.append((ts, _sshd_pubkey(ts, ip, user, host)))

    # Normal sessions disconnecting cleanly
    for _ in range(10):
        ts = rand_recent(45)
        events.append((ts, _sshd_disconnect(
            ts, pick(INTERNAL_IPS), pick_normal_user()["username"], pick(SSH_HOSTS))))

    # Cron and scheduled-job noise
    for _ in range(8):
        ts = rand_recent(60)
        events.append((ts, _cron_run(ts, pick(SSH_HOSTS))))

    # ----------------------------------------------------------------
    # SCENARIO-DRIVEN BRUTE FORCE — one chain per active incident
    # ----------------------------------------------------------------
    # This is what makes alerts correlate across sources: each incident's
    # attacker_ip and victim_user from shared_state.INCIDENTS gets a full
    # brute-force-then-success chain in auth.log.
    # ----------------------------------------------------------------
    for incident in INCIDENTS:
        attacker_ip = incident["attacker_ip"]
        victim_user = incident["victim_user"]
        base = rand_recent(30)
        # Pick a host this attacker hammers (consistent within this chain)
        target_host = pick(SSH_HOSTS)

        # Mix the targeted victim with classic brute-force usernames so the
        # burst looks realistic — attacker tries common accounts first.
        bf_users = ["root", "admin", "test", "ubuntu",
                    "postgres", "oracle", "git", victim_user]

        # 18-22 rapid failures over ~1 minute
        n_attempts = random.randint(18, 22)
        for i in range(n_attempts):
            ts = base + timedelta(seconds=i * 3 + random.randint(0, 2))
            user = pick(bf_users)
            if user not in USERNAMES:
                events.append((ts, _sshd_invalid_user(ts, attacker_ip, user, target_host)))
            events.append((ts, _sshd_failed_password(
                ts, attacker_ip, user, target_host,
                invalid=(user not in USERNAMES))))

        # Then a PAM failure (rule 5503) using the actual victim username
        ts = base + timedelta(seconds=n_attempts * 3 + 2)
        events.append((ts, _pam_failure(ts, victim_user, attacker_ip, target_host)))

        # And finally — SUCCESS as the real victim user (compromise!)
        ts = base + timedelta(seconds=n_attempts * 3 + 8)
        events.append((ts, _sshd_accepted(ts, attacker_ip, victim_user, target_host)))

        # Post-compromise: try sudo (fails first, then maybe succeeds)
        ts = base + timedelta(seconds=n_attempts * 3 + 20)
        events.append((ts, _sudo_fail(ts, victim_user, target_host)))
        ts = base + timedelta(seconds=n_attempts * 3 + 25)
        events.append((ts, _su_event(ts, target_host, victim_user, success=False)))

        # If the victim is a privileged user, the attacker gets root quickly
        if incident["victim_priv"] in ("admin", "manager", "service"):
            ts = base + timedelta(seconds=n_attempts * 3 + 40)
            events.append((ts, _su_event(ts, target_host, victim_user, success=True)))
            # Persistence: add a backdoor user
            ts = base + timedelta(seconds=n_attempts * 3 + 60)
            events.append((ts, _useradd(ts, target_host)))
            ts = base + timedelta(seconds=n_attempts * 3 + 65)
            events.append((ts, _groupadd_admin(
                ts, target_host, f"oper_{random.randint(100,999)}")))

    # ----------------------------------------------------------------
    # STANDALONE attacks (for rule-coverage even when scenarios miss SSH)
    # ----------------------------------------------------------------

    # Scattered routine failed logins by ordinary users (typos, expired pw)
    for _ in range(8):
        ts = rand_recent(60)
        events.append((ts, _sshd_failed_password(
            ts, pick(INTERNAL_IPS), pick_normal_user()["username"], pick(SSH_HOSTS))))

    # Root direct-login attempts from various external IPs (rule 5404)
    for _ in range(4):
        ts = rand_recent(45)
        events.append((ts, _root_login_refused(ts, pick(ATTACKER_IPS), pick(SSH_HOSTS))))

    # Normal sudo activity by noisy users (managers running ops scripts)
    for _ in range(10):
        ts = rand_recent(45)
        user = pick_noisy_user()["username"]
        events.append((ts, _sudo_ok(ts, user, pick(SSH_HOSTS))))

    # A few sudo failures by ordinary users (rule 5401)
    for _ in range(4):
        ts = rand_recent(30)
        events.append((ts, _sudo_fail(ts, pick_normal_user()["username"], pick(SSH_HOSTS))))

    # PAM failures from unknown external IPs (rule 5503)
    for _ in range(5):
        ts = rand_recent(45)
        events.append((ts, _pam_failure(
            ts, pick(USERNAMES), pick(ATTACKER_IPS), pick(SSH_HOSTS))))

    # SFTP activity — vendor downloading files (mostly benign, occasionally fishy)
    for _ in range(6):
        ts = rand_recent(60)
        ip   = pick(VPN_IPS)
        user = pick_normal_user()["username"]
        host = pick(["sftp01", "swift-gw01", "backup01"])
        events.append((ts, _sftp_session(ts, ip, user, host, "open")))
        events.append((ts + timedelta(seconds=2),
                       _sftp_session(ts, ip, user, host, "download")))
        events.append((ts + timedelta(seconds=10),
                       _sftp_session(ts, ip, user, host, "close")))

    # Sort and write
    events.sort(key=lambda x: x[0])
    with path.open("w", encoding="utf-8") as f:
        for _, line in events:
            f.write(line + "\n")

    print(f"  wrote {len(events)} auth events -> {path.name}")
    print(f"  scenario-driven SSH brute-force chains: {len(INCIDENTS)} "
          f"(attackers: {[i['attacker_ip'] for i in INCIDENTS]})")