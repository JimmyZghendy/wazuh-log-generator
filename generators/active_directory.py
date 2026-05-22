"""
Active Directory log generator.

Produces Windows Security events in the XML envelope used by Wazuh's
windows decoder. Event IDs included (all have built-in Wazuh rules):

  4624 - Successful logon
  4625 - Failed logon          -> rule 60122 / brute-force chain
  4634 - Logoff                -> rule 60107
  4648 - Logon with explicit credentials -> lateral movement indicator
  4672 - Special privileges    -> rule 60106
  4688 - Process creation
  4699 - Scheduled task deleted (impair defenses)
  4720 - User account created  -> rule 60103
  4732 - Member added to security-enabled local group -> rule 60112
  4740 - User account locked out -> rule 60123
  4768 - Kerberos TGT request (also AS-REP roast indicator)
  4769 - Kerberos service ticket (kerberoasting indicator)
  4776 - Credential validation (NTLM)
  4798 - User membership enumerated (recon)

NEW: pulls attacker IPs and victim usernames from generators.shared_state so
the same IP and username that brute-forced SSH in auth.log also show up here
as 4625 bursts → 4624 success. Analyst can pivot on data.srcip or
data.win.eventdata.targetUserName across BOTH sources.
"""
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    USERNAMES, PRIV_USERS, HOSTS, HOSTS_DC, HOSTS_BANKING, HOSTS_WS,
    DOMAINS, INTERNAL_IPS, EXTERNAL_IPS, ATTACKER_IPS,
    pick_normal_user, pick_noisy_user, NOISY_USERS, USERS_BY_NAME,
    rand_recent, iso_z, pick, maybe,
)
from .shared_state import INCIDENTS


LOGON_TYPES = {
    2:  "Interactive",
    3:  "Network",
    4:  "Batch",
    5:  "Service",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}

FAILURE_REASONS = {
    "0xC000006A": "Bad password",
    "0xC0000064": "User name does not exist",
    "0xC0000234": "Account locked out",
    "0xC0000072": "Account disabled",
    "0xC000006F": "Outside authorized hours",
    "0xC0000371": "The local account store does not contain secret material",
}

DOMAIN = "BANK"


# =========================================================================
# XML envelope
# =========================================================================
def _envelope(event_id: int, ts, computer: str, channel: str, body: str) -> str:
    record_id = random.randint(100000, 999999)
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/>
    <EventID>{event_id}</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>{12544 if event_id == 4624 else 13824}</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime='{iso_z(ts)}'/>
    <EventRecordID>{record_id}</EventRecordID>
    <Correlation/>
    <Execution ProcessID='628' ThreadID='740'/>
    <Channel>{channel}</Channel>
    <Computer>{computer}</Computer>
    <Security/>
  </System>
{body}
</Event>"""


# =========================================================================
# Event builders
# =========================================================================
def _ev_4624(ts, user=None, src_ip=None, host=None, logon_type=None) -> str:
    """Successful logon."""
    user = user or pick_normal_user()["username"]
    host = host or pick(HOSTS)
    logon_type = logon_type or pick([2, 3, 10])
    src_ip = src_ip or (pick(INTERNAL_IPS) if logon_type != 10
                        else pick(INTERNAL_IPS + EXTERNAL_IPS[:2]))
    body = f"""  <EventData>
    <Data Name='SubjectUserSid'>S-1-5-18</Data>
    <Data Name='SubjectUserName'>{host.split('.')[0]}$</Data>
    <Data Name='SubjectDomainName'>{DOMAIN}</Data>
    <Data Name='SubjectLogonId'>0x3e7</Data>
    <Data Name='TargetUserSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000, 9999)}</Data>
    <Data Name='TargetUserName'>{user}</Data>
    <Data Name='TargetDomainName'>{DOMAIN}</Data>
    <Data Name='TargetLogonId'>0x{random.randint(0x10000, 0xfffff):x}</Data>
    <Data Name='LogonType'>{logon_type}</Data>
    <Data Name='LogonProcessName'>Advapi</Data>
    <Data Name='AuthenticationPackageName'>Negotiate</Data>
    <Data Name='WorkstationName'>{host.split('.')[0]}</Data>
    <Data Name='IpAddress'>{src_ip}</Data>
    <Data Name='IpPort'>{random.randint(49152, 65535)}</Data>
  </EventData>"""
    return _envelope(4624, ts, host, "Security", body)


def _ev_4625(ts, user=None, src_ip=None, host=None, status=None) -> str:
    """Failed logon."""
    user = user or pick(USERNAMES)
    host = host or pick(HOSTS)
    src_ip = src_ip or pick(INTERNAL_IPS)
    status = status or pick(list(FAILURE_REASONS.keys()))
    body = f"""  <EventData>
    <Data Name='SubjectUserSid'>S-1-0-0</Data>
    <Data Name='SubjectUserName'>-</Data>
    <Data Name='SubjectDomainName'>-</Data>
    <Data Name='TargetUserName'>{user}</Data>
    <Data Name='TargetDomainName'>{DOMAIN}</Data>
    <Data Name='Status'>{status}</Data>
    <Data Name='FailureReason'>{FAILURE_REASONS[status]}</Data>
    <Data Name='SubStatus'>0xC000006A</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='LogonProcessName'>NtLmSsp</Data>
    <Data Name='AuthenticationPackageName'>NTLM</Data>
    <Data Name='WorkstationName'>{host.split('.')[0]}</Data>
    <Data Name='IpAddress'>{src_ip}</Data>
    <Data Name='IpPort'>{random.randint(49152, 65535)}</Data>
  </EventData>"""
    return _envelope(4625, ts, host, "Security", body)


def _ev_4634(ts, user=None, host=None) -> str:
    """Account logoff."""
    user = user or pick_normal_user()["username"]
    host = host or pick(HOSTS)
    body = f"""  <EventData>
    <Data Name='TargetUserSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000, 9999)}</Data>
    <Data Name='TargetUserName'>{user}</Data>
    <Data Name='TargetDomainName'>{DOMAIN}</Data>
    <Data Name='TargetLogonId'>0x{random.randint(0x10000, 0xfffff):x}</Data>
    <Data Name='LogonType'>{pick([2, 3, 10])}</Data>
  </EventData>"""
    return _envelope(4634, ts, host, "Security", body)


def _ev_4648(ts, user, target_user, target_host, src_ip) -> str:
    """Logon attempted using explicit credentials — lateral movement marker."""
    body = f"""  <EventData>
    <Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000, 9999)}</Data>
    <Data Name='SubjectUserName'>{user}</Data>
    <Data Name='SubjectDomainName'>{DOMAIN}</Data>
    <Data Name='SubjectLogonId'>0x{random.randint(0x10000, 0xfffff):x}</Data>
    <Data Name='LogonGuid'>{{00000000-0000-0000-0000-000000000000}}</Data>
    <Data Name='TargetUserName'>{target_user}</Data>
    <Data Name='TargetDomainName'>{DOMAIN}</Data>
    <Data Name='TargetServerName'>{target_host}</Data>
    <Data Name='TargetInfo'>{target_host}</Data>
    <Data Name='ProcessId'>0x{random.randint(0x100, 0xffff):x}</Data>
    <Data Name='ProcessName'>C:\\Windows\\System32\\mstsc.exe</Data>
    <Data Name='IpAddress'>{src_ip}</Data>
    <Data Name='IpPort'>{random.randint(49152, 65535)}</Data>
  </EventData>"""
    return _envelope(4648, ts, target_host, "Security", body)


def _ev_4672(ts, user=None, host="DC01.bank.local") -> str:
    """Special privileges assigned to new logon (admin login)."""
    user = user or pick(PRIV_USERS)
    body = f"""  <EventData>
    <Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-500</Data>
    <Data Name='SubjectUserName'>{user}</Data>
    <Data Name='SubjectDomainName'>{DOMAIN}</Data>
    <Data Name='SubjectLogonId'>0x{random.randint(0x10000, 0xfffff):x}</Data>
    <Data Name='PrivilegeList'>SeSecurityPrivilege
    SeBackupPrivilege
    SeRestorePrivilege
    SeTakeOwnershipPrivilege
    SeDebugPrivilege
    SeSystemEnvironmentPrivilege
    SeLoadDriverPrivilege
    SeImpersonatePrivilege</Data>
  </EventData>"""
    return _envelope(4672, ts, host, "Security", body)


def _ev_4720(ts, by_user=None, new_user=None, host="DC01.bank.local") -> str:
    """User account created."""
    by_user = by_user or pick(PRIV_USERS)
    new_user = new_user or f"newuser_{random.randint(100, 999)}"
    body = f"""  <EventData>
    <Data Name='TargetUserName'>{new_user}</Data>
    <Data Name='TargetDomainName'>{DOMAIN}</Data>
    <Data Name='TargetSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(2000, 9999)}</Data>
    <Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-500</Data>
    <Data Name='SubjectUserName'>{by_user}</Data>
    <Data Name='SubjectDomainName'>{DOMAIN}</Data>
    <Data Name='PrivilegeList'>-</Data>
    <Data Name='SamAccountName'>{new_user}</Data>
    <Data Name='DisplayName'>%%1793</Data>
    <Data Name='UserAccountControl'>%%2080 %%2082 %%2084</Data>
  </EventData>"""
    return _envelope(4720, ts, host, "Security", body)


def _ev_4732(ts, by_user=None, member=None, group="Administrators",
             host="DC01.bank.local") -> str:
    """Member added to security-enabled local group."""
    by_user = by_user or pick(PRIV_USERS)
    member = member or pick(USERNAMES)
    body = f"""  <EventData>
    <Data Name='MemberName'>CN={member},CN=Users,DC=bank,DC=local</Data>
    <Data Name='MemberSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000, 9999)}</Data>
    <Data Name='TargetUserName'>{group}</Data>
    <Data Name='TargetDomainName'>Builtin</Data>
    <Data Name='TargetSid'>S-1-5-32-544</Data>
    <Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-500</Data>
    <Data Name='SubjectUserName'>{by_user}</Data>
    <Data Name='SubjectDomainName'>{DOMAIN}</Data>
    <Data Name='PrivilegeList'>-</Data>
  </EventData>"""
    return _envelope(4732, ts, host, "Security", body)


def _ev_4740(ts, locked=None, host="DC01.bank.local") -> str:
    """Account locked out."""
    locked = locked or pick(USERNAMES)
    body = f"""  <EventData>
    <Data Name='TargetUserName'>{locked}</Data>
    <Data Name='TargetDomainName'>{DOMAIN}</Data>
    <Data Name='TargetSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000, 9999)}</Data>
    <Data Name='SubjectUserSid'>S-1-5-18</Data>
    <Data Name='SubjectUserName'>DC01$</Data>
    <Data Name='SubjectDomainName'>{DOMAIN}</Data>
    <Data Name='CallerComputerName'>\\\\{pick(HOSTS_WS).split('.')[0]}</Data>
  </EventData>"""
    return _envelope(4740, ts, host, "Security", body)


def _ev_4768(ts, user=None, src_ip=None, suspicious: bool = False) -> str:
    """Kerberos TGT requested. suspicious=True -> AS-REP roasting indicator."""
    user = user or (pick(PRIV_USERS) if suspicious else pick(USERNAMES))
    enc_type = "0x17" if suspicious else "0x12"   # rc4-hmac vs aes256
    src_ip = src_ip or (pick(ATTACKER_IPS) if suspicious else pick(INTERNAL_IPS))
    body = f"""  <EventData>
    <Data Name='TargetUserName'>{user}</Data>
    <Data Name='TargetDomainName'>BANK.LOCAL</Data>
    <Data Name='TargetSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000, 9999)}</Data>
    <Data Name='ServiceName'>krbtgt</Data>
    <Data Name='ServiceSid'>S-1-5-21-1004336348-1177238915-682003330-502</Data>
    <Data Name='TicketOptions'>0x40810010</Data>
    <Data Name='Status'>0x0</Data>
    <Data Name='TicketEncryptionType'>{enc_type}</Data>
    <Data Name='PreAuthType'>{'0' if suspicious else '2'}</Data>
    <Data Name='IpAddress'>::ffff:{src_ip}</Data>
    <Data Name='IpPort'>{random.randint(49152, 65535)}</Data>
    <Data Name='CertIssuerName'>-</Data>
    <Data Name='CertSerialNumber'>-</Data>
    <Data Name='CertThumbprint'>-</Data>
  </EventData>"""
    return _envelope(4768, ts, "DC01.bank.local", "Security", body)


def _ev_4769(ts, user=None, src_ip=None, kerberoast: bool = False) -> str:
    """Kerberos service ticket. kerberoast=True -> rc4-hmac on SPN account."""
    user = user or pick(USERNAMES)
    service = ("svc_sql/sql01.bank.local" if kerberoast
               else pick(["HTTP/ibank-web01.bank.local",
                          "cifs/file01.bank.local",
                          "MSSQLSvc/sql01.bank.local:1433"]))
    enc_type = "0x17" if kerberoast else "0x12"
    src_ip = src_ip or (pick(ATTACKER_IPS) if kerberoast else pick(INTERNAL_IPS))
    body = f"""  <EventData>
    <Data Name='TargetUserName'>{user}@BANK.LOCAL</Data>
    <Data Name='TargetDomainName'>BANK.LOCAL</Data>
    <Data Name='ServiceName'>{service}</Data>
    <Data Name='ServiceSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000, 9999)}</Data>
    <Data Name='TicketOptions'>0x40810000</Data>
    <Data Name='TicketEncryptionType'>{enc_type}</Data>
    <Data Name='IpAddress'>::ffff:{src_ip}</Data>
    <Data Name='IpPort'>{random.randint(49152, 65535)}</Data>
    <Data Name='Status'>0x0</Data>
    <Data Name='LogonGuid'>{{00000000-0000-0000-0000-000000000000}}</Data>
    <Data Name='TransmittedServices'>-</Data>
  </EventData>"""
    return _envelope(4769, ts, "DC01.bank.local", "Security", body)


def _ev_4776(ts, user, src_workstation, success: bool = True) -> str:
    """Credential validation (NTLM auth attempt against a DC)."""
    status = "0x0" if success else "0xC000006A"
    body = f"""  <EventData>
    <Data Name='PackageName'>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data>
    <Data Name='TargetUserName'>{user}</Data>
    <Data Name='Workstation'>{src_workstation}</Data>
    <Data Name='Status'>{status}</Data>
  </EventData>"""
    return _envelope(4776, ts, "DC01.bank.local", "Security", body)


def _ev_4798(ts, by_user, target_user, host=None) -> str:
    """A user's local group membership was enumerated (recon)."""
    host = host or pick(HOSTS)
    body = f"""  <EventData>
    <Data Name='TargetUserName'>{target_user}</Data>
    <Data Name='TargetDomainName'>{DOMAIN}</Data>
    <Data Name='TargetSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000, 9999)}</Data>
    <Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000, 9999)}</Data>
    <Data Name='SubjectUserName'>{by_user}</Data>
    <Data Name='SubjectDomainName'>{DOMAIN}</Data>
    <Data Name='SubjectLogonId'>0x{random.randint(0x10000, 0xfffff):x}</Data>
    <Data Name='CallerProcessId'>0x{random.randint(0x100, 0xffff):x}</Data>
    <Data Name='CallerProcessName'>C:\\Windows\\System32\\net.exe</Data>
  </EventData>"""
    return _envelope(4798, ts, host, "Security", body)


def _ev_4699(ts, by_user, task_name, host="DC01.bank.local") -> str:
    """Scheduled task deleted (impair defenses indicator)."""
    body = f"""  <EventData>
    <Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-500</Data>
    <Data Name='SubjectUserName'>{by_user}</Data>
    <Data Name='SubjectDomainName'>{DOMAIN}</Data>
    <Data Name='SubjectLogonId'>0x{random.randint(0x10000, 0xfffff):x}</Data>
    <Data Name='TaskName'>\\{task_name}</Data>
  </EventData>"""
    return _envelope(4699, ts, host, "Security", body)


# =========================================================================
# Main generator
# =========================================================================
def generate(path: Path, count: int = 40) -> None:
    events = []

    # ----------------------------------------------------------------
    # Baseline normal activity from ordinary users
    # ----------------------------------------------------------------
    for _ in range(count):
        ts = rand_recent(60)
        user = pick_normal_user()["username"]
        events.append((ts, _ev_4624(ts, user=user)))

    # Some logoffs (4634)
    for _ in range(count // 2):
        ts = rand_recent(60)
        events.append((ts, _ev_4634(ts)))

    # Privileged user logons (4672) — admins doing normal work
    for _ in range(5):
        ts = rand_recent(60)
        events.append((ts, _ev_4672(ts)))

    # Kerberos TGT for legitimate users
    for _ in range(8):
        ts = rand_recent(60)
        user = pick_normal_user()["username"]
        events.append((ts, _ev_4768(ts, user=user, suspicious=False)))

    # NTLM auth (4776) — successful
    for _ in range(6):
        ts = rand_recent(60)
        events.append((ts, _ev_4776(
            ts, pick_normal_user()["username"],
            pick(HOSTS_WS).split('.')[0], success=True)))

    # ----------------------------------------------------------------
    # SCENARIO-DRIVEN: one brute-force chain per incident
    # ----------------------------------------------------------------
    for incident in INCIDENTS:
        attacker_ip = incident["attacker_ip"]
        victim_user = incident["victim_user"]
        victim_host = incident["victim_host"]
        base = rand_recent(30)

        # 10-15 rapid 4625 failures from attacker_ip targeting victim_user
        # (mixed with a few classic accounts so the burst looks realistic)
        bf_targets = [victim_user, "administrator", "admin", victim_user,
                      "sa", victim_user]
        n_attempts = random.randint(10, 15)
        for i in range(n_attempts):
            ts = base + timedelta(seconds=i * 4)
            target = pick(bf_targets)
            status = "0xC000006A" if target in USERNAMES else "0xC0000064"
            events.append((ts, _ev_4625(
                ts, user=target, src_ip=attacker_ip,
                host=victim_host, status=status)))
            # Also a 4776 NTLM failure for each
            events.append((ts + timedelta(milliseconds=100),
                           _ev_4776(ts, target,
                                    victim_host.split('.')[0], success=False)))

        # Account lockout (4740) after enough failures
        ts = base + timedelta(seconds=n_attempts * 4 + 5)
        events.append((ts, _ev_4740(ts, locked=victim_user)))

        # SUCCESSFUL logon as victim_user from the SAME attacker IP — compromise
        ts = base + timedelta(seconds=n_attempts * 4 + 60)  # after lockout expires
        events.append((ts, _ev_4624(
            ts, user=victim_user, src_ip=attacker_ip,
            host=victim_host, logon_type=10)))  # RemoteInteractive

        # Recon: enumerate domain admins (4798)
        ts = base + timedelta(seconds=n_attempts * 4 + 90)
        events.append((ts, _ev_4798(
            ts, by_user=victim_user, target_user="administrator",
            host=victim_host)))

        # If victim is privileged, attacker uses explicit creds to lateral-move
        if incident["victim_priv"] in ("admin", "manager", "service"):
            # Lateral movement to a DB host using explicit creds (4648)
            ts = base + timedelta(seconds=n_attempts * 4 + 120)
            events.append((ts, _ev_4648(
                ts, user=victim_user, target_user="administrator",
                target_host=pick(HOSTS_BANKING), src_ip=attacker_ip)))

            # 4672 special privileges granted to attacker session
            ts = base + timedelta(seconds=n_attempts * 4 + 130)
            events.append((ts, _ev_4672(ts, user=victim_user, host=victim_host)))

            # Persistence: add a new domain user (4720)
            ts = base + timedelta(seconds=n_attempts * 4 + 180)
            backdoor = f"helpdesk_{random.randint(100, 999)}"
            events.append((ts, _ev_4720(
                ts, by_user=victim_user, new_user=backdoor)))

            # Add the backdoor user to Domain Admins (4732)
            ts = base + timedelta(seconds=n_attempts * 4 + 185)
            events.append((ts, _ev_4732(
                ts, by_user=victim_user, member=backdoor,
                group="Domain Admins")))

            # Impair defenses: delete the EDR scheduled task (4699)
            ts = base + timedelta(seconds=n_attempts * 4 + 200)
            events.append((ts, _ev_4699(
                ts, by_user=victim_user,
                task_name="Microsoft\\Windows\\Wazuh\\AgentCheck")))

    # ----------------------------------------------------------------
    # STANDALONE attacks (for rule coverage regardless of scenarios)
    # ----------------------------------------------------------------

    # Sprinkle of routine failed logons (typos)
    for _ in range(8):
        ts = rand_recent(60)
        events.append((ts, _ev_4625(ts)))

    # AS-REP roasting attempt (random target, not necessarily scenario victim)
    ts = rand_recent(40)
    events.append((ts, _ev_4768(ts, suspicious=True)))

    # Kerberoasting attempt
    ts = rand_recent(40)
    events.append((ts, _ev_4769(ts, kerberoast=True)))

    # Random new user creation (legitimate-looking)
    ts = rand_recent(50)
    events.append((ts, _ev_4720(ts)))

    # A noisy user (e.g., HR) being added to a sensitive group — needs review
    ts = rand_recent(40)
    target = pick_noisy_user()["username"]
    events.append((ts, _ev_4732(
        ts, member=target, group="Backup Operators")))

    # Sort and write
    events.sort(key=lambda x: x[0])

    with path.open("w", encoding="utf-8") as f:
        f.write("<?xml version='1.0' encoding='UTF-8'?>\n<Events>\n")
        for _, xml in events:
            f.write(xml + "\n")
        f.write("</Events>\n")

    print(f"  wrote {len(events)} Windows events -> {path.name}")
    print(f"  scenario-driven AD brute-force chains: {len(INCIDENTS)} "
          f"(attackers: {[i['attacker_ip'] for i in INCIDENTS]})")