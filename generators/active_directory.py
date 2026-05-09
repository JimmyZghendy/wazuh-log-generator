"""
Active Directory log generator.

Produces Windows Security events in the XML envelope used by Wazuh's
windows decoder. Event IDs included (all have built-in Wazuh rules):

  4624 - Successful logon
  4625 - Failed logon          -> rule 60122 / brute-force chain
  4672 - Special privileges    -> rule 60106
  4720 - User account created  -> rule 60103
  4732 - Member added to security-enabled local group   -> rule 60112
  4740 - User account locked out -> rule 60123
  4768 - Kerberos TGT request (also detects AS-REP roast attempts)
  4769 - Kerberos service ticket (kerberoasting indicator)
"""
import random
from pathlib import Path
from .common import (
    USERNAMES, PRIV_USERS, HOSTS, DOMAINS, INTERNAL_IPS, EXTERNAL_IPS,
    ATTACKER_IPS, rand_recent, iso_z, pick, maybe,
)

LOGON_TYPES = {
    2:  "Interactive",
    3:  "Network",
    10: "RemoteInteractive",
}

FAILURE_REASONS = {
    "0xC000006A": "Bad password",
    "0xC0000064": "User name does not exist",
    "0xC0000234": "Account locked out",
    "0xC0000072": "Account disabled",
    "0xC000006F": "Outside authorized hours",
}


def _envelope(event_id: int, ts, computer: str, channel: str, body: str) -> str:
    """Wrap event-specific EventData in the standard Windows XML structure."""
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


def _ev_4624(ts) -> str:
    """Successful logon."""
    user = pick(USERNAMES)
    host = pick(HOSTS)
    logon_type = pick([2, 3, 10])
    src_ip = pick(INTERNAL_IPS) if logon_type != 10 else pick(INTERNAL_IPS + EXTERNAL_IPS[:2])
    body = f"""  <EventData>
    <Data Name='SubjectUserSid'>S-1-5-18</Data>
    <Data Name='SubjectUserName'>{host.split('.')[0]}$</Data>
    <Data Name='SubjectDomainName'>{pick(DOMAINS)}</Data>
    <Data Name='SubjectLogonId'>0x3e7</Data>
    <Data Name='TargetUserSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000,9999)}</Data>
    <Data Name='TargetUserName'>{user}</Data>
    <Data Name='TargetDomainName'>{pick(DOMAINS)}</Data>
    <Data Name='TargetLogonId'>0x{random.randint(0x10000, 0xfffff):x}</Data>
    <Data Name='LogonType'>{logon_type}</Data>
    <Data Name='LogonProcessName'>Advapi</Data>
    <Data Name='AuthenticationPackageName'>Negotiate</Data>
    <Data Name='WorkstationName'>{host.split('.')[0]}</Data>
    <Data Name='IpAddress'>{src_ip}</Data>
    <Data Name='IpPort'>{random.randint(49152, 65535)}</Data>
  </EventData>"""
    return _envelope(4624, ts, host, "Security", body)


def _ev_4625(ts, attacker: bool = False) -> str:
    """Failed logon. If attacker=True, target a privileged account from an external IP."""
    user = pick(PRIV_USERS) if attacker else pick(USERNAMES)
    host = pick(HOSTS)
    src_ip = pick(ATTACKER_IPS) if attacker else pick(INTERNAL_IPS)
    status = pick(list(FAILURE_REASONS.keys()))
    body = f"""  <EventData>
    <Data Name='SubjectUserSid'>S-1-0-0</Data>
    <Data Name='SubjectUserName'>-</Data>
    <Data Name='SubjectDomainName'>-</Data>
    <Data Name='TargetUserName'>{user}</Data>
    <Data Name='TargetDomainName'>{pick(DOMAINS)}</Data>
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


def _ev_4720(ts) -> str:
    """User account created."""
    creator = pick(PRIV_USERS)
    new_user = f"newuser_{random.randint(100, 999)}"
    host = "DC01.corp.local"
    body = f"""  <EventData>
    <Data Name='TargetUserName'>{new_user}</Data>
    <Data Name='TargetDomainName'>CORP</Data>
    <Data Name='TargetSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(2000,9999)}</Data>
    <Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-500</Data>
    <Data Name='SubjectUserName'>{creator}</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
    <Data Name='PrivilegeList'>-</Data>
    <Data Name='SamAccountName'>{new_user}</Data>
    <Data Name='DisplayName'>%%1793</Data>
    <Data Name='UserAccountControl'>%%2080 %%2082 %%2084</Data>
  </EventData>"""
    return _envelope(4720, ts, host, "Security", body)


def _ev_4732(ts) -> str:
    """Member added to security-enabled local group (e.g. Administrators)."""
    actor = pick(PRIV_USERS)
    target = pick(USERNAMES)
    body = f"""  <EventData>
    <Data Name='MemberName'>CN={target},CN=Users,DC=corp,DC=local</Data>
    <Data Name='MemberSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000,9999)}</Data>
    <Data Name='TargetUserName'>Administrators</Data>
    <Data Name='TargetDomainName'>Builtin</Data>
    <Data Name='TargetSid'>S-1-5-32-544</Data>
    <Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-500</Data>
    <Data Name='SubjectUserName'>{actor}</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
    <Data Name='PrivilegeList'>-</Data>
  </EventData>"""
    return _envelope(4732, ts, "DC01.corp.local", "Security", body)


def _ev_4740(ts) -> str:
    """Account locked out."""
    locked = pick(USERNAMES)
    body = f"""  <EventData>
    <Data Name='TargetUserName'>{locked}</Data>
    <Data Name='TargetDomainName'>CORP</Data>
    <Data Name='TargetSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000,9999)}</Data>
    <Data Name='SubjectUserSid'>S-1-5-18</Data>
    <Data Name='SubjectUserName'>DC01$</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
    <Data Name='CallerComputerName'>\\\\{pick(HOSTS).split('.')[0]}</Data>
  </EventData>"""
    return _envelope(4740, ts, "DC01.corp.local", "Security", body)


def _ev_4672(ts) -> str:
    """Special privileges assigned to new logon (admin login)."""
    user = pick(PRIV_USERS)
    body = f"""  <EventData>
    <Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-500</Data>
    <Data Name='SubjectUserName'>{user}</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
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
    return _envelope(4672, ts, "DC01.corp.local", "Security", body)


def _ev_4768(ts, suspicious: bool = False) -> str:
    """Kerberos TGT requested. suspicious=True -> AS-REP roasting indicator (rc4_hmac, no preauth)."""
    user = pick(PRIV_USERS) if suspicious else pick(USERNAMES)
    enc_type = "0x17" if suspicious else "0x12"   # rc4-hmac vs aes256
    src_ip = pick(ATTACKER_IPS) if suspicious else pick(INTERNAL_IPS)
    body = f"""  <EventData>
    <Data Name='TargetUserName'>{user}</Data>
    <Data Name='TargetDomainName'>CORP.LOCAL</Data>
    <Data Name='TargetSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000,9999)}</Data>
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
    return _envelope(4768, ts, "DC01.corp.local", "Security", body)


def _ev_4769(ts, kerberoast: bool = False) -> str:
    """Kerberos service ticket requested. kerberoast=True -> rc4-hmac on SPN account."""
    user = pick(USERNAMES)
    service = "svc_sql/sql01.corp.local" if kerberoast else pick(["HTTP/web01.corp.local", "cifs/file01.corp.local"])
    enc_type = "0x17" if kerberoast else "0x12"
    src_ip = pick(ATTACKER_IPS) if kerberoast else pick(INTERNAL_IPS)
    body = f"""  <EventData>
    <Data Name='TargetUserName'>{user}@CORP.LOCAL</Data>
    <Data Name='TargetDomainName'>CORP.LOCAL</Data>
    <Data Name='ServiceName'>{service}</Data>
    <Data Name='ServiceSid'>S-1-5-21-1004336348-1177238915-682003330-{random.randint(1000,9999)}</Data>
    <Data Name='TicketOptions'>0x40810000</Data>
    <Data Name='TicketEncryptionType'>{enc_type}</Data>
    <Data Name='IpAddress'>::ffff:{src_ip}</Data>
    <Data Name='IpPort'>{random.randint(49152, 65535)}</Data>
    <Data Name='Status'>0x0</Data>
    <Data Name='LogonGuid'>{{00000000-0000-0000-0000-000000000000}}</Data>
    <Data Name='TransmittedServices'>-</Data>
  </EventData>"""
    return _envelope(4769, ts, "DC01.corp.local", "Security", body)


def generate(path: Path, count: int = 40) -> None:
    """Write `count` Windows-Event XML records, plus an embedded brute-force burst."""
    events = []

    # --- Baseline normal activity ----------------------------------------
    for _ in range(count // 2):
        ts = rand_recent(60)
        events.append((ts, _ev_4624(ts)))
    for _ in range(3):
        ts = rand_recent(60)
        events.append((ts, _ev_4672(ts)))

    # --- Brute-force scenario (10 rapid 4625 from one attacker) ----------
    burst_start = rand_recent(20)
    for i in range(10):
        ts = burst_start.replace(microsecond=0) + \
             __import__("datetime").timedelta(seconds=i * 3)
        events.append((ts, _ev_4625(ts, attacker=True)))
    # ...followed by a lockout (4740) and a successful logon (4624)
    events.append((burst_start, _ev_4740(burst_start)))

    # --- Suspicious privilege scenarios ----------------------------------
    ts = rand_recent(30); events.append((ts, _ev_4720(ts)))     # new user
    ts = rand_recent(30); events.append((ts, _ev_4732(ts)))     # added to Administrators
    ts = rand_recent(30); events.append((ts, _ev_4768(ts, suspicious=True)))  # AS-REP roast
    ts = rand_recent(30); events.append((ts, _ev_4769(ts, kerberoast=True)))  # Kerberoast

    # --- Sprinkle some routine failures ---------------------------------
    for _ in range(5):
        ts = rand_recent(60)
        events.append((ts, _ev_4625(ts, attacker=False)))

    events.sort(key=lambda x: x[0])

    with path.open("w", encoding="utf-8") as f:
        f.write("<?xml version='1.0' encoding='UTF-8'?>\n<Events>\n")
        for _, xml in events:
            f.write(xml + "\n")
        f.write("</Events>\n")

    print(f"  wrote {len(events)} Windows events -> {path.name}")
