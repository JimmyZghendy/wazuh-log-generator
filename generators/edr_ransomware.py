"""
EDR / Ransomware activity generator.

Wazuh detects ransomware through THREE correlated signal sources, all of which
this generator produces:

  1. FIM (syscheck) events  -> rules 550 (modified), 553 (deleted), 554 (added)
     Mass file modifications + new extensions like .locked .encrypted .HAes are
     the classic signature.

  2. Sysmon Event ID 1 (process creation) -> parent rule 61603
     Ransomware-specific child rules fire on commands like:
       - vssadmin.exe Delete Shadows /All /Quiet     (T1490 - Inhibit Recovery)
       - wbadmin delete catalog -quiet
       - bcdedit /set {default} recoveryenabled No
       - wmic shadowcopy delete
       - cipher /w:C:
       - Ransom note file creation (README*.txt, HOW_TO_DECRYPT*, etc.)

  3. VirusTotal integration -> rule 87105
     File hash matched malicious detections -> followed by Wazuh Active Response
     -> rule 100092 (remove-threat success).

Output is newline-delimited JSON, the same shape the Wazuh agent forwards
from the Windows Security and Sysmon event channels.

Reference: https://wazuh.com/blog/ransomware-protection-on-windows-with-wazuh/
"""
import json
import random
from pathlib import Path
from datetime import timedelta
from .common import (
    USERNAMES, INTERNAL_IPS, ATTACKER_IPS,
    rand_recent, iso_z, pick,
)

# Known ransomware family signatures we'll emulate
RANSOMWARE_FAMILIES = [
    {
        "name": "LockBit",
        "extension": ".lockbit",
        "ransom_note": "Restore-My-Files.txt",
        "hash": "a4e7e4c2b9f8c7d6e5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2",
    },
    {
        "name": "BlackCat",
        "extension": ".bc7e",
        "ransom_note": "RECOVER-FILES.txt",
        "hash": "be8e7c5a9d3f2b1a0c8e7d6f5b4a3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b",
    },
    {
        "name": "Conti",
        "extension": ".conti",
        "ransom_note": "readme.txt",
        "hash": "c0f7e6d5c4b3a2918171615141312111e0d9c8b7a6f5e4d3c2b1a09f8e7d6c5b",
    },
    {
        "name": "Mamona",
        "extension": ".HAes",
        "ransom_note": "README.HAes.txt",
        "hash": "d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0",
    },
]

VICTIM_HOST = "WS-FIN-04.corp.local"
VICTIM_HOST_SHORT = "WS-FIN-04"
VICTIM_USER = "alopez"

# Files the ransomware will "encrypt"
VICTIM_FILES = [
    "C:\\Users\\alopez\\Documents\\Q4_Financials.xlsx",
    "C:\\Users\\alopez\\Documents\\Budget_2026.docx",
    "C:\\Users\\alopez\\Documents\\Contract_Acme.pdf",
    "C:\\Users\\alopez\\Documents\\Tax_Returns.pdf",
    "C:\\Users\\alopez\\Desktop\\presentation.pptx",
    "C:\\Users\\alopez\\Desktop\\customer_list.csv",
    "C:\\Users\\alopez\\Pictures\\family_2024.jpg",
    "C:\\Users\\alopez\\Pictures\\vacation.png",
    "C:\\Users\\alopez\\Downloads\\report.pdf",
    "C:\\Users\\alopez\\Downloads\\meeting_notes.docx",
    "C:\\Users\\alopez\\AppData\\Local\\Mail\\backup.pst",
    "C:\\Users\\Public\\Documents\\company_handbook.pdf",
]


# -------- Sysmon Event ID 1 (process creation) ---------------------------
def _sysmon_process_create(ts, image, cmdline, parent_image, user=None):
    """Wazuh-formatted Sysmon process-creation event (JSON)."""
    user = user or f"CORP\\{VICTIM_USER}"
    return {
        "timestamp": iso_z(ts),
        "agent": {"id": "002", "name": VICTIM_HOST_SHORT, "ip": "10.0.1.45"},
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
                    "computer": VICTIM_HOST,
                    "systemTime": iso_z(ts),
                    "eventRecordID": str(random.randint(100000, 999999)),
                    "processID": "2444",
                    "threadID": "3000",
                },
                "eventdata": {
                    "ruleName": "-",
                    "utcTime": iso_z(ts),
                    "processGuid": "{" + "-".join([
                        f"{random.randint(0,0xffffffff):08x}",
                        f"{random.randint(0,0xffff):04x}",
                        f"{random.randint(0,0xffff):04x}",
                        f"{random.randint(0,0xffff):04x}",
                        f"{random.randint(0,0xffffffffffff):012x}",
                    ]) + "}",
                    "processId": str(random.randint(2000, 9999)),
                    "image": image,
                    "originalFileName": image.split("\\")[-1],
                    "commandLine": cmdline,
                    "currentDirectory": "C:\\Users\\alopez\\",
                    "user": user,
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
def _fim_event(ts, path, event_type, sha256=None):
    """
    File integrity monitoring event matching what Wazuh syscheck emits.

    event_type:
      "added"    -> rule 554
      "modified" -> rule 550
      "deleted"  -> rule 553
    """
    sha256 = sha256 or "".join(random.choices("0123456789abcdef", k=64))
    return {
        "timestamp": iso_z(ts),
        "agent": {"id": "002", "name": VICTIM_HOST_SHORT, "ip": "10.0.1.45"},
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
            "groups": ["ossec", "syscheck", f"syscheck_entry_{event_type}", "syscheck_file"],
        },
        "decoder": {"name": "syscheck_event"},
        "location": "syscheck",
    }


# -------- VirusTotal integration alert -----------------------------------
def _virustotal_alert(ts, file_path, sha256, family):
    """Wazuh VirusTotal integration alert (rule 87105 = malicious match)."""
    return {
        "timestamp": iso_z(ts),
        "agent": {"id": "002", "name": VICTIM_HOST_SHORT, "ip": "10.0.1.45"},
        "manager": {"name": "wazuh-manager"},
        "integration": "virustotal",
        "virustotal": {
            "found": 1,
            "malicious": 1,
            "source": {
                "alert_id": f"{int(ts.timestamp())}.{random.randint(100000,999999)}",
                "file": file_path,
                "md5":    "".join(random.choices("0123456789abcdef", k=32)),
                "sha1":   "".join(random.choices("0123456789abcdef", k=40)),
                "sha256": sha256,
            },
            "sha1":      "".join(random.choices("0123456789abcdef", k=40)),
            "scan_date": iso_z(ts),
            "positives":  str(random.randint(45, 68)),
            "total":      "72",
            "permalink":  f"https://www.virustotal.com/gui/file/{sha256}/detection",
            "malicious":  1,
        },
        "rule": {
            "level": 12,
            "description": f"VirusTotal: Alert - {file_path} - {random.randint(45,68)} engines detected this file ({family})",
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
def _active_response(ts, file_path):
    """Wazuh Active Response remove-threat success (rule 100092)."""
    return {
        "timestamp": iso_z(ts),
        "agent": {"id": "002", "name": VICTIM_HOST_SHORT, "ip": "10.0.1.45"},
        "manager": {"name": "wazuh-manager"},
        "data": {
            "command":   "remove-threat.exe",
            "parameters": {
                "extra_args": [],
                "alert": {"data": {"virustotal": {"source": {"file": file_path}}}},
                "program": "remove-threat.exe",
            },
            "status": "SUCCESS",
        },
        "rule": {
            "level": 7,
            "description": f"Active response: Successfully removed threat located at {file_path}",
            "id": "100092",
            "groups": ["active_response", "ransomware"],
        },
        "decoder": {"name": "json"},
        "location": "active-response",
    }


# -------- High-level scenario assembly -----------------------------------
def _ransomware_scenario(start_ts, family):
    """
    Build a full ransomware kill-chain as a list of (ts, json_event) tuples.

    Timeline (~5 minutes):
      T+0     : initial download   -> Sysmon process create (browser writes EXE)
      T+5s    : FIM "added" event on the EXE
      T+8s    : VirusTotal flags hash -> rule 87105
      T+10s   : Active Response removes file -> rule 100092  (defender wins)

    But for the demo we ALSO show the case where AV misses it and the
    ransomware executes. The remaining events model that path:

      T+30s   : vssadmin delete shadows           -> custom rule (T1490)
      T+35s   : wbadmin delete catalog
      T+40s   : bcdedit recoveryenabled No
      T+45s   : wmic shadowcopy delete
      T+60s.. : mass file modification (FIM 550 burst) + new .ext files (FIM 554)
      T+180s  : ransom note dropped in every directory
    """
    events = []

    # --- Initial dropper ---------------------------------------------
    exe_path = f"C:\\Users\\{VICTIM_USER}\\Downloads\\invoice_{random.randint(1000,9999)}.exe"
    ts = start_ts
    events.append((ts, _sysmon_process_create(
        ts,
        image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        cmdline='"chrome.exe" --download',
        parent_image="C:\\Windows\\explorer.exe",
    )))

    ts = start_ts + timedelta(seconds=5)
    events.append((ts, _fim_event(ts, exe_path, "added", sha256=family["hash"])))

    ts = start_ts + timedelta(seconds=8)
    events.append((ts, _virustotal_alert(ts, exe_path, family["hash"], family["name"])))

    ts = start_ts + timedelta(seconds=10)
    events.append((ts, _active_response(ts, exe_path)))

    # --- Now imagine AR was disabled / hash not yet known: ransomware runs ---
    ransom_exe = f"C:\\Users\\{VICTIM_USER}\\AppData\\Local\\Temp\\{family['name'].lower()}.exe"

    # Process create for the ransomware itself
    ts = start_ts + timedelta(seconds=20)
    events.append((ts, _sysmon_process_create(
        ts,
        image=ransom_exe,
        cmdline=f'"{ransom_exe}" -encrypt -path C:\\Users\\{VICTIM_USER}',
        parent_image="C:\\Windows\\explorer.exe",
    )))

    # vssadmin Delete Shadows /All /Quiet   -> T1490
    ts = start_ts + timedelta(seconds=30)
    events.append((ts, _sysmon_process_create(
        ts,
        image="C:\\Windows\\System32\\vssadmin.exe",
        cmdline='vssadmin.exe Delete Shadows /All /Quiet',
        parent_image=ransom_exe,
    )))

    # wbadmin delete catalog -quiet
    ts = start_ts + timedelta(seconds=35)
    events.append((ts, _sysmon_process_create(
        ts,
        image="C:\\Windows\\System32\\wbadmin.exe",
        cmdline='wbadmin.exe delete catalog -quiet',
        parent_image=ransom_exe,
    )))

    # bcdedit recoveryenabled No
    ts = start_ts + timedelta(seconds=40)
    events.append((ts, _sysmon_process_create(
        ts,
        image="C:\\Windows\\System32\\bcdedit.exe",
        cmdline='bcdedit.exe /set {default} recoveryenabled No',
        parent_image=ransom_exe,
    )))

    # wmic shadowcopy delete
    ts = start_ts + timedelta(seconds=45)
    events.append((ts, _sysmon_process_create(
        ts,
        image="C:\\Windows\\System32\\wbem\\WMIC.exe",
        cmdline='wmic.exe shadowcopy delete',
        parent_image=ransom_exe,
    )))

    # Disable Defender (registry change)
    ts = start_ts + timedelta(seconds=50)
    events.append((ts, _sysmon_process_create(
        ts,
        image="C:\\Windows\\System32\\reg.exe",
        cmdline=('reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" '
                 '/v DisableAntiSpyware /t REG_DWORD /d 1 /f'),
        parent_image=ransom_exe,
    )))

    # Disable Windows Firewall
    ts = start_ts + timedelta(seconds=55)
    events.append((ts, _sysmon_process_create(
        ts,
        image="C:\\Windows\\System32\\netsh.exe",
        cmdline='netsh.exe advfirewall set currentprofile state off',
        parent_image=ransom_exe,
    )))

    # --- Mass file encryption: each file gets modified + .ext appended ---
    for i, vfile in enumerate(VICTIM_FILES):
        ts_mod = start_ts + timedelta(seconds=60 + i * 2)
        events.append((ts_mod, _fim_event(ts_mod, vfile, "modified")))

        # Then a new file with .lockbit / .bc7e / .conti / .HAes added
        ts_add = start_ts + timedelta(seconds=61 + i * 2)
        events.append((ts_add, _fim_event(
            ts_add, vfile + family["extension"], "added"
        )))

        # And the original gets deleted
        ts_del = start_ts + timedelta(seconds=62 + i * 2)
        events.append((ts_del, _fim_event(ts_del, vfile, "deleted")))

    # --- Ransom notes dropped in every monitored directory ---------------
    note_dirs = [
        f"C:\\Users\\{VICTIM_USER}\\Documents",
        f"C:\\Users\\{VICTIM_USER}\\Desktop",
        f"C:\\Users\\{VICTIM_USER}\\Pictures",
        f"C:\\Users\\{VICTIM_USER}\\Downloads",
        "C:\\Users\\Public\\Documents",
    ]
    for i, d in enumerate(note_dirs):
        ts_note = start_ts + timedelta(seconds=180 + i * 2)
        events.append((ts_note, _fim_event(
            ts_note, f"{d}\\{family['ransom_note']}", "added"
        )))

    # --- Ransomware also clears Windows event logs (cover tracks) ----
    ts = start_ts + timedelta(seconds=200)
    events.append((ts, _sysmon_process_create(
        ts,
        image="C:\\Windows\\System32\\wevtutil.exe",
        cmdline='wevtutil.exe cl Security',
        parent_image=ransom_exe,
    )))

    return events


def generate(path: Path, count: int = 1) -> None:
    """
    `count` is the number of ransomware infection scenarios to emit.
    Each scenario produces ~50 correlated events.
    """
    all_events = []

    # Pick which families to emulate
    families = random.sample(RANSOMWARE_FAMILIES, k=min(count, len(RANSOMWARE_FAMILIES)))
    if count > len(RANSOMWARE_FAMILIES):
        families += [pick(RANSOMWARE_FAMILIES) for _ in range(count - len(RANSOMWARE_FAMILIES))]

    for i, family in enumerate(families):
        # Spread scenarios across the last hour
        scenario_start = rand_recent(60)
        all_events.extend(_ransomware_scenario(scenario_start, family))

    all_events.sort(key=lambda x: x[0])

    with path.open("w", encoding="utf-8") as f:
        for _, ev in all_events:
            f.write(json.dumps(ev, separators=(",", ":")) + "\n")

    print(f"  wrote {len(all_events)} EDR/ransomware events across "
          f"{len(families)} scenario(s) -> {path.name}")
    print(f"  families emulated: {', '.join(fam['name'] for fam in families)}")
