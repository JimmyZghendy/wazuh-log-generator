# Wazuh EDR Ransomware Detection — Setup & Troubleshooting Guide

End-to-end documentation of how we configured custom ransomware detection rules
on Wazuh, the issues we hit, and how each was resolved.

---

## 1. Architecture overview

Two-server lab setup:

```
┌─────────────────────────┐         ┌──────────────────────────┐
│   Server 1: gen         │         │   Server 2: ctl          │
│   (log generator)       │         │   (Wazuh manager)        │
│   10.1.244.110          │         │   10.1.244.10            │
│                         │         │                          │
│  /opt/wazuh-log-        │         │  /var/ossec/             │
│    generator/           │         │    ├── bin/              │
│    └── generate_logs.py │  agent  │    │   └── wazuh-logtest │
│                         │ ──────► │    ├── etc/rules/        │
│  /var/log/wazuh-test/   │  ships  │    │   └── ransomware_   │
│    └── edr_ransomware   │  events │    │       rules.xml     │
│        .json            │   over  │    └── logs/alerts/      │
│         ▲ appended by   │   1514  │        └── alerts.json   │
│         │ generator     │         │                          │
│                         │         │  Dashboard UI lives here │
│  wazuh-agent tails file │         │  (Wazuh dashboard)       │
└─────────────────────────┘         └──────────────────────────┘
```

| Role                                | Lives on | Tool / Path                                         |
| ----------------------------------- | -------- | --------------------------------------------------- |
| Generate fake events                | gen      | `/opt/wazuh-log-generator/generate_logs.py`         |
| Tail event file, forward to manager | gen      | `wazuh-agent` (`<localfile>` block in `ossec.conf`) |
| Decode events, evaluate rules       | ctl      | `wazuh-analysisd`                                   |
| Test rules without running pipeline | ctl      | `/var/ossec/bin/wazuh-logtest`                      |
| View alerts                         | ctl      | `/var/ossec/logs/alerts/alerts.json` + dashboard    |

Key mental model: **the agent generates/ships, the manager decodes/rules/alerts**.
`wazuh-logtest` and `alerts.json` exist only on the manager.

---

## 2. The custom rules file

Location on the manager:

```
/var/ossec/etc/rules/ransomware_rules.xml
```

Rule ID range: **100200–100231** (we originally used 100100 but it collided
with existing rules in `local_rules.xml`, so everything was renumbered).

Coverage by MITRE technique:

| ID range      | Technique                         | What it detects                                                                         |
| ------------- | --------------------------------- | --------------------------------------------------------------------------------------- |
| 100200–100203 | T1490 — Inhibit System Recovery   | vssadmin / wbadmin / bcdedit / wmic shadow-copy deletion                                |
| 100210–100212 | T1562, T1070 — Impair Defenses    | Defender disable, firewall off, event-log clear                                         |
| 100220        | T1486 — Data Encrypted for Impact | Files renamed with known ransomware extensions                                          |
| 100221        | T1486                             | Ransom-note file dropped (README/HOW_TO_DECRYPT/etc.)                                   |
| 100230        | T1486                             | Correlation: 8+ encryption events in 60s                                                |
| 100231        | T1486 + T1490                     | Correlation: encryption + 2+ recovery-inhibition events in 5 min (confirmed ransomware) |

---

## 3. The full troubleshooting journey

Six distinct issues, in the order we hit them.

### Issue 1 — Rule ID collision with `local_rules.xml`

**Symptom:** `wazuh-analysisd -t` complained about duplicate IDs.

```
/var/ossec/etc/rules/local_rules.xml:3:  <rule id="100100" level="12" ...>
```

**Cause:** Rule ID 100100 was already in use.

**Fix:** Renumbered all rules from 100100-range to 100200-range.

```bash
grep -rn 'id="100200"' /var/ossec/etc/rules/ /var/ossec/ruleset/rules/ 2>/dev/null
# Confirmed no duplicates
```

---

### Issue 2 — Heredoc paste corrupted the file

**Symptom:** After pasting the rules via `cat > file <<EOF`, the file ended
with garbled text:

```
EOFroup>>p>impact,attack,correlation,confirmed_ransomware,</group>...
```

`wc -l` showed 104 lines instead of the expected ~140.

**Cause:** Terminal dropped/reordered characters during a large SSH paste —
heredocs over SSH are fragile for big blocks.

**Fix:** Used `nano` instead. Open the file, paste once, save with
`Ctrl+O` / `Enter` / `Ctrl+X`. Fallback option documented: base64-encode
the file locally, paste the blob, `base64 -d` on the manager.

---

### Issue 3 — Invalid `frequency="1"` on correlation rule

**Symptom:** `wazuh-analysisd -t` rejected the file with a frequency error.

**Cause:** Wazuh requires `frequency` ≥ 2 on correlation rules. Rule 100231
had `frequency="1"`.

**Fix:** Changed to `frequency="2"`. Re-validated:

```bash
/var/ossec/bin/wazuh-analysisd -t
# wazuh-analysisd: Configuration test passed.
```

---

### Issue 4 — Running `generate_logs.py` from the wrong directory / wrong filename

**Symptom:**

```
python3: can't open file '/home/toor/generate_logs.py': [Errno 2] No such file or directory
cat: /opt/wazuh-log-generator/generator_logs.py: No such file or directory
```

**Causes (two):**

1. Typo: the file is `generate_logs.py` (verb-noun), not `generator_logs.py`.
2. Running from `/home/toor` while the script lives in `/opt/wazuh-log-generator/`.

**Fix:**

```bash
cd /opt/wazuh-log-generator
python3 generate_logs.py --source edr_ransomware --count 30
```

Or use the absolute path:

```bash
python3 /opt/wazuh-log-generator/generate_logs.py --source edr_ransomware --count 30
```

---

### Issue 5 — Field path mismatch: rules used `data.*`, decoder produced bare fields

**Symptom:** Dashboard showed 44 alerts but none were from the 100200 range.
All hits were default rules (5501, 5402) firing on auth.log.

**Diagnosis** — ran a controlled test with `wazuh-logtest`:

```
**Phase 2: Completed decoding.
        name: 'json'
        win.eventdata.commandLine: 'vssadmin.exe Delete Shadows /All /Quiet'
        win.system.eventID: '1'
                                    ← no Phase 3 — no rule matched
```

The decoder produced `win.eventdata.commandLine` (top-level), but the rules
were looking for `data.win.eventdata.commandLine` (one level deeper).

**The gotcha:** In `alerts.json` (what the dashboard shows), every payload
sits under `data.*`. The `data.` wrapper is added by the alert-writer
**after** rules run. Rules see un-wrapped fields. The dashboard sees wrapped
fields. Easy to mix up.

**Fix:** Stripped `data.` from every `<field name=...>`:

```bash
cp /var/ossec/etc/rules/ransomware_rules.xml /var/ossec/etc/rules/ransomware_rules.xml.bak
sed -i 's/name="data\.win\.eventdata/name="win.eventdata/g' /var/ossec/etc/rules/ransomware_rules.xml
sed -i 's/name="data\.syscheck/name="syscheck/g' /var/ossec/etc/rules/ransomware_rules.xml
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

Re-ran the same test:

```
**Phase 3: Completed filtering (rules).
        id: '100200'
        level: '12'
        description: 'EDR Ransomware: Volume Shadow Copies deleted via vssadmin (T1490)'
**Alert to be generated.
```

Rule confirmed working.

---

### Issue 6 — Generator emits alert-shaped JSON instead of raw event JSON (open)

**Symptom:** Even with rules fixed, generator output didn't trigger anything.

**Cause:** `generate_logs.py` produces fully-formed Wazuh **alerts**, not raw
Sysmon events:

```json
{
  "timestamp": "...",
  "agent": {...},
  "manager": {...},
  "data": { "win": {...} },          ← extra wrapper
  "rule": {...},                       ← shouldn't be present
  "decoder": { "name": "..." },        ← shouldn't be present
  "location": "EventChannel"
}
```

Two problems with this shape:

1. The `data.` wrapper puts fields one level too deep — rules can't match.
2. Pre-baked `rule`/`decoder` fields confuse the manager (they're
   decisions the manager should make).
3. The commandLines in generated events are mostly benign (e.g. `chrome.exe
--download`), so even with the shape fixed, nothing would match the
   attack-pattern regexes.

**Status:** Pending generator rewrite. Required shape:

```json
{
  "win": {
    "system": {
      "providerName": "Microsoft-Windows-Sysmon",
      "eventID": "1",
      "computer": "WS-FIN-04.corp.local",
      "systemTime": "2026-05-18T10:10:00.000Z"
    },
    "eventdata": {
      "image": "C:\\Windows\\System32\\vssadmin.exe",
      "commandLine": "vssadmin.exe Delete Shadows /All /Quiet",
      "user": "NT AUTHORITY\\SYSTEM",
      "processId": "4321"
    }
  }
}
```

The generator must also emit malicious `commandLine` values that match the
rule regexes (table below).

---

## 4. Configuration files reference

### 4.1 Manager — `/var/ossec/etc/rules/ransomware_rules.xml`

```xml
<!--
  Wazuh custom rules - EDR / Ransomware detection
  Rule ID range: 100200 - 100231
  Field paths use top-level decoder names (win.*, syscheck.*) — NOT data.*
-->
<group name="ransomware,wazuh_log_generator,">

  <!-- T1490 - Inhibit System Recovery -->
  <rule id="100200" level="12">
    <decoded_as>json</decoded_as>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)vssadmin(\.exe)?\s+(?:[^\s]+\s+)?Delete\s+Shadows</field>
    <description>EDR Ransomware: Volume Shadow Copies deleted via vssadmin (T1490)</description>
    <mitre><id>T1490</id></mitre>
    <group>inhibit_recovery,attack,</group>
  </rule>
  <!-- ... 100201, 100202, 100203 follow same shape ... -->

  <!-- T1562 / T1070 - Impair Defenses -->
  <!-- 100210, 100211, 100212 -->

  <!-- T1486 - Data Encrypted for Impact -->
  <!-- 100220, 100221 use syscheck.path -->

  <!-- Correlation rules -->
  <rule id="100230" level="14" frequency="8" timeframe="60">
    <if_matched_sid>100220</if_matched_sid>
    <same_field>agent.id</same_field>
    <description>EDR Ransomware: Mass file-encryption burst (T1486)</description>
    <mitre><id>T1486</id></mitre>
    <group>impact,attack,correlation,</group>
  </rule>

  <rule id="100231" level="15" frequency="2" timeframe="300">
    <if_sid>100220</if_sid>
    <if_matched_group>inhibit_recovery</if_matched_group>
    <same_field>agent.id</same_field>
    <description>EDR RANSOMWARE CONFIRMED: encryption + recovery-inhibition (T1486 + T1490)</description>
    <mitre><id>T1486</id><id>T1490</id></mitre>
    <group>impact,attack,correlation,confirmed_ransomware,</group>
  </rule>

</group>
```

File permissions:

```bash
chown wazuh:wazuh /var/ossec/etc/rules/ransomware_rules.xml
chmod 660         /var/ossec/etc/rules/ransomware_rules.xml
```

### 4.2 Agent — `/var/ossec/etc/ossec.conf` (on gen)

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/wazuh-test/edr_ransomware.json</location>
</localfile>
```

---

## 5. Commands to trigger each rule

Each `commandLine` below, when ingested as a Sysmon JSON event, fires its
mapped rule.

| Rule   | `commandLine` value                                                                                          |
| ------ | ------------------------------------------------------------------------------------------------------------ |
| 100200 | `vssadmin.exe Delete Shadows /All /Quiet`                                                                    |
| 100201 | `wbadmin.exe delete catalog -quiet`                                                                          |
| 100202 | `bcdedit.exe /set {default} recoveryenabled No`                                                              |
| 100203 | `wmic.exe shadowcopy delete`                                                                                 |
| 100210 | `reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f` |
| 100211 | `netsh.exe advfirewall set allprofiles state off`                                                            |
| 100212 | `wevtutil.exe cl Security`                                                                                   |

FIM-based rules (different mechanism — require real file events from the
syscheck module, not JSON ingestion):

| Rule   | Trigger                                                                                                                |
| ------ | ---------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------------- | --------- | ---- | ----- |
| 100220 | File created with extension `.lockbit`, `.conti`, `.ryuk`, `.locked`, `.encrypted`, etc., in a monitored FIM directory |
| 100221 | File added matching `(README                                                                                           | RECOVER | RESTORE | HOW_TO_DECRYPT | ...).(txt | html | hta)` |

Correlation rules:

- **100230**: emit 8+ events triggering 100220 within 60s, same `agent.id`.
- **100231**: 1+ event triggering 100220 + 2+ events from `inhibit_recovery` group within 5 min, same `agent.id`.

---

## 6. Standard testing workflow

### 6.1 Test a rule in isolation (manager only — no agent needed)

On **ctl**:

```bash
/var/ossec/bin/wazuh-logtest
```

Paste one event:

```
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1"},"eventdata":{"commandLine":"vssadmin.exe Delete Shadows /All /Quiet"}}}
```

Expected output:

```
**Phase 2: Completed decoding.
        name: 'json'
        win.eventdata.commandLine: 'vssadmin.exe Delete Shadows /All /Quiet'
**Phase 3: Completed filtering (rules).
        id: '100200'
        level: '12'
**Alert to be generated.
```

### 6.2 Test end-to-end (agent → manager → dashboard)

On **ctl** — start tailing alerts:

```bash
tail -f /var/ossec/logs/alerts/alerts.json | grep -E '"id":"1002'
```

On **gen** — inject a raw event into the watched file:

```bash
echo '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","computer":"WS-FIN-04","systemTime":"2026-05-18T10:10:00.000Z"},"eventdata":{"image":"C:\\Windows\\System32\\vssadmin.exe","commandLine":"vssadmin.exe Delete Shadows /All /Quiet","user":"NT AUTHORITY\\SYSTEM","processId":"4321"}}}' >> /var/log/wazuh-test/edr_ransomware.json
```

Alert should appear on ctl's `tail -f` within 1–3 seconds.

### 6.3 Verify in the dashboard

Discover → filter:

```
rule.id >= 100200 and rule.id <= 100231
```

or:

```
rule.groups: "ransomware"
```

---

## 7. Verification & health checks

### Manager side (ctl)

```bash
# Rules file syntactically valid?
/var/ossec/bin/wazuh-analysisd -t

# Manager running?
systemctl status wazuh-manager --no-pager

# Count rules loaded from our file
grep -cE 'id="1002(0[0-3]|1[0-2]|2[0-1]|3[0-1])"' /var/ossec/etc/rules/ransomware_rules.xml
# Expected: 11

# Check for ID collisions
grep -rn 'id="100200"' /var/ossec/etc/rules/ /var/ossec/ruleset/rules/ 2>/dev/null

# Is the agent visible to the manager?
/var/ossec/bin/agent_control -l
```

### Agent side (gen)

```bash
# Agent running?
systemctl status wazuh-agent --no-pager

# Connected to manager?
cat /var/ossec/var/run/wazuh-agentd.state | grep -E 'status|last_keepalive'
# Expected: status='connected'

# Is the file being tailed?
grep -i 'edr_ransomware' /var/ossec/logs/ossec.log | tail -20
# Expected: "INFO: Analyzing file: '/var/log/wazuh-test/edr_ransomware.json'."
```

---

## 8. Common pitfalls — quick lookup

| Symptom                                                | Cause                                                                            | Fix                                                            |
| ------------------------------------------------------ | -------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| Duplicate rule ID error on validate                    | ID already exists in another `.xml`                                              | Pick an unused range; check `local_rules.xml` first            |
| `wc -l` of pasted file is way short                    | Terminal mangled a heredoc paste                                                 | Use `nano` or base64-paste                                     |
| `frequency` error from validate                        | Wazuh requires frequency ≥ 2                                                     | Set `frequency="2"` minimum                                    |
| `python3: can't open file`                             | Wrong cwd or typo in filename                                                    | `cd /opt/wazuh-log-generator` first                            |
| `wazuh-logtest: No such file or directory`             | Running on agent host instead of manager                                         | SSH to ctl; the tool is manager-only                           |
| `alerts.json: No such file or directory`               | Same — alerts only exist on the manager                                          | View on ctl                                                    |
| Decoder works, no rule matches (no Phase 3)            | Field path mismatch (`data.foo` vs `foo`)                                        | Match the path printed in Phase 2                              |
| Rule matches in `wazuh-logtest` but no dashboard alert | Indexer/filebeat pipeline issue, or event was added before agent started tailing | Re-append; check filebeat status on ctl                        |
| Alerts firing on auth.log but not ransomware events    | Generator output is alert-shaped, not event-shaped                               | Strip outer `agent`/`manager`/`data`/`rule`/`decoder` wrappers |

---

## 9. Current status

- [x] Custom rules file created and renumbered to 100200–100231
- [x] Field paths corrected (`win.*` instead of `data.win.*`)
- [x] `wazuh-analysisd -t` passes
- [x] Manager restarts cleanly
- [x] `wazuh-logtest` confirms rule 100200 fires on valid input
- [x] Agent `<localfile>` block tails `/var/log/wazuh-test/edr_ransomware.json`
- [ ] **Generator rewrite** — emit raw Sysmon-shape events with attack `commandLine` values (in progress)
- [ ] Full pipeline test: `generate_logs.py` → file → agent → manager → dashboard
- [ ] FIM rules 100220/100221 validation (requires monitored FIM directory on a real agent)
- [ ] Correlation rules 100230/100231 validation (needs the burst pattern)

---

## 10. Useful one-liners

```bash
# Re-test rule 100200 quickly
echo '{"win":{"eventdata":{"commandLine":"vssadmin.exe Delete Shadows /All /Quiet"}}}' | /var/ossec/bin/wazuh-logtest

# Watch new ransomware alerts in real time (manager)
tail -f /var/ossec/logs/alerts/alerts.json | grep -E '"id":"1002'

# Count how many of our rules have fired in the last hour
grep -c '"id":"1002' /var/ossec/logs/alerts/alerts.json

# Show the last 5 ransomware alerts pretty-printed
grep '"id":"1002' /var/ossec/logs/alerts/alerts.json | tail -5 | python3 -m json.tool

# Restart manager
systemctl restart wazuh-manager && systemctl status wazuh-manager --no-pager

# Restart agent (on gen)
systemctl restart wazuh-agent && systemctl status wazuh-agent --no-pager
```
