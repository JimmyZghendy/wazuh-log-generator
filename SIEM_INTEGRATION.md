# SIEM Integration — Wazuh Deployment Notes

Companion document to the main `README.md`. This file documents the
**real-world deployment** of the log generator into a Wazuh environment,
the issues encountered along the way, and the exact fixes applied.

If you're setting this up for the first time on a fresh environment, read
this in addition to the main `README.md` — it will save you from
re-discovering everything we learned the hard way.

## Environment

| Component     | Server                     | OS                     | Role                           |
| ------------- | -------------------------- | ---------------------- | ------------------------------ |
| Wazuh manager | **10.1.244.10** (`ctl`)    | RHEL/AmazonLinux (OVA) | analysisd, indexer, dashboard  |
| Log generator | **10.1.244.110** (`gen`)   | Ubuntu 22.04           | Python generator + Wazuh agent |
| Transport     | TCP/1514 (agent → manager) | —                      | —                              |

## TL;DR — what works

After all fixes applied, the pipeline produces alerts from **all six sources**:

| Source                | Decoder                      | Status                   | Notes                           |
| --------------------- | ---------------------------- | ------------------------ | ------------------------------- |
| `auth.log`            | `sshd` / `pam_unix` / `sudo` | ✅ Working               | Rules 5710, 5712, 5715, 5402    |
| `web_access.log`      | `web-accesslog`              | ✅ Working               | Rules 31101, 31103, 31151       |
| `mysql.log`           | `mysql_log`                  | ✅ Working               | Rule 50106                      |
| `mssql_audit.log`     | `mssql_log`                  | ✅ Working               | Rule 85004                      |
| `paloalto.csv`        | `paloalto`                   | ✅ Working _(after fix)_ | Rules 64500–64517               |
| `edr_ransomware.json` | `json`                       | ⚠️ Partial               | Needs EDR module + custom rules |

---

# Deployment journey — issues and fixes

Each section below is a real issue we hit, the diagnostic that revealed
the root cause, and the exact fix.

## Issue 1 — Manager OS mismatch (ufw vs firewalld)

### Symptom

```
$ sudo ufw allow 1514/tcp
sudo: ufw: command not found
```

### Root cause

The Wazuh manager was deployed as a Wazuh OVA, which is based on
RHEL/AmazonLinux — not Ubuntu. The original deployment script
assumed `ufw` (Ubuntu).

### Fix

The Wazuh OVA ships with `firewalld` disabled by default, and ports
1514/1515 are already open. **No firewall configuration needed.**

```bash
systemctl status firewalld
# Unit firewalld.service could not be found.   ← OK, nothing to configure
```

If you have a different RHEL-based environment with `firewalld` active:

```bash
firewall-cmd --permanent --add-port=1514/tcp
firewall-cmd --permanent --add-port=1515/tcp
firewall-cmd --reload
```

## Issue 2 — Agent key import on the wrong server

### Symptom

```
Choose your action: I
** Key import only available on an agent **
```

### Root cause

Tried to import the enrollment key on the **manager** (where keys are
generated). Key import is an **agent-side** operation.

### Fix — correct workflow

On the **manager** (`ctl`):

```bash
/var/ossec/bin/manage_agents
# Press A, name=loggen-server, IP=10.1.244.110
# Press Q
/var/ossec/bin/manage_agents -e <ID>   # extract & COPY the base64 string
```

On the **agent** (`gen`):

```bash
/var/ossec/bin/manage_agents
# Press I, PASTE the key, confirm with y, Press Q
systemctl restart wazuh-agent
```

## Issue 3 — Extracted the wrong agent's key

### Symptom

After installing the agent and registering, the manager showed:

```
ID: 003, Name: gen,            IP: any,           Disconnected
ID: 004, Name: loggen-server,  IP: 10.1.244.110,  Never connected
```

### Root cause

1. A stale agent `gen` (ID 003) existed from a previous test.
2. The key extracted earlier (`-e 001`) belonged to `DC`, not `loggen-server`.

### Fix

```bash
# On manager
/var/ossec/bin/manage_agents
# Press R, remove the stale 003

/var/ossec/bin/manage_agents -e 004   # extract the CORRECT key
```

Then on the agent, re-import using `I` (overwriting the wrong key).

### Lesson learned

Always verify the agent ID matches the agent name **before** extracting
the key. Use `agent_control -l` from the manager to list all agents
and their statuses.

## Issue 4 — Stale `<localfile>` block hijacking the agent

### Symptom

After registering and restarting, only **MySQL alerts** fired — none
of the other log sources produced events.

### Diagnostic

```bash
grep "/var/log/wazuh-test" /var/ossec/logs/ossec.log
# Found:
# ERROR: Could not open file '/var/log/wazuh-test/auth.log' due to [No such file or directory]
# (this was from before files existed — expected)

tail -50 /var/ossec/logs/ossec.log
# Found:
# Analyzing file: '/tmp/wazuh_test/logs_2026-05-07_08-01-43.jsonl'
# Analyzing file: '/tmp/wazuh_test/logs_2026-05-07_08-01-44.jsonl'
# ... 40+ similar lines pointing at /tmp/wazuh_test/*.jsonl
```

### Root cause

A leftover `<localfile>` block from a previous test was still in
`ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/tmp/wazuh_test/*.jsonl</location>
</localfile>
```

The wildcard expanded to 40+ stale JSONL files from May 7, and the
agent was busy churning through them — slowing down the processing
of our new files.

### Fix

```bash
# Remove the stale block (one-liner):
sed -i '/<localfile>/{N;N;N;/tmp\/wazuh_test/d;}' /var/ossec/etc/ossec.conf

# Or open ossec.conf and delete the 4-line <localfile> block manually
nano /var/ossec/etc/ossec.conf

# Clean up the stale files
rm -rf /tmp/wazuh_test

# Restart agent
systemctl restart wazuh-agent
```

After this, all generator files were monitored correctly.

## Issue 5 — Agent only reads NEW lines (overwrite vs append)

### Symptom

After copying files with `cp` into `/var/log/wazuh-test/`, alerts didn't
appear right away even though the files were there.

### Root cause

Wazuh's logcollector uses **inode + last-position tracking**. When you:

- Overwrite a file with `cp`: the inode might be replaced, OR if the new
  content is shorter than the old, you get:
  ```
  ossec: File size reduced (inode remained): '/var/log/wazuh-test/paloalto.csv'.
  ```
  The agent then re-reads from position 0 — but that's the entire file,
  not just the new events.
- **Append with `>>` (recommended):** the agent sees genuinely new content
  added after its last read position. Events flow immediately.

### Fix — always append, never overwrite

```bash
cd /opt/wazuh-log-generator
python3 generate_logs.py --all --count 50

# Append (>>) so the agent processes only the new lines
cat output/auth.log         >> /var/log/wazuh-test/auth.log
cat output/web_access.log   >> /var/log/wazuh-test/web_access.log
cat output/mssql_audit.log  >> /var/log/wazuh-test/mssql_audit.log
cat output/paloalto.csv     >> /var/log/wazuh-test/paloalto.csv
cat output/mysql.log        >> /var/log/wazuh-test/mysql.log

chown wazuh:wazuh /var/log/wazuh-test/*
```

## Issue 6 — Palo Alto: 2,046 events arrived but 0 alerts fired

### Symptom

```bash
# On manager
grep "wazuh-test/paloalto" /var/ossec/logs/archives/archives.log | wc -l
# 1896
grep "wazuh-test/paloalto" /var/ossec/logs/alerts/alerts.log | wc -l
# 0
```

In the dashboard:

- `wazuh-archives-*` → 2,046 hits ✅
- `wazuh-alerts-*` → **No Results** ❌

### Diagnostic — wazuh-logtest revealed everything

```bash
echo '1,2026/05/14 06:30:00,012345678901,THREAT,vulnerability,...,critical,...' \
  | /var/ossec/bin/wazuh-logtest

# Output showed:
# Phase 2: Completed decoding.
#   name: 'paloalto'                            ← decoder matched
#   application_risk: 'web-browsing'            ← WRONG — should be a risk level
#   sctp_association_id: 'vulnerability'        ← WRONG — should be a subtype
#   url_category_list: '185.220.101.45'         ← WRONG — should be a category
#
# Phase 3: Completed filtering (rules).
#   id: '64500', level: '0'                     ← generic catch-all rule, silent
```

### Root cause

The `0505-paloalto_decoders.xml` decoder maps CSV fields **by position**.
Real PAN-OS THREAT events have **~70 fields**; our generator produced
only ~36. Every field after column 15 was being read from the wrong slot,
so the **severity** field (which determines the rule level) never landed
where the decoder expected.

Wazuh fell back to rule **64500** (generic Palo Alto event, level 0 — silent),
never matching the critical/high-severity rules **64513 / 64514**.

### Fix

Rewrite `generators/paloalto.py` to emit the full 67-field TRAFFIC and
74-field THREAT/URL records that match the official PAN-OS 8.x–10.x
schema. The fix:

1. Added all 32+ trailing fields to each record (sequence number, source
   country, destination country, FUTURE_USE placeholders, etc.).
2. Ensured `action` lands at column 31, `miscellaneous` at column 32,
   `threat_name` at column 33, `category` at column 34, **`severity` at
   column 35**.
3. Boosted the count of THREAT (vulnerability/spyware) events from 8 to
   80 per generation cycle, and URL-blocked events from 6 to 40.

### Verification

After applying the fixed `paloalto.py`:

```bash
# Field counts now match real PAN-OS
grep ",TRAFFIC," output/paloalto.csv | head -1 | awk -F',' '{print NF}'
# 67  ← correct
grep ",THREAT,vulnerability," output/paloalto.csv | head -1 | awk -F',' '{print NF}'
# 74  ← correct

# Re-test on manager
echo '<one-threat-line-from-output>' | /var/ossec/bin/wazuh-logtest
# Phase 2: severity: 'critical'           ← correctly mapped ✅
# Phase 3: id: '64513', level: '12'       ← real alert fires ✅
```

### Lesson learned

When a Wazuh decoder uses **positional CSV parsing**, field counts must
match the official vendor schema exactly. Any missing or extra columns
shift every subsequent field. Always run `wazuh-logtest` against one
sample line before trusting that an alert will fire.

## Issue 7 — EDR ransomware events absent

### Symptom

`edr_ransomware.json` not in `/var/log/wazuh-test/`, no alerts from
ransomware scenarios.

### Root cause

The EDR ransomware generator (`generators/edr_ransomware.py`) wasn't in
the GitHub repo at deployment time. So `python3 generate_logs.py --all`
silently skipped it (no file → nothing to monitor).

### Fix

1. Add `generators/edr_ransomware.py` to the repo (see separate file).
2. Register it in `generate_logs.py`:

   ```python
   from generators import (
       ...,
       edr_ransomware,    # add this
   )

   SOURCE_MAP = {
       ...,
       "edr": (edr_ransomware, "edr_ransomware.json"),
   }
   ```

3. Regenerate and append:

   ```bash
   python3 generate_logs.py --source edr --count 2
   cat output/edr_ransomware.json >> /var/log/wazuh-test/edr_ransomware.json
   chown wazuh:wazuh /var/log/wazuh-test/edr_ransomware.json
   ```

### Note about ransomware detection coverage

Wazuh's default ruleset will detect:

- File integrity events (rules **550 / 553 / 554**)
- VirusTotal malicious hash (rule **87105**)
- Sysmon process creation generic (rule **61603**)

For **high-severity ransomware-specific alerts** (vssadmin shadow copy
deletion, bcdedit recovery disabled, ransom-extension files,
ransom-note dropped), you need custom rules. See
`custom_rules/ransomware_rules.xml` and Issue 8 below.

## Issue 8 — Confirming which rules actually fire

Throughout the deployment, the most useful diagnostic commands were:

```bash
# Manager: top firing rule IDs
grep "Rule:" /var/ossec/logs/alerts/alerts.log \
  | grep -oE "Rule: [0-9]+" | sort | uniq -c | sort -rn | head -20

# Manager: which source files produced alerts (and how many)
grep "loggen-server" /var/ossec/logs/alerts/alerts.log \
  | grep -oE "/var/log/wazuh-test/[a-z_.]+" \
  | sort | uniq -c

# Manager: per-file event count in archives (whether or not an alert fired)
grep "wazuh-test/<filename>" /var/ossec/logs/archives/archives.log | wc -l

# Manager: test a single log line against the analysis engine
echo '<one log line>' | /var/ossec/bin/wazuh-logtest
```

### `wazuh-logtest` output cheat sheet

| What you see                       | What it means                               |
| ---------------------------------- | ------------------------------------------- |
| `Phase 2: name: '<decoder>'`       | Decoder matched ✅                          |
| `Phase 2: No decoder matched`      | Format mismatch — review the line           |
| `Phase 3: id: 'NNNN', level: '0'`  | Decoded but silent (level 0–2 not surfaced) |
| `Phase 3: id: 'NNNN', level: '5'+` | Will appear in `wazuh-alerts-*`             |

---

# Final agent config (`/var/ossec/etc/ossec.conf`)

After all fixes, the relevant section on the agent looks like:

```xml
<!-- ===== Wazuh log generator inputs ===== -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wazuh-test/auth.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/var/log/wazuh-test/web_access.log</location>
</localfile>

<localfile>
  <log_format>mysql_log</log_format>
  <location>/var/log/wazuh-test/mysql.log</location>
</localfile>

<localfile>
  <log_format>mssql_log</log_format>
  <location>/var/log/wazuh-test/mssql_audit.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wazuh-test/paloalto.csv</location>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>/var/log/wazuh-test/edr_ransomware.json</location>
</localfile>
```

---

# Dashboard verification queries

To confirm everything is wired up, in Wazuh dashboard
(`https://10.1.244.10`):

## See ALL alerts from the generator

- Index pattern: **`wazuh-alerts-*`**
- Filter: `agent.name : loggen-server`
- Time range: Last 24 hours

## See alerts from one specific source

- Add filter: `location : /var/log/wazuh-test/paloalto.csv`
- (replace `paloalto.csv` with the file you want)

## See rule distribution

Click `rule.id` in the field list on the left — popular values panel
shows the top firing rules.

## Compare alerts vs raw events

If a file is "missing" from `wazuh-alerts-*`:

- Switch to `wazuh-archives-*` (top-left dropdown)
- Apply the same filter

If events appear in archives but not alerts → rule level is too low or
decoder is misparsing (see Issue 6).

---

# Operational notes

## Regenerating logs on a schedule

For continuous testing, add to `crontab -e` on the agent server:

```cron
*/5 * * * * cd /opt/wazuh-log-generator && /usr/bin/python3 generate_logs.py --all --count 30 >/dev/null 2>&1 && /bin/cat output/auth.log >> /var/log/wazuh-test/auth.log && /bin/cat output/web_access.log >> /var/log/wazuh-test/web_access.log && /bin/cat output/mysql.log >> /var/log/wazuh-test/mysql.log && /bin/cat output/mssql_audit.log >> /var/log/wazuh-test/mssql_audit.log && /bin/cat output/paloalto.csv >> /var/log/wazuh-test/paloalto.csv && /bin/chown wazuh:wazuh /var/log/wazuh-test/* && /bin/chmod 644 /var/log/wazuh-test/*
```

## File-size considerations

Each `--count 50` run appends roughly:

- `auth.log` → ~10 KB
- `web_access.log` → ~30 KB
- `paloalto.csv` → ~100 KB
- Others → 5–15 KB

Running every 5 minutes adds ~50 MB/day across all files. Set up
logrotate or periodic truncation if running for long periods:

```bash
# Truncate weekly
0 0 * * 0 truncate -s 0 /var/log/wazuh-test/*.log /var/log/wazuh-test/*.csv /var/log/wazuh-test/*.json
```

## Connectivity test

If the agent shows "Disconnected" again:

```bash
# On agent
nc -zv 10.1.244.10 1514
tail -50 /var/ossec/logs/ossec.log | grep -iE "error|warn|connect"

# On manager
/var/ossec/bin/agent_control -l
```

---

# What's NOT covered yet

These are intentional gaps you may want to close as next steps:

1. **Active Directory XML** — the agent can't ingest `active_directory.xml`
   as a flat file. The Wazuh `windows_eventchannel` decoder expects events
   from a real Windows event channel. To test:
   - Pipe individual events through `wazuh-logtest` on the manager
   - OR generate the events on a Windows host with Sysmon installed

2. **Ransomware-specific high-severity alerts** — the built-in ruleset
   produces FIM and VirusTotal alerts, but not "RANSOMWARE!" correlation
   alerts. Install `custom_rules/ransomware_rules.xml` to your manager:

   ```bash
   # On manager
   cp ransomware_rules.xml /var/ossec/etc/rules/
   chown wazuh:wazuh /var/ossec/etc/rules/ransomware_rules.xml
   chmod 660 /var/ossec/etc/rules/ransomware_rules.xml
   systemctl restart wazuh-manager
   ```

3. **Production syslog ingestion** — real Palo Alto firewalls send via
   UDP/514 syslog, not as files. For closer-to-production behavior,
   configure a syslog listener on the manager:

   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>udp</protocol>
     <allowed-ips>10.0.0.0/8</allowed-ips>
   </remote>
   ```

---

# Quick reference — server-by-server cheat sheet

## On 10.1.244.10 (manager / `ctl`)

```bash
# Service status
systemctl status wazuh-manager

# Live alerts
tail -f /var/ossec/logs/alerts/alerts.log

# Agent list
/var/ossec/bin/agent_control -l

# Test a log line
echo '<line>' | /var/ossec/bin/wazuh-logtest

# Top firing rules
grep "Rule:" /var/ossec/logs/alerts/alerts.log \
  | grep -oE "Rule: [0-9]+" | sort | uniq -c | sort -rn | head

# Dashboard
# https://10.1.244.10
```

## On 10.1.244.110 (agent / `gen`)

```bash
# Service status
systemctl status wazuh-agent

# Confirm files monitored
grep "Analyzing file" /var/ossec/logs/ossec.log | grep wazuh-test

# Generate + append logs
cd /opt/wazuh-log-generator
python3 generate_logs.py --all --count 50
for f in auth.log web_access.log mysql.log mssql_audit.log paloalto.csv; do
  cat output/$f >> /var/log/wazuh-test/$f
done
chown wazuh:wazuh /var/log/wazuh-test/*

# Connection to manager
tail /var/ossec/logs/ossec.log | grep -i connected
```
