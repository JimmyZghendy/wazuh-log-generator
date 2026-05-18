# Wazuh Log Generator — Component Command Reference

Quick reference for generating, appending, and fixing ownership of test logs
for every supported component.

All commands assume you're starting from:

```bash
cd /opt/wazuh-log-generator
```

---

## Master command table

| #   | Component                | `--source` name    | Output file                    | Watched file (`<location>`)                 | Log format  |
| --- | ------------------------ | ------------------ | ------------------------------ | ------------------------------------------- | ----------- |
| 1   | Active Directory         | `active_directory` | `output/active_directory.json` | `/var/log/wazuh-test/active_directory.json` | `json`      |
| 2   | Auth Alerts (auth.log)   | `auth_alerts`      | `output/auth.log`              | `/var/log/wazuh-test/auth.log`              | `syslog`    |
| 3   | Common (mixed/baseline)  | `common`           | `output/common.log`            | `/var/log/wazuh-test/common.log`            | `syslog`    |
| 4   | EDR / Ransomware         | `edr_ransomware`   | `output/edr_ransomware.json`   | `/var/log/wazuh-test/edr_ransomware.json`   | `json`      |
| 5   | Palo Alto Firewall       | `paloalto`         | `output/paloalto.csv`          | `/var/log/wazuh-test/paloalto.csv`          | `syslog`    |
| 6   | Web Application (Apache) | `web_app`          | `output/web_access.log`        | `/var/log/wazuh-test/web_access.log`        | `apache`    |
| 7   | MySQL Database           | `mysql_db`         | `output/mysql.log`             | `/var/log/wazuh-test/mysql.log`             | `mysql_log` |
| 8   | MSSQL Database           | `mssql_db`         | `output/mssql_audit.log`       | `/var/log/wazuh-test/mssql_audit.log`       | `mssql_log` |

---

## Per-component command blocks

Each block follows the same 3-step pattern: **generate → append → chown**.

### 1. Active Directory

```bash
cd /opt/wazuh-log-generator
# 1. Generate
python3 generate_logs.py --source active_directory --count 30
# 2. Append to the watched file (so the agent sees NEW lines)
cat output/active_directory.json >> /var/log/wazuh-test/active_directory.json
# 3. Fix ownership
chown wazuh:wazuh /var/log/wazuh-test/active_directory.json
```

**Agent `<localfile>` block:**

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/wazuh-test/active_directory.json</location>
</localfile>
```

---

### 2. Auth Alerts

```bash
cd /opt/wazuh-log-generator
# 1. Generate
python3 generate_logs.py --source auth_alerts --count 30
# 2. Append to the watched file (so the agent sees NEW lines)
cat output/auth.log >> /var/log/wazuh-test/auth.log
# 3. Fix ownership
chown wazuh:wazuh /var/log/wazuh-test/auth.log
```

**Agent `<localfile>` block:**

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wazuh-test/auth.log</location>
</localfile>
```

---

### 3. Common (baseline / mixed)

```bash
cd /opt/wazuh-log-generator
# 1. Generate
python3 generate_logs.py --source common --count 30
# 2. Append to the watched file (so the agent sees NEW lines)
cat output/common.log >> /var/log/wazuh-test/common.log
# 3. Fix ownership
chown wazuh:wazuh /var/log/wazuh-test/common.log
```

**Agent `<localfile>` block:**

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wazuh-test/common.log</location>
</localfile>
```

---

### 4. EDR / Ransomware

```bash
cd /opt/wazuh-log-generator
# 1. Generate
python3 generate_logs.py --source edr_ransomware --count 30
# 2. Append to the watched file (so the agent sees NEW lines)
cat output/edr_ransomware.json >> /var/log/wazuh-test/edr_ransomware.json
# 3. Fix ownership
chown wazuh:wazuh /var/log/wazuh-test/edr_ransomware.json
```

**Agent `<localfile>` block:**

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/wazuh-test/edr_ransomware.json</location>
</localfile>
```

---

### 5. Palo Alto Firewall

```bash
cd /opt/wazuh-log-generator
# 1. Generate
python3 generate_logs.py --source paloalto --count 30
# 2. Append to the watched file (so the agent sees NEW lines)
cat output/paloalto.csv >> /var/log/wazuh-test/paloalto.csv
# 3. Fix ownership
chown wazuh:wazuh /var/log/wazuh-test/paloalto.csv
```

**Agent `<localfile>` block:**

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wazuh-test/paloalto.csv</location>
</localfile>
```

---

### 6. Web Application (Apache)

```bash
cd /opt/wazuh-log-generator
# 1. Generate
python3 generate_logs.py --source web_app --count 30
# 2. Append to the watched file (so the agent sees NEW lines)
cat output/web_access.log >> /var/log/wazuh-test/web_access.log
# 3. Fix ownership
chown wazuh:wazuh /var/log/wazuh-test/web_access.log
```

**Agent `<localfile>` block:**

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/wazuh-test/web_access.log</location>
</localfile>
```

---

### 7. MySQL Database

```bash
cd /opt/wazuh-log-generator
# 1. Generate
python3 generate_logs.py --source mysql_db --count 30
# 2. Append to the watched file (so the agent sees NEW lines)
cat output/mysql.log >> /var/log/wazuh-test/mysql.log
# 3. Fix ownership
chown wazuh:wazuh /var/log/wazuh-test/mysql.log
```

**Agent `<localfile>` block:**

```xml
<localfile>
  <log_format>mysql_log</log_format>
  <location>/var/log/wazuh-test/mysql.log</location>
</localfile>
```

---

### 8. MSSQL Database

```bash
cd /opt/wazuh-log-generator
# 1. Generate
python3 generate_logs.py --source mssql_db --count 30
# 2. Append to the watched file (so the agent sees NEW lines)
cat output/mssql_audit.log >> /var/log/wazuh-test/mssql_audit.log
# 3. Fix ownership
chown wazuh:wazuh /var/log/wazuh-test/mssql_audit.log
```

**Agent `<localfile>` block:**

```xml
<localfile>
  <log_format>mssql_log</log_format>
  <location>/var/log/wazuh-test/mssql_audit.log</location>
</localfile>
```

---

## Run-all helper (optional)

If you want to fire all 8 components in one go:

```bash
cd /opt/wazuh-log-generator

for src in active_directory auth_alerts common edr_ransomware paloalto web_app mysql_db mssql_db; do
  echo "=== Generating: $src ==="
  python3 generate_logs.py --source "$src" --count 30
done

# Append everything to the watched files (filenames match what's in output/)
for f in output/*; do
  name=$(basename "$f")
  echo "=== Appending: $name ==="
  cat "$f" >> "/var/log/wazuh-test/$name"
done

# Fix ownership on the whole watched directory in one shot
chown -R wazuh:wazuh /var/log/wazuh-test/
```

---

## Verifying the agent is picking up each file

On **gen**:

```bash
grep -E 'wazuh-test' /var/ossec/logs/ossec.log | tail -20
```

You should see one `INFO: Analyzing file:` line per `<localfile>` location.

On **ctl** (manager):

```bash
tail -f /var/ossec/logs/alerts/alerts.json | grep -oE '"id":"[0-9]+"' | sort -u
```

Leave it running for ~30 seconds after appending — you'll see which rule
IDs are firing across all components.

---

## Notes

- `--count 30` is illustrative; tune up or down as needed.
- All watched files live under `/var/log/wazuh-test/` and must be owned by
  `wazuh:wazuh` so the agent process can read them.
- `<log_format>` in the agent config **must** match the file format —
  `json` for JSON-per-line, `syslog` for plain syslog-style lines, `apache`
  for combined-log-format access logs, `mysql_log` / `mssql_log` for the
  respective DB audit formats. Mismatched format = decoder fails = no alerts.
- If you ever rotate or truncate a watched file, restart the agent so it
  re-reads from the start: `systemctl restart wazuh-agent`.
