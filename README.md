# Wazuh Log Generator

Generates realistic sample logs for testing Wazuh detection rules across six
log sources. Each generator embeds **specific attack scenarios** that are
calibrated to trip the default Wazuh ruleset — both single-event rules and
frequency / correlation rules.

## Quick start

```bash
python3 generate_logs.py --all                  # all sources, ~40 events each
python3 generate_logs.py --source ad            # one source only
python3 generate_logs.py --source web --count 100
```

Output is written to `./output/`:

| File                    | Source                | Wazuh decoder       |
|-------------------------|-----------------------|---------------------|
| `active_directory.xml`  | Windows AD events     | `windows_eventchannel` |
| `mssql_audit.log`       | MSSQL ERRORLOG        | `mssql_log`         |
| `mysql.log`             | MySQL error + general | `mysql_log`         |
| `paloalto.csv`          | PAN-OS syslog         | `paloalto`          |
| `web_access.log`        | Apache combined       | `web-accesslog`     |
| `auth.log`              | Linux auth (sshd/sudo)| `sshd`, `sudo`, `pam` |

## How to feed it into Wazuh

The simplest path: copy each file to a path the agent monitors, e.g.

```yaml
# /var/ossec/etc/ossec.conf  (on the agent)
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/wazuh-test/web_access.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wazuh-test/auth.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wazuh-test/mssql_audit.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wazuh-test/mysql.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wazuh-test/paloalto.csv</location>
</localfile>
```

For the Windows XML file, you can either pipe individual events through
`wazuh-logtest` on the manager, or send them to an agent's event channel via
PowerShell.

### Testing individual events on the manager

```bash
# Pick a single line and pipe it
sed -n '5p' output/auth.log | /var/ossec/bin/wazuh-logtest

# For Apache logs you must declare the format:
echo '<log_format apache>' | /var/ossec/bin/wazuh-logtest
# (or use -U "rule_id:agent_id:user")
```

## Embedded attack scenarios → Wazuh rules

Each generator embeds at least one attack pattern designed to fire a
*specific* rule chain. The exact rule IDs below reference Wazuh's
default ruleset (v4.x).

### `active_directory.xml`

| Scenario              | Event IDs         | Wazuh rules (defaults)      |
|-----------------------|-------------------|-----------------------------|
| Normal logon          | 4624              | 60106 (info)                |
| **Brute force burst** | 10× 4625 from one external IP | 60122 → 60204 (frequency) |
| Account lockout       | 4740              | 60123                       |
| New user created      | 4720              | 60103                       |
| Added to Administrators | 4732            | 60112                       |
| **AS-REP roast attempt** | 4768 PreAuth=0, rc4_hmac | custom / 92651 |
| **Kerberoasting**     | 4769 rc4_hmac on SPN | custom / 92652           |
| Special privileges    | 4672              | 60106                       |

### `auth.log` (Linux)

| Scenario                | Lines | Wazuh rules               |
|-------------------------|-------|---------------------------|
| **SSH brute force**     | 20 Failed password + Invalid user from one IP | 5710 → 5712 (frequency) |
| Compromise after brute force | 1 Accepted password from same attacker IP | 5715 (correlated)  |
| Root login refused      | 3     | 5404                      |
| Sudo command            | 8     | 5402                      |
| **Sudo failure**        | 3     | 5401                      |
| PAM authentication failure | 4  | 5503                      |
| **User added (post-compromise)** | 1 | 5902                |

### `mssql_audit.log`

| Scenario                       | Lines | Wazuh hook                  |
|--------------------------------|-------|-----------------------------|
| **Brute force on `sa`**        | 15 Login failed for 'sa' | mssql_log decoder, custom freq rule |
| Login failed (no such user)    | 2     | sql_log auth-failure        |
| **xp_cmdshell execution**      | 3     | high-risk: command exec via DB |
| **sysadmin role grant**        | 1     | privilege escalation        |
| UNION SELECT against sys.sql_logins | 1 | SQLi indicator             |

### `mysql.log`

| Scenario                          | Lines | Wazuh rule family       |
|-----------------------------------|-------|-------------------------|
| **Access denied burst on root**   | 12    | mysql brute-force chain |
| **GRANT ALL ... WITH GRANT OPTION** | 1   | privilege escalation    |
| **CREATE USER backdoor_***        | 1     | suspicious account creation |
| **DROP DATABASE production**      | 1     | destructive DDL         |
| UNION SELECT / SLEEP() / LOAD_FILE | 4    | SQLi behind app         |

### `paloalto.csv`

| Scenario              | Subtype  | Wazuh rules                  |
|-----------------------|----------|------------------------------|
| Normal allow traffic  | TRAFFIC  | 63100 (info)                 |
| **Port scan**         | TRAFFIC `deny` × 25 from one IP, varied dst ports | 63103 → 63152 (frequency) |
| **THREAT critical**   | THREAT (vulnerability/spyware) | 63111 (critical severity) |
| Log4Shell / ZeroLogon / Cobalt Strike signatures | THREAT | 63111 |
| **Malicious URL blocked** | THREAT url, block-url, malware/c2/phishing | 63115 |

### `web_access.log`

| Scenario              | Pattern                              | Wazuh rules     |
|-----------------------|--------------------------------------|-----------------|
| **SQL injection**     | `' OR '1'='1`, `UNION SELECT`, `SLEEP(5)` | 31103, 31106 |
| **XSS**               | `<script>`, `onerror=`, `<svg/onload=>` | 31104        |
| **Path traversal / LFI** | `../../../etc/passwd`, `....//etc/shadow` | 31106 |
| **RCE attempt**       | `;cat /etc/passwd`, `` `id` ``, `$(id)`   | 31106 / 31104 |
| **Scanner user-agent**| `sqlmap`, `Nikto`, `Nmap NSE`        | 31151           |
| **Login brute force** | 15× `POST /login` → 401 from one IP  | 31108 → 31151 (chain) |
| **Shellshock UA**     | `() { :; };` payload                 | 31168           |

## Customising

- **More volume**: `--count 500`
- **One source only**: `--source paloalto`
- **Edit attacker IPs / usernames**: see `generators/common.py`
- **Add a new attack pattern**: drop a function into the matching
  `generators/<source>.py` and append to the events list inside `generate()`.

## Project layout

```
log-generator/
├── generate_logs.py            # CLI entry point
├── generators/
│   ├── __init__.py
│   ├── common.py               # shared helpers, IP/user pools, time fns
│   ├── active_directory.py
│   ├── mssql_db.py
│   ├── mysql_db.py
│   ├── paloalto.py
│   ├── web_app.py
│   └── auth_alerts.py
└── output/                     # generated logs (created on first run)
```

## Reproducibility

The default mode uses fresh randomness every run. If you want reproducible
output for regression tests, set a fixed seed at the top of
`generators/common.py`:

```python
random.seed(42)
```
