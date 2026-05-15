# Wazuh Log Generator

A Python toolkit for producing realistic, attack-laden log samples to validate
[Wazuh](https://wazuh.com/) detection rules across six common log sources.
Each generator embeds documented attack scenarios — calibrated to trigger
single-event rules, frequency rules, and correlation chains in the default
Wazuh ruleset.

> 📘 **Deploying this in a Wazuh environment?**
> See [**SIEM_INTEGRATION.md**](./SIEM_INTEGRATION.md) for the full
> deployment walkthrough, agent/manager configuration, known issues, and
> verified fixes from a production setup.

---

## Why this exists

SIEM detection engineering is hard to validate without realistic data.
Production logs are sensitive, sanitized samples rarely contain attack
patterns, and synthetic data often doesn't match the format real decoders
expect. This generator solves that by:

- Producing logs in the **exact format** Wazuh's built-in decoders consume
- Embedding **specific attack scenarios** mapped to specific rule IDs
- Generating realistic **timing patterns** (bursts, frequency thresholds)
  so correlation rules actually fire

## Supported log sources

| Source                   | Output file            | Wazuh decoder              | Default rules triggered           |
| ------------------------ | ---------------------- | -------------------------- | --------------------------------- |
| Windows Active Directory | `active_directory.xml` | `windows_eventchannel`     | 60103, 60112, 60122, 60123        |
| Linux authentication     | `auth.log`             | `sshd`, `sudo`, `pam_unix` | 5402, 5503, 5710, 5712, 5715      |
| MSSQL Server             | `mssql_audit.log`      | `mssql_log`                | 85004, 85005, 85006               |
| MySQL                    | `mysql.log`            | `mysql_log`                | 50106, 50108, 50120               |
| Palo Alto Networks       | `paloalto.csv`         | `paloalto`                 | 64500–64517                       |
| Web application          | `web_access.log`       | `web-accesslog`            | 31101, 31103, 31104, 31106, 31151 |

---

## Quick start

### Requirements

- Python 3.8+
- No external dependencies (standard library only)

### Installation

```bash
git clone https://github.com/JimmyZghendy/wazuh-log-generator.git
cd wazuh-log-generator
```

### Usage

```bash
# Generate all sources with default volume (~40 events each)
python3 generate_logs.py --all

# One source, custom volume
python3 generate_logs.py --source paloalto --count 100

# Available sources
python3 generate_logs.py --help
```

Output files are written to `./output/` and ready for ingestion.

---

## Attack scenarios

Each generator embeds attack patterns calibrated to fire specific Wazuh
rule chains. Selected highlights:

### Active Directory (`active_directory.xml`)

| Scenario                                   | MITRE                  | Rule chain        |
| ------------------------------------------ | ---------------------- | ----------------- |
| Failed-logon burst from external IP        | T1110 — Brute Force    | 60122 → frequency |
| Account lockout                            | T1110 — Brute Force    | 60123             |
| New user created → added to Administrators | T1136 — Create Account | 60103 + 60112     |
| AS-REP roast attempt (PreAuth=0, RC4)      | T1558.004              | custom / 92651    |
| Kerberoasting (RC4 ticket on SPN)          | T1558.003              | custom / 92652    |

### Linux authentication (`auth.log`)

| Scenario                                        | MITRE                  | Rule chain  |
| ----------------------------------------------- | ---------------------- | ----------- |
| SSH brute force (20× failures from one IP)      | T1110 — Brute Force    | 5710 → 5712 |
| Compromise after brute force (successful login) | T1078 — Valid Accounts | 5715        |
| Root login refused                              | T1078.003              | 5404        |
| Sudo command execution                          | T1548.003              | 5402        |
| User added post-compromise                      | T1136 — Create Account | 5902        |

### MSSQL (`mssql_audit.log`)

| Scenario                                   | MITRE                                     | Rule trigger         |
| ------------------------------------------ | ----------------------------------------- | -------------------- |
| Brute force on `sa` account (15× failures) | T1110                                     | mssql_log decoder    |
| `xp_cmdshell` invocation                   | T1059 — Command and Scripting Interpreter | privilege escalation |
| Server role membership grant (`sysadmin`)  | T1078 — Valid Accounts                    | privilege escalation |
| SQL injection against `sys.sql_logins`     | T1190 — Exploit Public-Facing App         | SQLi indicator       |

### MySQL (`mysql.log`)

| Scenario                                                | MITRE                        | Rule family                 |
| ------------------------------------------------------- | ---------------------------- | --------------------------- |
| Access-denied burst on `root` (12×)                     | T1110                        | mysql brute-force chain     |
| `GRANT ALL ... WITH GRANT OPTION`                       | T1098 — Account Manipulation | privilege escalation        |
| `CREATE USER backdoor_*`                                | T1136                        | suspicious account creation |
| `DROP DATABASE production`                              | T1485 — Data Destruction     | destructive DDL             |
| SQL injection patterns (UNION SELECT, SLEEP, LOAD_FILE) | T1190                        | SQLi indicators             |

### Palo Alto Networks (`paloalto.csv`)

| Scenario                                            | Subtype        | Severity | Rule              |
| --------------------------------------------------- | -------------- | -------- | ----------------- |
| Port scan from one IP, 25× varied destination ports | TRAFFIC `deny` | —        | 64504 (frequency) |
| Log4Shell exploit attempt                           | THREAT         | critical | 64513             |
| Cobalt Strike beacon                                | THREAT         | critical | 64513             |
| ZeroLogon (CVE-2020-1472)                           | THREAT         | critical | 64513             |
| Mimikatz signature                                  | THREAT         | critical | 64513             |
| Malicious URL block (C2 / phishing / malware)       | URL            | high     | 64509             |

> **Note:** Palo Alto records are emitted in the full ~70-field PAN-OS
> schema. Field positions matter — the Wazuh decoder parses by column
> index. See `SIEM_INTEGRATION.md` for details.

### Web application (`web_access.log`)

| Scenario                           | MITRE                                | Pattern                                     | Rule          |
| ---------------------------------- | ------------------------------------ | ------------------------------------------- | ------------- |
| SQL injection                      | T1190                                | `' OR '1'='1`, `UNION SELECT`, `SLEEP(5)`   | 31103, 31106  |
| Cross-site scripting               | T1059.007                            | `<script>`, `onerror=`, `<svg/onload>`      | 31104         |
| Path traversal / LFI               | T1083 — File and Directory Discovery | `../../../etc/passwd`                       | 31106         |
| Remote command execution           | T1059                                | `;id`, `` `whoami` ``, `$(cat /etc/shadow)` | 31104, 31106  |
| Scanner user-agent                 | T1595 — Active Scanning              | `sqlmap`, `Nikto`, `Nmap NSE`               | 31151         |
| Login brute force                  | T1110                                | 15× `POST /login` → 401 from one IP         | 31108 → 31151 |
| Shellshock exploit (CVE-2014-6271) | T1190                                | `() { :; };` payload in UA                  | 31168         |

---

## Project structure

```
wazuh-log-generator/
├── README.md                       ← you are here
├── SIEM_INTEGRATION.md             ← deployment playbook & troubleshooting
├── generate_logs.py                ← CLI entry point
├── generators/
│   ├── __init__.py
│   ├── common.py                   ← shared helpers, IP/user pools
│   ├── active_directory.py
│   ├── auth_alerts.py
│   ├── mssql_db.py
│   ├── mysql_db.py
│   ├── paloalto.py
│   └── web_app.py
└── output/                         ← generated logs (created on first run)
```

---

## Integration with Wazuh

For step-by-step deployment instructions covering both the agent and
manager sides, see **[SIEM_INTEGRATION.md](./SIEM_INTEGRATION.md)**.
That document covers:

- Agent installation (Ubuntu/Debian, RHEL/Rocky)
- Manager-side agent registration
- The full `<localfile>` configuration block
- Verification with `wazuh-logtest`
- Dashboard queries (`wazuh-alerts-*` vs `wazuh-archives-*`)
- Common deployment issues and their fixes

### Minimal `ossec.conf` snippet

Drop the following inside the `<ossec_config>` block on the Wazuh agent
that should monitor the generated files. Adjust paths if needed.

```xml
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
```

### Validating a single line

To test how a generated event is decoded and which rule (if any) fires:

```bash
# On the Wazuh manager
sed -n '5p' output/auth.log | /var/ossec/bin/wazuh-logtest
```

The output shows the decoder match (Phase 2) and rule that fired (Phase 3).

---

## Customisation

| What you want to change              | Where                                                     |
| ------------------------------------ | --------------------------------------------------------- |
| Attacker IPs / usernames / hostnames | `generators/common.py`                                    |
| Volume of generated events           | CLI `--count` flag                                        |
| Attack-pattern frequency             | Loop counts inside each generator's `generate()`          |
| Add a new log source                 | New file in `generators/`, register in `generate_logs.py` |

### Reproducible output for regression tests

Set a fixed random seed at the top of `generators/common.py`:

```python
random.seed(42)
```

---

## Operational considerations

### Append, don't overwrite

When pushing generated content into a Wazuh-monitored directory, **append**
with `>>` instead of overwriting with `cp`. Wazuh's logcollector tracks
file inode and read position, so overwrite operations can cause it to
re-read the entire file or miss new content. Detailed explanation in
[`SIEM_INTEGRATION.md`](./SIEM_INTEGRATION.md).

```bash
# Recommended
cat output/auth.log >> /var/log/wazuh-test/auth.log

# Avoid
cp output/auth.log /var/log/wazuh-test/auth.log
```

### Continuous generation

For ongoing testing, schedule the generator via cron:

```cron
*/5 * * * * cd /opt/wazuh-log-generator && python3 generate_logs.py --all --count 30 >/dev/null 2>&1
```

---

## Roadmap

- AWS CloudTrail log generator
- Azure activity log generator
- Cisco ASA / FTD generator
- Sysmon Linux generator
- EDR ransomware generator (FIM + Sysmon + VirusTotal correlation)
- Optional syslog-listener mode (send directly to manager over UDP/514)

---

## License

MIT — see `LICENSE`.

## Contributing

Pull requests welcome, particularly for additional log sources or
attack scenarios. Please ensure each new generator:

1. Produces output that passes through the relevant Wazuh decoder
   (verify with `wazuh-logtest`)
2. Embeds at least one explicit attack scenario mapped to a known rule
3. Documents the rule IDs it targets in this README
