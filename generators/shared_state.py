import random
from .common import (
    NOISY_USERS, TOR_EXITS, SCANNER_IPS, C2_IPS,
    HOSTS_WS, HOSTS_BANKING, HOSTS_DB, DATABASES_SENSITIVE,
    USERS_BY_NAME,
)


def _build_incidents(n: int = 2) -> list:
    """Pick `n` incidents for this run. Each incident is self-consistent.
    If n is larger than the number of unique attacker IPs or victim users,
    values are cycled (reused) to avoid errors.
    """
    incidents = []

    # 1. Build a pool of unique attacker IPs (with labels)
    attacker_pool = []
    seen_ips = set()
    for label, ip_list in [("tor", TOR_EXITS), ("scanner", SCANNER_IPS), ("c2", C2_IPS)]:
        for ip in ip_list:
            if ip not in seen_ips:
                seen_ips.add(ip)
                attacker_pool.append((label, ip))
    random.shuffle(attacker_pool)

    # If n > len(attacker_pool), we will cycle through the pool
    # (repeat IPs but that's acceptable; the correlation still works per incident)
    attacker_cycle = [attacker_pool[i % len(attacker_pool)] for i in range(n)]

    # 2. Build a pool of victim users (distinct by username)
    victim_pool = []
    seen_users = set()
    for u in NOISY_USERS:
        if u["username"] not in seen_users:
            seen_users.add(u["username"])
            victim_pool.append(u)
    random.shuffle(victim_pool)

    # If n > len(victim_pool), cycle through the pool
    victim_cycle = [victim_pool[i % len(victim_pool)] for i in range(n)]

    # 3. Assemble n incidents
    for i in range(n):
        attacker_label, attacker_ip = attacker_cycle[i]
        victim = victim_cycle[i]
        victim_host = random.choice(HOSTS_WS)
        target_db = random.choice(DATABASES_SENSITIVE)
        target_db_host = random.choice(HOSTS_DB)

        incidents.append({
            "id":             f"INC-{i+1:03d}",
            "attacker_ip":    attacker_ip,
            "attacker_label": attacker_label,
            "victim_user":    victim["username"],
            "victim_priv":    victim["privilege"],
            "victim_host":    victim_host,
            "target_db":      target_db,
            "target_db_host": target_db_host,
            "type":           "ransomware",
            "c2_ip":          attacker_ip,   # for EDR correlation
        })

    return incidents


# Build incidents with a default of 2, but will be overwritten later by _reinit_incidents
# (We keep a placeholder; the real list is mutated in generate_logs.py)
INCIDENTS = _build_incidents(n=2)


# Convenience flat lists — these will be updated via mutation as well
ATTACKER_IPS_ACTIVE  = [i["attacker_ip"]  for i in INCIDENTS]
VICTIM_USERS_ACTIVE  = [i["victim_user"]  for i in INCIDENTS]
VICTIM_HOSTS_ACTIVE  = [i["victim_host"]  for i in INCIDENTS]

def print_incidents():
    """Print current incidents in a human-readable format."""
    print("\n=== Active incidents this run ===")
    for inc in INCIDENTS:
        print(f"  {inc['id']}: attacker {inc['attacker_ip']:16} ({inc['attacker_label']:7}) -> "
              f"victim {inc['victim_user']:20} @ {inc['victim_host']}  target {inc['target_db']}")
    print("======================================================================")
