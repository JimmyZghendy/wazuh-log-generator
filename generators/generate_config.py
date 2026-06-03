"""
Shared ratio constants used by all generators to enforce the 60/40 split.

60% of total events should be benign baseline (do NOT trigger Wazuh alerts or
trigger only low-level rules that the agent ignores).
40% should be attack/suspicious events that produce correlated Wazuh alerts.

Within the 40% attack slice:
  - 70% are scenario-driven (tied to incident attacker_ip + victim_user)
    -> these ARE what the correlation agent groups into incidents
  - 30% are standalone (real attack patterns but NOT tied to any incident)
    -> these produce alerts the agent should classify as isolated/FP

This split is enforced by each generator scaling its standalone counts down.
"""

# Ratio knobs — tune without touching individual generators
NORMAL_RATIO    = 0.60   # fraction of all events that are benign baseline
ATTACK_RATIO    = 0.40   # fraction that produce alerts
CORRELATED_FRAC = 0.70   # of attack events: fraction tied to incident chains
STANDALONE_FRAC = 0.30   # of attack events: fraction as isolated noise

def scale_standalone(count: int, incidents: int) -> int:
    """
    Given the per-generator `count` arg and number of incidents,
    return how many standalone (non-incident) attack events to produce.
    Keeps standalones proportional to incident chains.
    """
    # Approximate attack events from incident chains (roughly 15 events/incident)
    chain_events = incidents * 15
    # standalone should be 30/70 of chain events
    return max(2, int(chain_events * (STANDALONE_FRAC / CORRELATED_FRAC)))
