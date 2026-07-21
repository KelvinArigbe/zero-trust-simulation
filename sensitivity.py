"""
Sensitivity analysis: how does the Zero Trust architecture's
containment rate and false-positive exposure change as the PDP's
risk threshold is varied?

This matters because Section 3.3's design choice of a single risk
threshold (0.55) is a parameter, not a law of nature -- a real
implementation would need to tune this value, trading off
containment effectiveness against the risk of flagging legitimate
users unnecessarily (a false positive). This analysis makes that
trade-off explicit rather than presenting one threshold as if it
were the only possible choice.
"""

import random
import statistics
import json
from simulation import ZONES, TARGET_ZONE

random.seed(42)

N_TRIALS = 2000
THRESHOLDS = [0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75]


def simulate_zt_trial_with_threshold(threshold):
    identity_confidence = random.uniform(0.75, 0.98)
    device_posture = random.uniform(0.10, 0.55)
    behavioural_consistency = random.uniform(0.05, 0.45)

    risk_score = (
        (1 - identity_confidence) * 0.2
        + (1 - device_posture) * 0.35
        + (1 - behavioural_consistency) * 0.45
    )

    steps = 0
    zone_index = 0
    contained = False
    detection_step = None

    steps += 1
    if risk_score >= threshold:
        contained = True
        detection_step = steps
    else:
        while zone_index < len(ZONES) - 1:
            steps += 1
            zone_index += 1
            risk_score += random.uniform(0.05, 0.15)
            if risk_score >= threshold:
                contained = True
                detection_step = steps
                break
            if zone_index == ZONES.index(TARGET_ZONE):
                contained = False
                break

    reached_target = not contained
    return {"contained": contained, "reached_target": reached_target, "detection_time": detection_step}


def simulate_legitimate_user_trial(threshold):
    """
    A legitimate user's session, scored by the same PDP logic, to
    measure the false-positive rate at a given threshold -- i.e. how
    often a genuine user would be incorrectly flagged or interrupted.
    Legitimate users mostly score low risk, but a realistic minority
    of sessions involve a new phone, travel, or an unusual access
    time -- exactly the situations that make Zero Trust threshold
    tuning a genuine trade-off rather than a free win. This is drawn
    from a beta-shaped distribution skewed toward low risk, with a
    longer tail than the attack model's signals, reflecting that
    legitimate behaviour is varied but rarely indistinguishable from
    an attacker's.
    """
    identity_confidence = random.uniform(0.85, 0.999)
    device_posture = random.betavariate(4, 1.3)        # skewed high, occasional low outlier
    behavioural_consistency = random.betavariate(4, 1.3)

    risk_score = (
        (1 - identity_confidence) * 0.2
        + (1 - device_posture) * 0.35
        + (1 - behavioural_consistency) * 0.45
    )
    flagged = risk_score >= threshold
    return {"flagged": flagged}


results_by_threshold = []
for t in THRESHOLDS:
    attack_trials = [simulate_zt_trial_with_threshold(t) for _ in range(N_TRIALS)]
    legit_trials = [simulate_legitimate_user_trial(t) for _ in range(N_TRIALS)]

    containment_rate = 100 * sum(1 for r in attack_trials if r["contained"]) / N_TRIALS
    false_positive_rate = 100 * sum(1 for r in legit_trials if r["flagged"]) / N_TRIALS

    results_by_threshold.append({
        "threshold": t,
        "containment_rate_pct": round(containment_rate, 1),
        "false_positive_rate_pct": round(false_positive_rate, 1),
    })

print(json.dumps(results_by_threshold, indent=2))

with open("sensitivity_results.json", "w") as f:
    json.dump(results_by_threshold, f, indent=2)
