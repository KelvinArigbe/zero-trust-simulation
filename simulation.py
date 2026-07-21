"""
Zero Trust vs. Perimeter Security simulation.

Models two architectures responding to the same attack scenario:
credential compromise (MITRE ATT&CK: Credential Access) followed by
an attempt at lateral movement toward the core banking database
(MITRE ATT&CK: Lateral Movement).

PERIMETER MODEL:
  - One checkpoint: login at the network edge.
  - Once authenticated, the session is trusted for its full duration.
  - No re-verification, no segmentation: a successful login can reach
    any zone the underlying network access already permits.
  - Detection only occurs via passive review (e.g. someone notices
    something looks wrong) at a randomly distributed later point.

ZERO TRUST MODEL (per Chapter 3 design):
  - Every request hits a Policy Decision Point (PDP).
  - The PDP scores each request using three signals: identity
    confidence, device posture, and behavioral consistency.
  - Each network zone has its own Policy Enforcement Point (PEP),
    which only allows traffic carrying a current, valid PDP token.
  - A request that scores below a risk threshold is flagged for
    step-up verification or denied outright, which is what produces
    fast detection of anomalous behaviour.

The simulation runs N independent attack trials through both
architectures and records, per trial:
  - detection_time   (steps until the attack is flagged)
  - contained        (whether the attacker reached the core banking
                       data zone before being stopped)
  - response_time    (steps from detection to access being revoked)

This is a discrete-event style simulation with stochastic signal
quality, not a deterministic walkthrough -- the randomness reflects
genuine uncertainty in attacker skill, credential quality, and how
closely an attacker can mimic legitimate behaviour, consistent with
the scenario design in Section 3.4.
"""

import random
import statistics
import json

random.seed(42)  # reproducibility for the written report

# ----------------------------------------------------------------------
# Network zones, consistent with Section 3.3's three-zone segmentation
# ----------------------------------------------------------------------
ZONES = ["customer_transaction", "core_banking_data", "internal_admin"]
TARGET_ZONE = "core_banking_data"  # the attacker's objective (Section 3.4)

N_TRIALS = 1000


def simulate_perimeter_trial():
    """
    Perimeter model: one gate at login. Once past it, the attacker's
    compromised session is trusted across all zones with no further
    checks. Detection only happens through passive, after-the-fact
    review, modelled as a geometric random delay (consistent with
    NIBSS's finding that Nigerian banks tend to discover fraud after
    the fact rather than during the event -- Section 1.2).
    """
    steps = 0
    zone_index = 0

    # Step 1: credential access -- attacker logs in with stolen creds.
    # Perimeter model has no behavioural check at login beyond the
    # password/MFA gate itself, which the attacker has already passed
    # by definition of "credential access" succeeding.
    steps += 1
    login_succeeds = True  # by construction: this trial models a
                            # successful credential compromise

    contained = False
    detection_step = None

    # Passive detection delay: modelled as a geometric distribution
    # with mean ~14 steps, loosely calibrated to NIBSS's finding that
    # institutions absorb fraud impact across a full reporting period
    # rather than catching it immediately (Section 1.2). A "step" here
    # represents one discrete unit of attacker activity, not a fixed
    # wall-clock unit -- the simulation measures relative not absolute
    # timing, consistent with the analytical (not live) scope in 1.4.
    passive_detection_step = max(1, int(random.gammavariate(2, 7)))

    # Distance from entry zone to target zone, in hops. With only
    # three zones and no segmentation, an attacker can reach the
    # target in as few as one hop, but the model still allows
    # multiple intermediate steps of attacker activity (reconnaissance,
    # privilege escalation) before the final hop, so detection has a
    # genuine chance to land before the target is reached.
    hops_to_target = ZONES.index(TARGET_ZONE)  # = 1
    attacker_steps_needed = hops_to_target + random.randint(1, 6)  # recon + the hop itself

    while steps < attacker_steps_needed:
        steps += 1
        if steps >= passive_detection_step:
            contained = True
            detection_step = steps
            break

    if detection_step is None:
        # Attacker completed their steps without being passively caught
        contained = False
        detection_step = passive_detection_step  # still logged eventually, after the fact

    # Response time in the perimeter model: once detection finally
    # happens, response still requires manual investigation before
    # access is revoked -- no automated PEP to act immediately.
    response_time = max(1, int(random.gammavariate(2, 4)))

    return {
        "detection_time": detection_step,
        "contained": contained,
        "response_time": response_time,
        "reached_target": not contained,
    }


def simulate_zero_trust_trial():
    """
    Zero Trust model: every request hits a PDP that scores identity
    confidence, device posture, and behavioural consistency. An
    attacker using stolen credentials typically has high identity
    confidence (the password/MFA token is technically valid) but lower
    device posture (unfamiliar device) and lower behavioural
    consistency (access patterns differ from the legitimate user's
    baseline) -- consistent with Section 3.3's Identity, Devices, and
    Networks pillar design.

    Each zone transition requires passing a PEP, which re-evaluates
    the PDP's current risk score. A sufficiently high risk score
    triggers immediate flagging (fast detection) and access denial
    (containment) at that PEP, rather than waiting for passive review.
    """
    # Risk signal quality varies per trial: a skilled attacker with
    # well-mimicked behaviour scores closer to a legitimate user.
    # These are drawn per trial to reflect that attacker sophistication
    # is not uniform -- consistent with treating this as a stochastic
    # scenario rather than one fixed walkthrough.
    identity_confidence = random.uniform(0.75, 0.98)   # stolen creds often pass MFA
    device_posture = random.uniform(0.10, 0.55)        # unfamiliar device, weak posture
    behavioural_consistency = random.uniform(0.05, 0.45)  # hardest signal to fake

    # Composite risk score (0 = no risk, 1 = max risk), weighted
    # per Section 3.3: identity alone is the weakest signal on its own
    # (84% Nigerian adoption baseline -- already commonly trusted),
    # so the architecture leans on device and behavioural signals,
    # the two pillars Section 2.2 found least mature in practice,
    # specifically because those are the signals that catch a stolen
    # credential being used by someone who is not its owner.
    risk_score = (
        (1 - identity_confidence) * 0.2
        + (1 - device_posture) * 0.35
        + (1 - behavioural_consistency) * 0.45
    )

    RISK_THRESHOLD = 0.55  # PDP denies / flags at or above this score

    steps = 0
    zone_index = 0
    contained = False
    detection_step = None

    # Step 1: credential access attempt evaluated at the first PEP
    steps += 1
    if risk_score >= RISK_THRESHOLD:
        # Flagged immediately at first PEP -- fast detection
        contained = True
        detection_step = steps
    else:
        # Passed initial check (a well-disguised attacker can still
        # get through occasionally); proceed to lateral movement
        # attempt, where each zone's PEP re-evaluates risk
        while zone_index < len(ZONES) - 1:
            steps += 1
            zone_index += 1

            # Each additional zone transition is itself a behavioural
            # anomaly (legitimate users rarely traverse zones this
            # way), so risk score escalates slightly per hop -- this
            # reflects continuous re-evaluation, not one-time trust.
            risk_score += random.uniform(0.05, 0.15)

            if risk_score >= RISK_THRESHOLD:
                contained = True
                detection_step = steps
                break
            if zone_index == ZONES.index(TARGET_ZONE):
                contained = False
                detection_step = None
                break

    reached_target = not contained
    if detection_step is None and not contained:
        # Reached target zone without triggering containment in this trial
        detection_step = steps + max(1, int(random.gammavariate(2, 3)))  # eventual passive catch

    # Response time in the Zero Trust model: PEP can revoke access
    # tokens automatically once the PDP flags a session, so response
    # is fast and largely automated (Section 3.3, Automation and
    # Orchestration cross-cutting capability) when containment occurs
    # at a PEP. If containment failed (attacker reached target),
    # response still requires manual investigation, same as perimeter.
    if contained:
        response_time = max(1, int(random.gammavariate(1.5, 1.2)))  # fast, automated
    else:
        response_time = max(1, int(random.gammavariate(2, 4)))  # manual, same as perimeter

    return {
        "detection_time": detection_step,
        "contained": contained,
        "response_time": response_time,
        "reached_target": reached_target,
    }


def run_trials(fn, n=N_TRIALS):
    results = [fn() for _ in range(n)]
    return results


def summarize(results, label):
    detection_times = [r["detection_time"] for r in results]
    response_times = [r["response_time"] for r in results]
    contained_count = sum(1 for r in results if r["contained"])
    reached_target_count = sum(1 for r in results if r["reached_target"])
    n = len(results)

    summary = {
        "label": label,
        "n_trials": n,
        "mean_detection_time_steps": round(statistics.mean(detection_times), 2),
        "median_detection_time_steps": statistics.median(detection_times),
        "stdev_detection_time_steps": round(statistics.stdev(detection_times), 2),
        "mean_response_time_steps": round(statistics.mean(response_times), 2),
        "median_response_time_steps": statistics.median(response_times),
        "containment_rate_pct": round(100 * contained_count / n, 1),
        "breach_reach_rate_pct": round(100 * reached_target_count / n, 1),
    }
    return summary


if __name__ == "__main__":
    perimeter_results = run_trials(simulate_perimeter_trial)
    zt_results = run_trials(simulate_zero_trust_trial)

    perimeter_summary = summarize(perimeter_results, "Perimeter (baseline)")
    zt_summary = summarize(zt_results, "Zero Trust (proposed)")

    output = {
        "n_trials_per_architecture": N_TRIALS,
        "perimeter": perimeter_summary,
        "zero_trust": zt_summary,
        "improvement": {
            "detection_time_reduction_pct": round(
                100 * (1 - zt_summary["mean_detection_time_steps"] / perimeter_summary["mean_detection_time_steps"]), 1
            ),
            "response_time_reduction_pct": round(
                100 * (1 - zt_summary["mean_response_time_steps"] / perimeter_summary["mean_response_time_steps"]), 1
            ),
            "containment_rate_improvement_pct_points": round(
                zt_summary["containment_rate_pct"] - perimeter_summary["containment_rate_pct"], 1
            ),
            "breach_reach_reduction_pct_points": round(
                perimeter_summary["breach_reach_rate_pct"] - zt_summary["breach_reach_rate_pct"], 1
            ),
        },
    }

    print(json.dumps(output, indent=2))

    with open("simulation_results.json", "w") as f:
        json.dump(output, f, indent=2)

    # Save raw per-trial data too, for any follow-on statistical testing
    with open("perimeter_raw.json", "w") as f:
        json.dump(perimeter_results, f)
    with open("zero_trust_raw.json", "w") as f:
        json.dump(zt_results, f)
