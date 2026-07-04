"""Temporal analytics over ledger transfers.

Time-domain signals that complement the structural typologies:

  burst_velocity        sudden spikes in transfer rate / value (activity bursts)
  dormancy_activation   long-dormant accounts that suddenly reactivate
  periodicity           regular, machine-like cadence (fixed-interval automation)

Each returns ``Finding`` objects with transparent features. Timestamps are
parsed defensively; entities with too little history degrade gracefully to no
finding rather than a false positive.
"""

from __future__ import annotations

from collections import defaultdict

from .confidence import clamp
from .findings import Finding
from .ledger import epoch, mean, stdev


def _entity_events(transfers) -> dict:
    """entity -> sorted list of (epoch_seconds, amount) for all transfers it is
    a party to (as src or dst)."""
    ev = defaultdict(list)
    for t in transfers:
        ep = epoch(t.get("timestamp"))
        amt = float(t.get("amount", 0))
        if t.get("src") is not None:
            ev[t["src"]].append((ep, amt))
        if t.get("dst") is not None:
            ev[t["dst"]].append((ep, amt))
    for e in ev:
        ev[e].sort()
    return ev


def detect_burst_velocity(transfers, window_hours=24.0, min_events=5,
                          spike_factor=3.0) -> list:
    """Flag entities whose transfer rate within a rolling window sharply exceeds
    their own baseline rate (a velocity spike)."""
    ev = _entity_events(transfers)
    findings = []
    w = window_hours * 3600.0
    for ent, events in ev.items():
        if len(events) < min_events:
            continue
        times = [e[0] for e in events if e[0] > 0]
        if len(times) < min_events:
            continue
        span = times[-1] - times[0]
        if span <= 0:
            continue
        baseline_rate = len(times) / (span / w)  # events per window on average
        # Densest window (max events in any window_hours span).
        best = 0
        i = 0
        for j in range(len(times)):
            while times[j] - times[i] > w:
                i += 1
            best = max(best, j - i + 1)
        if baseline_rate <= 0:
            continue
        ratio = best / baseline_rate
        # A genuine burst must itself be a cluster: the peak window has to hold
        # at least min_events. This rejects sparse histories whose "baseline" is
        # tiny (a single event is never a burst).
        if best < min_events or ratio < spike_factor:
            continue
        score = clamp(0.4 + 0.12 * min(ratio - spike_factor, 5.0))
        findings.append(Finding(
            typology="burst_velocity",
            entities=[ent],
            score=score,
            features={"peak_events_in_window": best,
                      "baseline_events_per_window": round(baseline_rate, 3),
                      "spike_ratio": round(ratio, 2),
                      "window_hours": window_hours},
            evidence=[f"{best} transfers in a {window_hours:.0f}h window vs "
                      f"baseline {baseline_rate:.2f} ({ratio:.1f}x)"],
            rationale="transfer velocity spikes far above the entity's baseline",
        ))
    return findings


def detect_dormancy_activation(transfers, dormancy_days=90.0, min_prior=2,
                               burst_after=3) -> list:
    """Flag accounts that were dormant for a long gap and then reactivated with a
    burst of activity — a common indicator of a resold/reactivated mule or a
    sleeper account."""
    ev = _entity_events(transfers)
    findings = []
    gap_s = dormancy_days * 86400.0
    for ent, events in ev.items():
        times = [e[0] for e in events if e[0] > 0]
        if len(times) < min_prior + burst_after:
            continue
        for i in range(1, len(times)):
            gap = times[i] - times[i - 1]
            if gap < gap_s:
                continue
            prior = i
            after = len(times) - i
            if prior < min_prior or after < burst_after:
                continue
            gap_days = gap / 86400.0
            score = clamp(0.45 + 0.1 * min(gap_days / dormancy_days, 3.0)
                          + 0.03 * (after - burst_after))
            findings.append(Finding(
                typology="dormancy_activation",
                entities=[ent],
                score=score,
                features={"dormant_days": round(gap_days, 1),
                          "prior_events": prior, "post_events": after},
                evidence=[f"dormant {gap_days:.0f} days then reactivated with "
                          f"{after} transfers"],
                rationale="long-dormant account reactivates with a burst of activity",
            ))
            break  # report the first (earliest) dormancy break per entity
    return findings


def detect_periodicity(transfers, min_events=6, cv_threshold=0.15) -> list:
    """Flag entities whose inter-transfer intervals are highly regular (low
    coefficient of variation), suggesting automated/scheduled movement rather
    than organic human activity."""
    ev = _entity_events(transfers)
    findings = []
    for ent, events in ev.items():
        times = sorted(set(e[0] for e in events if e[0] > 0))
        if len(times) < min_events:
            continue
        gaps = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        gaps = [g for g in gaps if g > 0]
        if len(gaps) < min_events - 1:
            continue
        m = mean(gaps)
        if m <= 0:
            continue
        cv = stdev(gaps) / m
        if cv > cv_threshold:
            continue
        period_h = m / 3600.0
        score = clamp(0.4 + 0.4 * (1 - cv / cv_threshold))
        findings.append(Finding(
            typology="periodicity",
            entities=[ent],
            score=score,
            features={"events": len(times), "mean_interval_hours": round(period_h, 2),
                      "interval_cv": round(cv, 4)},
            evidence=[f"{len(times)} transfers at a near-fixed ~{period_h:.1f}h "
                      f"cadence (CV={cv:.2f})"],
            rationale="highly regular transfer cadence consistent with automation",
        ))
    return findings


DETECTORS = {
    "burst_velocity": detect_burst_velocity,
    "dormancy_activation": detect_dormancy_activation,
    "periodicity": detect_periodicity,
}


def run_all(transfers, enabled=None) -> list:
    findings = []
    for name, fn in DETECTORS.items():
        if enabled and name not in enabled:
            continue
        findings.extend(fn(transfers))
    return findings
