#!/usr/bin/env python3
"""MSG-1791: Shadow evaluation dataset + launch-gate report.

Collects shadow-mode scan results and produces a launch-gate report
showing whether we're ready to move from shadow → quarantine mode.

Usage:
    python3 scripts/shadow_eval.py --db-url <postgres_url> --kumo-receptions <N> --phase-start <ISO> --phase-end <ISO>
    python3 scripts/shadow_eval.py --json-file <scan_decisions.json> --kumo-receptions <N>
    python3 scripts/shadow_eval.py --help

Output: JSON report to stdout with launch-gate assessment.

Scope: This script evaluates OPERATIONAL launch gates only (canary success,
scan coverage, latency, sample size, observation period). Detection-quality
metrics (precision, recall, FPR from reviewed appeals) are NOT computed here —
they require Phase 1 reviewed outcomes. This script CANNOT authorize quarantine
activation alone; a separate detection-quality gate is required.
"""

import argparse
import json
import math
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

# Launch gates (from proposal §10.3 Phase 0)
GATES = {
    "canary_success": {
        "description": "All clean/spam/phishing canaries passing (fresh run)",
        "threshold": "100% pass, all 3 types, within last 15 min",
    },
    "scan_coverage": {
        "description": "Successful shadow scans / Kumo receptions",
        "threshold": ">99% (strict)",
    },
    "scan_latency_p99": {
        "description": "p99 scan latency (100% completeness required)",
        "threshold": "<200ms (strict)",
    },
    "min_sample_size": {
        "description": "Unique injection attempts",
        "threshold": ">=10000",
    },
    "min_observation_days": {
        "description": "Days of shadow-mode observation",
        "threshold": ">=7 days (inclusive)",
    },
}

REQUIRED_CANARIES = {"clean", "spam", "phishing"}
CANARY_MAX_AGE_SECONDS = 900  # 15 minutes


def _parse_dt(val: Any) -> Optional[datetime]:
    """Parse a datetime from string or pass through. Returns None on failure."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            # Convert naive datetimes to UTC-aware
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None
    return None


def _validate_phase_bounds(
    phase_start: Optional[str],
    phase_end: Optional[str],
) -> Tuple[Optional[datetime], Optional[datetime], Optional[str]]:
    """Validate phase bounds. Returns (start_dt, end_dt, error_message)."""
    if not phase_start and not phase_end:
        return None, None, None

    # If either is provided, both must be provided
    if not phase_start or not phase_end:
        return None, None, "Both --phase-start and --phase-end must be provided together"

    ps_dt = _parse_dt(phase_start)
    pe_dt = _parse_dt(phase_end)

    if ps_dt is None:
        return None, None, f"Invalid --phase-start: {phase_start!r}"
    if pe_dt is None:
        return None, None, f"Invalid --phase-end: {phase_end!r}"

    if ps_dt > pe_dt:
        return None, None, "phase_start must be <= phase_end"

    now = datetime.now(timezone.utc)
    if pe_dt > now:
        return None, None, "phase_end must not be in the future"

    return ps_dt, pe_dt, None


def load_scan_decisions_from_db(
    db_url: str,
    phase_start: Optional[str] = None,
    phase_end: Optional[str] = None,
    days: int = 7,
) -> List[Dict[str, Any]]:
    """Load shadow scan decisions from PostgreSQL, bounded by phase window."""
    try:
        import psycopg2
    except ImportError:
        print("Error: psycopg2 not installed. Use --json-file instead.", file=sys.stderr)
        sys.exit(1)

    conn = psycopg2.connect(db_url)
    cursor = conn.cursor()

    # Build WHERE clause with phase bounds if provided
    conditions = ["scan_mode = 'shadow'"]
    params: List[Any] = []

    ps_dt = _parse_dt(phase_start)
    pe_dt = _parse_dt(phase_end)
    if ps_dt:
        conditions.append("inserted_at >= %s")
        params.append(ps_dt)
    if pe_dt:
        conditions.append("inserted_at <= %s")
        params.append(pe_dt)
    if not ps_dt and not pe_dt:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        conditions.append("inserted_at >= %s")
        params.append(since)

    where_clause = " AND ".join(conditions)

    cursor.execute(
        f"""
        SELECT
            message_id,
            recipient_id,
            injection_attempt_id,
            evaluation_id,
            score,
            rspamd_action,
            policy_action,
            scan_time_ms,
            scan_status,
            scan_mode,
            deterministic,
            fallback,
            inserted_at
        FROM scan_decisions
        WHERE {where_clause}
        ORDER BY inserted_at DESC
        """,
        params,
    )

    columns = [desc[0] for desc in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return rows


def load_scan_decisions_from_json(path: str) -> List[Dict[str, Any]]:
    """Load scan decisions from a JSON file."""
    with open(path) as f:
        return json.load(f)


def calculate_percentile(values: List[float], percentile: float) -> float:
    """Calculate the p-th percentile of a sorted list."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    idx = int(len(sorted_vals) * percentile / 100.0)
    idx = min(idx, len(sorted_vals) - 1)
    return float(sorted_vals[idx])


def _is_valid_latency(val: Any) -> bool:
    """Check if a latency value is valid: a real number (not bool), finite, non-negative."""
    if val is None:
        return False
    if isinstance(val, bool):  # bool is subclass of int — reject explicitly
        return False
    if not isinstance(val, (int, float)):
        return False
    if not math.isfinite(val):
        return False
    return val >= 0


def _filter_phase_window(
    decisions: List[Dict[str, Any]],
    phase_start: Optional[str],
    phase_end: Optional[str],
) -> List[Dict[str, Any]]:
    """Filter decisions to only those within the phase window."""
    ps_dt = _parse_dt(phase_start)
    pe_dt = _parse_dt(phase_end)
    if not ps_dt and not pe_dt:
        return decisions

    result = []
    for d in decisions:
        ts = _parse_dt(d.get("inserted_at") or d.get("created_at"))
        if ts is None:
            continue
        if ps_dt and ts < ps_dt:
            continue
        if pe_dt and ts > pe_dt:
            continue
        result.append(d)
    return result


def _deduplicate_by_attempt(decisions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate scan decisions by (message_id, recipient_id, injection_attempt_id).
    When multiple evaluations exist for the same attempt, prefer the one with
    scan_status='success' over 'error', then the latest by inserted_at."""
    by_key: Dict[Tuple, Dict[str, Any]] = {}
    for d in decisions:
        key = (
            d.get("message_id"),
            d.get("recipient_id"),
            d.get("injection_attempt_id"),
        )
        if key not in by_key:
            by_key[key] = d
            continue
        # Prefer success over error, then latest timestamp
        existing = by_key[key]
        existing_status = existing.get("scan_status")
        new_status = d.get("scan_status")
        if new_status == "success" and existing_status != "success":
            by_key[key] = d
        elif new_status == existing_status:
            existing_ts = _parse_dt(existing.get("inserted_at") or existing.get("created_at"))
            new_ts = _parse_dt(d.get("inserted_at") or d.get("created_at"))
            if new_ts and (not existing_ts or new_ts > existing_ts):
                by_key[key] = d
    return list(by_key.values())


def evaluate_gates(
    decisions: List[Dict[str, Any]],
    canary_results: Optional[Dict] = None,
    kumo_receptions: Optional[int] = None,
    phase_start: Optional[str] = None,
    phase_end: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate all launch gates against the collected data."""

    # Validate phase bounds if provided
    ps_dt, pe_dt, phase_error = _validate_phase_bounds(phase_start, phase_end)

    # Filter to shadow mode only
    shadow_decisions = [d for d in decisions if d.get("scan_mode") == "shadow"]

    # Apply phase window filtering
    if phase_start or phase_end:
        shadow_decisions = _filter_phase_window(shadow_decisions, phase_start, phase_end)

    # Deduplicate by injection attempt (one scan per attempt, not per evaluation)
    unique_decisions = _deduplicate_by_attempt(shadow_decisions)
    total_scans = len(unique_decisions)
    successful_scans = [d for d in unique_decisions if d.get("scan_status") == "success"]
    failed_scans = [d for d in unique_decisions if d.get("scan_status") == "error"]

    # Scan coverage: unique successful scans / Kumo receptions
    # Reject inconsistent counts (successful scans > kumo_receptions is impossible)
    if kumo_receptions is not None and kumo_receptions > 0:
        if len(successful_scans) > kumo_receptions:
            scan_coverage = None  # Impossible — inconsistent data
            coverage_error = f"Inconsistent: {len(successful_scans)} successful scans > {kumo_receptions} kumo_receptions"
        else:
            scan_coverage = len(successful_scans) / kumo_receptions
            coverage_error = None
    else:
        scan_coverage = None
        coverage_error = None

    # Scan latency p50/p99 — strict validation: no bools, must be finite
    valid_latencies = [
        d.get("scan_time_ms")
        for d in successful_scans
        if _is_valid_latency(d.get("scan_time_ms"))
    ]
    latency_completeness = (
        len(valid_latencies) / len(successful_scans) if successful_scans else 0.0
    )
    p50 = calculate_percentile(valid_latencies, 50)
    p99 = calculate_percentile(valid_latencies, 99)

    # Detection breakdown
    action_counts: Dict[str, int] = {}
    for d in unique_decisions:
        action = d.get("policy_action") or d.get("rspamd_action") or "unknown"
        action_counts[action] = action_counts.get(action, 0) + 1

    # Observation period: use validated phase window if provided, else from data
    if phase_error:
        observation_days = 0
    elif ps_dt and pe_dt:
        observation_days = (pe_dt - ps_dt).days + 1  # inclusive of both days
    elif shadow_decisions:
        timestamps = [
            _parse_dt(d.get("inserted_at") or d.get("created_at"))
            for d in unique_decisions
        ]
        timestamps = [t for t in timestamps if t is not None]
        if timestamps:
            timestamps.sort()
            observation_days = (timestamps[-1] - timestamps[0]).days + 1
        else:
            observation_days = 0
    else:
        observation_days = 0

    # Canary validation: require all three types, strict boolean True, fresh run
    canary_pass = False
    canary_detail: Dict[str, Any] = {}
    if canary_results:
        # Check for freshness metadata
        canary_timestamp = canary_results.get("timestamp") or canary_results.get("generated_at")
        canary_ts = _parse_dt(canary_timestamp)

        is_fresh = True
        if canary_ts is None:
            canary_detail["freshness"] = "missing timestamp — cannot verify freshness"
            is_fresh = False
        else:
            age = (datetime.now(timezone.utc) - canary_ts).total_seconds()
            if age < -60:  # Allow 60s clock skew, reject future beyond that
                canary_detail["freshness"] = f"future timestamp ({age:.0f}s — clock skew?)"
                is_fresh = False
            elif age > CANARY_MAX_AGE_SECONDS:
                canary_detail["freshness"] = f"stale ({age:.0f}s old, max {CANARY_MAX_AGE_SECONDS}s)"
                is_fresh = False
            else:
                canary_detail["freshness"] = f"fresh ({age:.0f}s old)"

        canary_keys = set(canary_results.keys()) - {"timestamp", "generated_at"}
        missing = REQUIRED_CANARIES - canary_keys
        for name in sorted(REQUIRED_CANARIES):
            val = canary_results.get(name)
            if val is None or name in missing:
                canary_detail[name] = "missing"
            elif not isinstance(val, bool):
                canary_detail[name] = f"invalid type ({type(val).__name__})"
            elif val:
                canary_detail[name] = "pass"
            else:
                canary_detail[name] = "fail"
        if missing:
            canary_detail["missing"] = sorted(missing)

        canary_pass = (
            is_fresh
            and missing == set()
            and all(
                isinstance(canary_results.get(name), bool) and canary_results.get(name)
                for name in REQUIRED_CANARIES
            )
        )
    else:
        canary_detail = {"note": "No canary results provided — manual check required"}

    # Evaluate each gate
    gate_results = {
        "canary_success": {
            "description": GATES["canary_success"]["description"],
            "threshold": GATES["canary_success"]["threshold"],
            "actual": canary_pass,
            "pass": canary_pass,
        },
        "scan_coverage": {
            "description": GATES["scan_coverage"]["description"],
            "threshold": GATES["scan_coverage"]["threshold"],
            "actual": (
                coverage_error or
                (f"{scan_coverage * 100:.2f}%" if scan_coverage is not None else "UNKNOWN — --kumo-receptions not provided")
            ),
            "pass": scan_coverage is not None and scan_coverage > 0.99,
        },
        "scan_latency_p99": {
            "description": GATES["scan_latency_p99"]["description"],
            "threshold": GATES["scan_latency_p99"]["threshold"],
            "actual": f"{p99:.1f}ms (completeness: {latency_completeness * 100:.1f}%)",
            "pass": (
                latency_completeness == 1.0
                and len(valid_latencies) > 0
                and p99 < 200
            ),
        },
        "min_sample_size": {
            "description": GATES["min_sample_size"]["description"],
            "threshold": GATES["min_sample_size"]["threshold"],
            "actual": str(total_scans),
            "pass": total_scans >= 10000,
        },
        "min_observation_days": {
            "description": GATES["min_observation_days"]["description"],
            "threshold": GATES["min_observation_days"]["threshold"],
            "actual": f"{observation_days} days" + (f" (ERROR: {phase_error})" if phase_error else ""),
            "pass": observation_days >= 7 and not phase_error,
        },
    }

    all_pass = all(g["pass"] for g in gate_results.values())

    # Build summary with null-safe coverage
    summary: Dict[str, Any] = {
        "total_scans": total_scans,
        "successful_scans": len(successful_scans),
        "failed_scans": len(failed_scans),
        "scan_coverage": (
            f"{scan_coverage * 100:.2f}%" if scan_coverage is not None else "UNKNOWN"
        ),
        "scan_latency_p50_ms": round(p50, 1),
        "scan_latency_p99_ms": round(p99, 1),
        "latency_completeness": f"{latency_completeness * 100:.1f}%",
        "action_breakdown": action_counts,
        "canary_results": canary_detail,
    }

    return {
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
        "evaluation_period_days": observation_days,
        "summary": summary,
        "launch_gates": gate_results,
        "operational_gates_passed": all_pass,
        "ready_for_next_phase": False,  # Always false — quarantine requires separate detection-quality gate
        "recommendation": (
            "All operational launch gates passed. "
            "Detection-quality gate (precision, recall, FPR from reviewed appeals) "
            "is STILL REQUIRED before quarantine activation. This report alone "
            "CANNOT authorize Phase 1."
            if all_pass
            else "Operational launch gates not yet met. Continue shadow-mode observation."
        ),
        "scope_note": (
            "This report evaluates OPERATIONAL launch gates only. Detection-quality "
            "metrics (precision, recall, FPR) require reviewed outcomes from a held-out "
            "corpus and appeals process. The 'ready_for_next_phase' field is always false "
            "because quarantine activation requires the full MSG-1791 detection-quality "
            "gate, not just operational gates. Use 'operational_gates_passed' to check "
            "the operational subset."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="MSG-1791: Shadow evaluation + launch-gate report"
    )
    parser.add_argument("--db-url", help="PostgreSQL connection URL for scan_decisions table")
    parser.add_argument("--json-file", help="Path to JSON file containing scan decisions")
    parser.add_argument("--canary-file", help="Path to JSON file containing canary results")
    parser.add_argument("--kumo-receptions", type=int, help="Total KumoMTA receptions (REQUIRED for coverage gate)")
    parser.add_argument("--phase-start", help="ISO timestamp for Phase 0 shadow start")
    parser.add_argument("--phase-end", help="ISO timestamp for Phase 0 shadow end")
    parser.add_argument("--days", type=int, default=7, help="Days to look back if no phase bounds (default: 7)")
    parser.add_argument("--output", help="Output file path (default: stdout)")
    args = parser.parse_args()

    if not args.db_url and not args.json_file:
        parser.error("Either --db-url or --json-file is required")

    # Load scan decisions
    if args.db_url:
        decisions = load_scan_decisions_from_db(args.db_url, args.phase_start, args.phase_end, args.days)
    else:
        decisions = load_scan_decisions_from_json(args.json_file)

    # Load canary results
    canary_results = None
    if args.canary_file:
        with open(args.canary_file) as f:
            canary_results = json.load(f)

    # Evaluate gates
    report = evaluate_gates(
        decisions,
        canary_results,
        kumo_receptions=args.kumo_receptions,
        phase_start=args.phase_start,
        phase_end=args.phase_end,
    )

    # Output
    output = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
