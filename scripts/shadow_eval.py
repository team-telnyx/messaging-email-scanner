#!/usr/bin/env python3
"""MSG-1791: Shadow evaluation dataset + launch-gate report.

Collects shadow-mode scan results and produces a launch-gate report
showing whether we're ready to move from shadow → quarantine mode.

Usage:
    python3 scripts/shadow_eval.py --db-url <postgres_url>
    python3 scripts/shadow_eval.py --json-file <scan_decisions.json>
    python3 scripts/shadow_eval.py --help

Output: JSON report to stdout with launch-gate assessment.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# Launch gates (from proposal §10.3 Phase 0)
GATES = {
    "canary_success": {
        "description": "All clean/spam/phishing canaries passing",
        "required": True,
        "threshold": 1.0,  # 100% pass rate
    },
    "scan_coverage": {
        "description": "Kumo receptions vs successful Rspamd scans",
        "required": True,
        "threshold": 0.99,  # >99%
    },
    "scan_latency_p99": {
        "description": "p99 scan latency",
        "required": True,
        "threshold_ms": 200,  # <200ms
    },
    "min_sample_size": {
        "description": "Minimum scan decisions for statistical significance",
        "required": True,
        "threshold": 10000,
    },
    "min_observation_days": {
        "description": "Minimum days of shadow-mode observation",
        "required": True,
        "threshold": 7,
    },
}


def load_scan_decisions_from_db(db_url: str, days: int = 7) -> List[Dict[str, Any]]:
    """Load scan decisions from PostgreSQL."""
    try:
        import psycopg2
    except ImportError:
        print("Error: psycopg2 not installed. Use --json-file instead.", file=sys.stderr)
        sys.exit(1)

    conn = psycopg2.connect(db_url)
    cursor = conn.cursor()
    since = datetime.now(timezone.utc) - timedelta(days=days)

    cursor.execute(
        """
        SELECT
            score,
            rspamd_action,
            policy_action,
            scan_time_ms,
            scan_status,
            scan_mode,
            deterministic,
            fallback,
            created_at
        FROM scan_decisions
        WHERE created_at >= %s
        ORDER BY created_at DESC
        """,
        (since,),
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
    return sorted_vals[idx]


def evaluate_gates(decisions: List[Dict[str, Any]], canary_results: Optional[Dict] = None) -> Dict[str, Any]:
    """Evaluate all launch gates against the collected data."""

    total_scans = len(decisions)
    successful_scans = [d for d in decisions if d.get("scan_status") == "success"]
    failed_scans = [d for d in decisions if d.get("scan_status") == "error"]

    # Scan coverage: successful scans / total scans
    scan_coverage = len(successful_scans) / total_scans if total_scans > 0 else 0.0

    # Scan latency p50/p99
    latencies = [d.get("scan_time_ms", 0) or 0 for d in successful_scans]
    p50 = calculate_percentile(latencies, 50)
    p99 = calculate_percentile(latencies, 99)

    # Detection breakdown
    action_counts: Dict[str, int] = {}
    for d in decisions:
        action = d.get("policy_action") or d.get("rspamd_action") or "unknown"
        action_counts[action] = action_counts.get(action, 0) + 1

    # Observation period
    if decisions:
        timestamps = [
            d.get("created_at") for d in decisions
            if d.get("created_at")
        ]
        if timestamps:
            timestamps.sort()
            first = timestamps[0]
            last = timestamps[-1]
            if isinstance(first, str):
                first = datetime.fromisoformat(first.replace("Z", "+00:00"))
            if isinstance(last, str):
                last = datetime.fromisoformat(last.replace("Z", "+00:00"))
            observation_days = (last - first).days
        else:
            observation_days = 0
    else:
        observation_days = 0

    # Canary results (expected from the canary CronJob)
    canary_pass = True
    canary_detail = {}
    if canary_results:
        for canary_name, passed in canary_results.items():
            canary_detail[canary_name] = "pass" if passed else "fail"
            if not passed:
                canary_pass = False
    else:
        canary_detail = {"note": "No canary results provided — manual check required"}
        canary_pass = False

    # Evaluate each gate
    gate_results = {
        "canary_success": {
            "description": GATES["canary_success"]["description"],
            "threshold": "100% pass",
            "actual": canary_pass,
            "pass": canary_pass,
        },
        "scan_coverage": {
            "description": GATES["scan_coverage"]["description"],
            "threshold": ">99%",
            "actual": f"{scan_coverage * 100:.2f}%",
            "pass": scan_coverage >= GATES["scan_coverage"]["threshold"],
        },
        "scan_latency_p99": {
            "description": GATES["scan_latency_p99"]["description"],
            "threshold": "<200ms",
            "actual": f"{p99:.1f}ms",
            "pass": p99 <= GATES["scan_latency_p99"]["threshold_ms"],
        },
        "min_sample_size": {
            "description": GATES["min_sample_size"]["description"],
            "threshold": f">={GATES['min_sample_size']['threshold']}",
            "actual": str(total_scans),
            "pass": total_scans >= GATES["min_sample_size"]["threshold"],
        },
        "min_observation_days": {
            "description": GATES["min_observation_days"]["description"],
            "threshold": f">={GATES['min_observation_days']['threshold']} days",
            "actual": f"{observation_days} days",
            "pass": observation_days >= GATES["min_observation_days"]["threshold"],
        },
    }

    all_pass = all(g["pass"] for g in gate_results.values())

    return {
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
        "evaluation_period_days": observation_days,
        "summary": {
            "total_scans": total_scans,
            "successful_scans": len(successful_scans),
            "failed_scans": len(failed_scans),
            "scan_coverage": f"{scan_coverage * 100:.2f}%",
            "scan_latency_p50_ms": round(p50, 1),
            "scan_latency_p99_ms": round(p99, 1),
            "action_breakdown": action_counts,
            "canary_results": canary_detail,
        },
        "launch_gates": gate_results,
        "ready_for_next_phase": all_pass,
        "recommendation": (
            "All launch gates passed. Ready to proceed to Phase 1 (quarantine)."
            if all_pass
            else "Launch gates not yet met. Continue shadow-mode observation."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="MSG-1791: Shadow evaluation + launch-gate report"
    )
    parser.add_argument(
        "--db-url",
        help="PostgreSQL connection URL for scan_decisions table",
    )
    parser.add_argument(
        "--json-file",
        help="Path to JSON file containing scan decisions",
    )
    parser.add_argument(
        "--canary-file",
        help="Path to JSON file containing canary results {name: bool}",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of days to look back (default: 7)",
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: stdout)",
    )
    args = parser.parse_args()

    if not args.db_url and not args.json_file:
        parser.error("Either --db-url or --json-file is required")

    # Load scan decisions
    if args.db_url:
        decisions = load_scan_decisions_from_db(args.db_url, args.days)
    else:
        decisions = load_scan_decisions_from_json(args.json_file)

    # Load canary results
    canary_results = None
    if args.canary_file:
        with open(args.canary_file) as f:
            canary_results = json.load(f)

    # Evaluate gates
    report = evaluate_gates(decisions, canary_results)

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
