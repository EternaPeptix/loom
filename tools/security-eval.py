#!/usr/bin/env python3
"""Descriptive paired security-workflow evaluation; standard library, no model/target calls.

Each JSONL row has task_id(str), repeat(int), workflow(str), settings_hash(str), elapsed_s(number),
censored(bool), verified_finish(bool), oracle_accepted(bool), controls_passed(bool),
usage_complete(bool), prompt_tokens(int|null), completion_tokens(int|null), cached_tokens(int|null).
Optional known_prompt_tokens/known_completion_tokens preserve reported lower bounds on interrupted
streams. settings_hash identifies shared target/model/budget/oracle settings, excluding the intended
workflow intervention. Raw logs/checker receipts/hashes belong beside the export; this analyzer does
not authenticate them or replace a checker. Missing usage is unknown, never zero-filled as exact cost.

All episodes remain in quality denominators. Successful latency ratios require both verified finishes
and no censoring; token ratios require complete usage. Pairing errors are reported, not silently
discarded. Exit 2 for malformed rows; output includes only descriptive, not significance, statistics.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import statistics
import sys


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def validate(row):
    for key in ("task_id", "workflow", "settings_hash"):
        if not isinstance(row.get(key), str) or not row[key].strip():
            raise ValueError(f"{key} must be a nonblank string")
    if not isinstance(row.get("repeat"), int) or isinstance(row["repeat"], bool) or row["repeat"] < 0:
        raise ValueError("repeat must be a nonnegative integer")
    if not number(row.get("elapsed_s")):
        raise ValueError("elapsed_s must be finite and nonnegative")
    for key in ("censored", "verified_finish", "oracle_accepted", "controls_passed", "usage_complete"):
        if not isinstance(row.get(key), bool):
            raise ValueError(f"{key} must be an explicit boolean")
    for key in ("prompt_tokens", "completion_tokens", "cached_tokens", "known_prompt_tokens", "known_completion_tokens"):
        value = row.get(key)
        if value is not None and (not number(value) or not isinstance(value, int)):
            raise ValueError(f"{key} must be a nonnegative integer or null")
    if row["usage_complete"] and any(row.get(k) is None for k in ("prompt_tokens", "completion_tokens")):
        raise ValueError("complete usage needs prompt_tokens and completion_tokens")
    if row.get("cached_tokens") is not None and row.get("prompt_tokens") is not None and row["cached_tokens"] > row["prompt_tokens"]:
        raise ValueError("cached_tokens cannot exceed prompt_tokens")
    return row


def succeeded(row):
    return row["verified_finish"] and row["oracle_accepted"] and row["controls_passed"] and not row["censored"]


def stats(values):
    values = list(values)
    return {"n": len(values), "mean": statistics.mean(values) if values else None,
            "median": statistics.median(values) if values else None}


def analyze(rows, baseline="core", candidate="ctf"):
    if baseline == candidate:
        raise ValueError("baseline and candidate must differ")
    rows = [validate(dict(row)) for row in rows]
    groups = defaultdict(list)
    pairs = defaultdict(dict)
    errors = []
    for row in rows:
        groups[row["workflow"]].append(row)
        if row["workflow"] not in (baseline, candidate):
            continue
        key = (row["task_id"], row["repeat"])
        if row["workflow"] in pairs[key]:
            raise ValueError(f"duplicate episode for {key}/{row['workflow']}")
        pairs[key][row["workflow"]] = row
    summaries = {}
    for name, episodes in sorted(groups.items()):
        def lower(key):
            values = [r.get("known_" + key) if r.get("known_" + key) is not None else r.get(key) for r in episodes]
            return {"reported": sum(v for v in values if v is not None), "episodes_with_report": sum(v is not None for v in values)}
        summaries[name] = {
            "episodes": len(episodes), "verified_successes": sum(map(succeeded, episodes)),
            "censored": sum(r["censored"] for r in episodes),
            "complete_usage_episodes": sum(r["usage_complete"] for r in episodes),
            "verified_success_latency_s": stats(r["elapsed_s"] for r in episodes if succeeded(r)),
            "known_prompt_lower_bound": lower("prompt_tokens"),
            "known_completion_lower_bound": lower("completion_tokens"),
            "usage_totals_exact": all(r["usage_complete"] for r in episodes),
        }
    comparisons = []
    for key, arms in sorted(pairs.items()):
        if set(arms) != {baseline, candidate}:
            errors.append({"task_id": key[0], "repeat": key[1], "error": "missing arm"})
            continue
        a, b = arms[baseline], arms[candidate]
        if a["settings_hash"] != b["settings_hash"]:
            errors.append({"task_id": key[0], "repeat": key[1], "error": "shared settings differ"})
            continue
        item = {"task_id": key[0], "repeat": key[1], "verified_success_delta": int(succeeded(b)) - int(succeeded(a)),
                "latency_ratio": None, "total_token_ratio": None, "uncached_token_ratio": None}
        if succeeded(a) and succeeded(b) and a["elapsed_s"] > 0:
            item["latency_ratio"] = b["elapsed_s"] / a["elapsed_s"]
        if a["usage_complete"] and b["usage_complete"]:
            at = a["prompt_tokens"] + a["completion_tokens"]
            bt = b["prompt_tokens"] + b["completion_tokens"]
            if at > 0:
                item["total_token_ratio"] = bt / at
            if a.get("cached_tokens") is not None and b.get("cached_tokens") is not None:
                au = a["prompt_tokens"] - a["cached_tokens"] + a["completion_tokens"]
                bu = b["prompt_tokens"] - b["cached_tokens"] + b["completion_tokens"]
                if au > 0:
                    item["uncached_token_ratio"] = bu / au
        comparisons.append(item)
    return {"baseline": baseline, "candidate": candidate, "workflows": summaries,
            "pairs": comparisons, "pairing_errors": errors,
            "paired_ratios": {key: stats(p[key] for p in comparisons if p[key] is not None)
                              for key in ("latency_ratio", "total_token_ratio", "uncached_token_ratio")},
            "interpretation": "Descriptive only. Censored latency and incomplete usage are excluded from ratios, retained in episode counts. Checker inputs are not authenticated by this analyzer."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--baseline", default="core")
    parser.add_argument("--candidate", default="ctf")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        rows = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
        output = json.dumps(analyze(rows, args.baseline, args.candidate), indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(output)
        else:
            sys.stdout.write(output)
    except (ValueError, OSError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
