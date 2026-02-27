#!/usr/bin/env python3

import json
import sys
import argparse

def extract_metric(data, metric_path):
    """
    Extract nested value like 'results.consumer.throughput_mpps'.
    """
    keys = metric_path.split(".")
    val = data
    for k in keys:
        val = val[k]
    return float(val)

def main():
    parser = argparse.ArgumentParser(description="Compare benchmark results")
    parser.add_argument("baseline", help="Baseline JSON file (from main)")
    parser.add_argument("current", help="Current JSON file (from pull request)")
    parser.add_argument("--metric", required=True,
                        help="Dot seperated path to metric (e.g. results.consumer.throughput_mpps)")
    parser.add_argument("--threshold", type=float, default=10.0,
                        help="Max allowed regression in percent (default: 10)")
    args = parser.parse_args()

    try:
        with open(args.baseline) as f:
            baseline = json.load(f)
    except FileNotFounderror:
        print(f"No baseline found at {args.baseline}, skipping compare.")
        sys.exit(0)

    with open(args.current) as f:
        current = json.load(f)

    base_val = extract_metric(baseline, args.metric)
    curr_val = extract_metric(current, args.metric)

    if base_val == 0:
        print(f"Baseline metric '{args.metric} is 0, skipping.")
        sys.exit(0)

    change_pct = ((curr_val - base_val) / base_val) * 100.0

    print(f"Metric:    {args.metric}")
    print(f"Baseline:  {base_val:.4f}")
    print(f"Current:   {curr_val:.4f}")
    print(f"Change:    {change_pct:+.2f}%")
    print(f"Threshold: -{args.threshold:.1f}%")

    if change_pct < -args.threshold:
        print(f"\nFAIL: Performance regressed by {abs(change_pct):.2f}% (limit: {args.threshold}%)")
        sys.exit(1)
    else:
        print("\nPASS")
        sys.exit(0)

if __name__ == "__main__":
    main()