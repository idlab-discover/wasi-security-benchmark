#!/usr/bin/env python3
"""Collect criterion estimates (target/criterion/**/new/*.json) into one JSON file."""
import json, sys, pathlib

root, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
rows = []
for bj in sorted(root.glob("**/new/benchmark.json")):
    b = json.loads(bj.read_text())
    e = json.loads((bj.parent / "estimates.json").read_text())
    rows.append({
        "group": b["group_id"],
        "function": b.get("function_id"),
        "value": b.get("value_str"),
        "median_ns": e["median"]["point_estimate"],
        "median_lo": e["median"]["confidence_interval"]["lower_bound"],
        "median_hi": e["median"]["confidence_interval"]["upper_bound"],
        "mean_ns": e["mean"]["point_estimate"],
    })
out.write_text(json.dumps(rows, indent=1))
print(f"collected {len(rows)} criterion benchmarks -> {out}")
