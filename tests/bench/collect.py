#!/usr/bin/env python3
"""Merge benchprobe CSVs from tests/bench/results/ into BENCH.md.

Takes the median of medians across runs per (group, path_class, arm) and
renders a markdown table with injected/stock medians and the delta.
"""

import csv
import statistics
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
RESULTS = ROOT / "tests/bench/results"
BENCH = ROOT / "tests/bench/BENCH.md"

def load() -> dict:
    rows = {}
    for path in sorted(RESULTS.glob("*.csv")):
        arm = "injected" if "injected" in path.name else "stock"
        with path.open() as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("arm=") or line.startswith("group,"):
                    continue
                parts = line.split(",")
                if len(parts) != 8 or parts[1] == "SKIP":
                    continue
                group, pclass, _, iters, median, p95, lo, hi = parts
                key = (group, pclass)
                rows.setdefault(key, {"injected": [], "stock": []})[arm].append(int(median))
    return rows

def median(values: list) -> int | None:
    return int(statistics.median(values)) if values else None

def main() -> int:
    rows = load()
    if not rows:
        print("no results; run tests/bench/run-a.sh first", file=sys.stderr)
        return 1

    lines = [
        "## Arm A — per-call hook microbench (median of medians, ns)",
        "",
        "| group | path class | injected | stock | delta |",
        "|---|---|---:|---:|---:|",
    ]
    for (group, pclass), arms in sorted(rows.items()):
        inj, stk = median(arms["injected"]), median(arms["stock"])
        if inj is None or stk is None:
            continue
        delta = inj - stk
        lines.append(f"| {group} | {pclass} | {inj} | {stk} | {delta:+d} |")

    text = BENCH.read_text() if BENCH.exists() else ""
    head = text.split("\n## Arm A", 1)[0].rstrip()
    tails = [text.find(marker) for marker in ("\n## Arm B", "\n## Arm C")]
    tails = [index for index in tails if index >= 0]
    tail = text[min(tails):].lstrip() if tails else ""
    output = head + "\n\n" + "\n".join(lines) + "\n"
    if tail:
        output += "\n" + tail
    BENCH.write_text(output)
    print(f"wrote {BENCH}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
