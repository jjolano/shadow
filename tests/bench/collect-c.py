#!/usr/bin/env python3
"""Collect per-detector timing fields emitted by ShadowHarness."""

import csv
import json
import pathlib
import statistics
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
RESULTS = ROOT / "tests/bench/results"
BENCH = ROOT / "tests/bench/BENCH.md"
EXPECTED_IDS = {
    "batjailbreakguard", "jailmonkey", "roothider", "safetynet",
    "dttjailbreakdetection", "jailbreakdetector", "securitytoolkit",
    "devicesecuritykit", "iossecuritysuite", "freerasp",
}


def median(values):
    return int(statistics.median(values)) if values else None


def load():
    records = []
    for path in sorted(RESULTS.glob("detector-*.json")):
        parts = path.stem.split("-")
        if len(parts) < 4 or parts[1] not in {"injected", "uninjected"}:
            continue
        try:
            run = int(parts[2])
        except ValueError:
            continue
        try:
            report = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        timing = report.get("timing")
        if not isinstance(timing, dict):
            continue
        rounds = report.get("rounds")
        round_data = rounds[-1] if isinstance(rounds, list) and rounds else {}
        records.append({
            "mode": parts[1],
            "run": run,
            "id": "-".join(parts[3:]),
            "phase": round_data.get("phase", "unknown"),
            "elapsed_ns": int(timing.get("elapsed_ns", 0)),
            "first_elapsed_ns": int(timing.get("first_elapsed_ns", 0)),
            "framework_load_ns": int(timing.get("framework_load_ns", 0)),
            "run_index": int(timing.get("run_index", 0)),
            "check_count": int(round_data.get("check_count", 0)),
        })
    return records


def write_csv(records):
    destination = RESULTS / "detector-timing.csv"
    fields = ["mode", "run", "id", "phase", "elapsed_ns", "first_elapsed_ns",
              "framework_load_ns", "run_index", "check_count"]
    with destination.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)


def validate(records):
    errors = []
    all_runs = {r["run"] for r in records}
    expected_runs = set(range(1, max(all_runs) + 1)) if all_runs else set()
    for mode in ("injected", "uninjected"):
        mode_records = [r for r in records if r["mode"] == mode]
        runs = {r["run"] for r in mode_records}
        if not runs:
            errors.append(f"{mode}: no reports")
            continue
        for run in sorted(expected_runs - runs):
            errors.append(f"{mode}: missing run {run}")
        for run in sorted(runs):
            ids = {r["id"] for r in mode_records if r["run"] == run}
            missing = sorted(EXPECTED_IDS - ids)
            extra = sorted(ids - EXPECTED_IDS)
            if missing:
                errors.append(f"{mode} run {run}: missing {', '.join(missing)}")
            if extra:
                errors.append(f"{mode} run {run}: unexpected {', '.join(extra)}")
    return errors


def ms(value):
    return "-" if value is None else f"{value / 1_000_000:.3f}"


def write_markdown(records):
    grouped = {}
    for record in records:
        grouped.setdefault((record["id"], record["mode"]), []).append(record)

    lines = [
        "## Arm C - detector response timing (median of medians, ms)",
        "",
        "`first` is the first invocation in a process; `latest` is the latest "
        "report after the harness scene re-run. `framework load` is the cold "
        "SDK framework load measured by the harness.",
        "",
        "| detector | injected first | injected latest | uninjected first | uninjected latest | latest delta | framework load |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    ids = sorted({key[0] for key in grouped})
    for identifier in ids:
        modes = {mode: grouped.get((identifier, mode), []) for mode in ("injected", "uninjected")}
        latest = {mode: median([r["elapsed_ns"] for r in rows]) for mode, rows in modes.items()}
        first = {mode: median([r["first_elapsed_ns"] for r in rows]) for mode, rows in modes.items()}
        framework = median([r["framework_load_ns"] for rows in modes.values() for r in rows])
        delta = None if latest["injected"] is None or latest["uninjected"] is None else latest["injected"] - latest["uninjected"]
        lines.append(f"| {identifier} | {ms(first['injected'])} | {ms(latest['injected'])} | "
                     f"{ms(first['uninjected'])} | {ms(latest['uninjected'])} | "
                     f"{ms(delta)} | {ms(framework)} |")

    text = BENCH.read_text() if BENCH.exists() else ""
    head = text.split("\n## Arm C", 1)[0].rstrip()
    BENCH.write_text(head + "\n\n" + "\n".join(lines) + "\n")


def main():
    records = load()
    if not records:
        print("no timed detector reports; run tests/bench/run-c.sh first", file=sys.stderr)
        return 1
    errors = validate(records)
    if errors:
        print("incomplete detector benchmark:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    write_csv(records)
    write_markdown(records)
    print(f"wrote {RESULTS / 'detector-timing.csv'} and {BENCH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
