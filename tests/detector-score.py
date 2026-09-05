#!/usr/bin/env python3
"""Tally harness detector reports into a detected score.

Usage: python3 tests/detector-score.py <reports-dir>

<reports-dir> holds one <id>.json per detector (as pulled by
`stealth-device.sh run-all` into its reports/ directory). For each of the
RUN_ALL_REPORT_IDS detectors prints the outcome and, when jailbroken, the
failed check ids. Ends with the detected score: N/13 detectors reporting
jailbroken under Shadow injection (lower is better for Shadow).
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from stealth_device import RUN_ALL_REPORT_IDS


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <reports-dir>", file=sys.stderr)
        return 2
    reports = pathlib.Path(sys.argv[1])
    clean, detected, inconclusive = 0, 0, 0
    for identifier in RUN_ALL_REPORT_IDS:
        path = reports / f"{identifier}.json"
        try:
            value = json.loads(path.read_text())
        except (OSError, ValueError):
            print(f"{identifier:<22} INCONCLUSIVE  missing or unreadable report")
            inconclusive += 1
            continue
        sdk = value.get("sdk") if isinstance(value.get("sdk"), dict) else {}
        version = sdk.get("version", "?") if isinstance(sdk, dict) else "?"
        outcome = value.get("outcome")
        if outcome == "clean":
            print(f"{identifier:<22} clean       {version}")
            clean += 1
        elif outcome == "jailbroken":
            failed = [
                check.get("id", "?")
                for round_value in (value.get("rounds") or [])
                if isinstance(round_value, dict)
                for check in (round_value.get("checks") or [])
                if isinstance(check, dict) and check.get("passed") is False
            ]
            print(f"{identifier:<22} JAILBROKEN  {version}  failed: {', '.join(failed) or '?'}")
            detected += 1
        else:
            print(f"{identifier:<22} INCONCLUSIVE  outcome={outcome!r}")
            inconclusive += 1
    total = len(RUN_ALL_REPORT_IDS)
    print(f"detected score: {detected}/{total} jailbroken, "
          f"{clean}/{total} clean, {inconclusive}/{total} inconclusive")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
