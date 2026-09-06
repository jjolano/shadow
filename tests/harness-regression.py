#!/usr/bin/env python3
"""On-device harness regression check (agent-runnable, not a CI gate).

Deploys the embedded ShadowHarness, runs all 13 detectors under aggressive
mode via a REAL SpringBoard launch (the foreground marker trigger, so
freerasp.debug does not fire on the headless environment), and asserts every
detector's outcome + its notChecked check-ids against tests/harness-expected.json.

Why not CI: needs a specific jailbroken device, mutates device prefs, ~4 min,
and one row (freerasp.debug) is environment-dependent by nature. This turns the
manual verify dance into one reproducible command with a checked-in baseline,
so a NEW notChecked id (a real fail quietly downgraded) or a flipped row trips
it — while known artifacts stay green.

  tests/harness-regression.py --device mobile@10.0.1.160 [--deb build/...harness.deb]
  tests/harness-regression.py --device mobile@10.0.1.160 --update   # regenerate baseline

Password: env SHADOW_DEVICE_PASSWORD (default "alpine").

ponytail: stdlib only, no evidence/journal ceremony (that's stealth_device.py's
job for provenance-bound CI runs); this is the ad-hoc "is it still clean" tool.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import plistlib
import shlex
import subprocess
import sys
import time

shell_quote = shlex.quote

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests" / "harness-expected.json"
BUNDLE = "me.jjolano.shadow.harness"
PREFS_REMOTE = "/var/jb/var/mobile/Library/Preferences/me.jjolano.shadow.plist"
REPORTS_DIR = "/var/mobile/Documents/ShadowDetectorTests"
MARKER = f"{REPORTS_DIR}/.run-all-trigger"
DETECTOR_IDS = (
    "dyldprobe", "iossecuritysuite", "jailbreakdetector", "securitytoolkit",
    "dttjailbreakdetection", "freerasp", "roothider", "batjailbreakguard",
    "safetynet", "devicesecuritykit", "jailmonkey", "isjailbroken", "swiftyjbd",
)
SSH_OPTS = (
    "-o", "StrictHostKeyChecking=no", "-o", "IdentitiesOnly=yes",
    "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
    "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=15",
)
NOTCHECKED_MARK = "notChecked"
# freerasp.debug prints a non-"notChecked" clean message under a real launch.
CLEAN_DIAGNOSTIC = "clean under real SpringBoard launch"


def die(message: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"harness-regression: {message}", file=sys.stderr)
    sys.exit(1)


class Device:
    def __init__(self, endpoint: str, password: str) -> None:
        if not endpoint.startswith("mobile@"):
            die("device must be mobile@host")
        self.endpoint = endpoint
        self.password = password

    def _sshpass(self, argv: list[str], **kw) -> subprocess.CompletedProcess:
        env = {**os.environ, "SSHPASS": self.password}
        return subprocess.run(["sshpass", "-e", *argv], env=env, text=True,
                              capture_output=True, **kw)

    def sh(self, script: str, timeout: int = 120, privileged: bool = False
           ) -> subprocess.CompletedProcess:
        if privileged:
            # sudo reads the password from stdin (-S), empty prompt (-p '').
            argv = ["ssh", *SSH_OPTS, self.endpoint, f"sudo -S -p '' /var/jb/bin/sh -c {shell_quote(script)}"]
            env = {**os.environ, "SSHPASS": self.password}
            return subprocess.run(["sshpass", "-e", *argv], env=env, text=True,
                                  capture_output=True, input=self.password + "\n", timeout=timeout)
        return self._sshpass(["ssh", *SSH_OPTS, self.endpoint, script], timeout=timeout)

    def run_ok(self, script: str, what: str, timeout: int = 120,
               privileged: bool = False) -> str:
        result = self.sh(script, timeout=timeout, privileged=privileged)
        if result.returncode != 0:
            die(f"{what}: {result.stderr.strip() or result.stdout.strip() or 'ssh failed'}")
        return result.stdout

    def put(self, local: pathlib.Path, remote: str, what: str) -> None:
        # base64 over the shell: scp -O drops on this device (see handoff notes).
        data = base64.b64encode(local.read_bytes()).decode()
        result = self._sshpass(
            ["ssh", *SSH_OPTS, self.endpoint, f"base64 -d > {remote}"],
            input=data, timeout=300,
        )
        if result.returncode != 0:
            die(f"{what}: {result.stderr.strip() or 'upload failed'}")

    def get_bytes(self, remote: str, what: str) -> bytes:
        result = self._sshpass(
            ["ssh", *SSH_OPTS, self.endpoint, f"base64 < {remote}"], timeout=120)
        if result.returncode != 0:
            die(f"{what}: {result.stderr.strip() or 'download failed'}")
        return base64.b64decode(result.stdout)


def report_consistency_error(value: dict, identifier: str) -> str | None:
    """Schema + internal-consistency guard (mirrors stealth_device.py)."""
    sdk = value.get("sdk")
    if not isinstance(sdk, dict) or sdk.get("id") != identifier:
        return f"{identifier}: report identity mismatch"
    if value.get("schemaVersion") != 1:
        return f"{identifier}: report schema is not 1"
    if value.get("outcome") not in {"clean", "jailbroken"}:
        return f"{identifier}: outcome not conclusive ({value.get('outcome')!r})"
    rounds = value.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        return f"{identifier}: no rounds"
    all_clean = True
    for rnd in rounds:
        checks = rnd.get("checks") if isinstance(rnd, dict) else None
        clean = rnd.get("clean") if isinstance(rnd, dict) else None
        if not isinstance(clean, bool) or not isinstance(checks, list) or not checks:
            return f"{identifier}: incomplete round"
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("passed"), bool):
                return f"{identifier}: invalid check"
        if clean != all(c["passed"] for c in checks):
            return f"{identifier}: round result inconsistent with its checks"
        all_clean &= clean
    if (value["outcome"] == "clean") != all_clean:
        return f"{identifier}: outcome inconsistent with rounds"
    return None


def notchecked_ids(value: dict) -> list[str]:
    ids = []
    for rnd in value.get("rounds", []):
        for check in rnd.get("checks", []):
            msg = check.get("message", "")
            if NOTCHECKED_MARK in msg or CLEAN_DIAGNOSTIC in msg:
                ids.append(check.get("id"))
    return sorted(i for i in ids if i)


def aggressive_prefs(original: dict) -> dict:
    """Global aggressive scalar + per-app harness override, harness enabled."""
    result = dict(original)
    result["Detector_Aggressive"] = True
    app = dict(result.get(BUNDLE, {})) if isinstance(result.get(BUNDLE), dict) else {}
    app["Detector_Aggressive"] = True
    app.pop("App_Disabled", None)
    app["App_Enabled"] = True
    result[BUNDLE] = app
    return result


def harness_app_dir(device: Device) -> str:
    out = device.run_ok(
        "ls -d /private/preboot/*/dopamine-*/procursus/Applications/ShadowHarness.app 2>/dev/null | head -1",
        "locate harness app",
    ).strip()
    if not out:
        die("ShadowHarness.app not found on device (install the harness deb first, or pass --deb)")
    return out


def collect_reports(device: Device) -> dict[str, dict]:
    reports: dict[str, dict] = {}
    for identifier in DETECTOR_IDS:
        raw = device.get_bytes(f"{REPORTS_DIR}/{identifier}.json", f"pull {identifier}")
        try:
            reports[identifier] = json.loads(raw)
        except json.JSONDecodeError as exc:
            die(f"{identifier}: report is not valid JSON ({exc})")
    return reports


def run_pass(device: Device, deb: pathlib.Path | None) -> dict[str, dict]:
    if deb is not None:
        if not deb.is_file():
            die(f"--deb not found: {deb}")
        device.put(deb, "/var/mobile/.harness-regression.deb", "upload harness deb")
        device.run_ok("dpkg -i /var/mobile/.harness-regression.deb && rm -f /var/mobile/.harness-regression.deb",
                      "install harness deb", timeout=180, privileged=True)

    app_dir = harness_app_dir(device)
    exe = f"{app_dir}/ShadowHarness"

    # Back up prefs, stage aggressive. Always restored in finally.
    original = device.get_bytes(PREFS_REMOTE, "read device prefs")
    prefs = plistlib.loads(original)
    if not isinstance(prefs, dict):
        die("device prefs root is not a dict")
    staged = plistlib.dumps(aggressive_prefs(prefs), fmt=plistlib.FMT_BINARY)
    backup = pathlib.Path("/tmp/opencode/harness-prefs-backup.plist")
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(original)
    staged_local = pathlib.Path("/tmp/opencode/harness-prefs-aggressive.plist")
    staged_local.write_bytes(staged)

    try:
        device.put(staged_local, "/var/mobile/.hr-prefs.plist", "upload aggressive prefs")
        device.run_ok(
            f"cp -a /var/mobile/.hr-prefs.plist {PREFS_REMOTE} && "
            f"chown mobile:mobile {PREFS_REMOTE} && chmod 600 {PREFS_REMOTE} && "
            "rm -f /var/mobile/.hr-prefs.plist && killall -9 cfprefsd 2>/dev/null; sleep 6; true",
            "stage aggressive prefs", privileged=True,
        )
        # Fresh reports dir + foreground marker, then a real SpringBoard launch.
        # uiopen must run as the mobile user (SpringBoard session), so the
        # privileged prep and the unprivileged launch are two steps.
        device.run_ok(
            f"killall -9 ShadowHarness 2>/dev/null; sleep 2; "
            f"rm -rf {REPORTS_DIR}; mkdir -p {REPORTS_DIR}; "
            f"touch {MARKER}; chown -R mobile:mobile {REPORTS_DIR}; "
            f"rm -f /var/mobile/Library/Logs/CrashReporter/ShadowHarness-*.ips; true",
            "prepare run", privileged=True,
        )
        device.run_ok(f"uiopen --bundleid {BUNDLE}; true", "foreground launch")
        # Wait for all 13 reports + the freerasp settle window (~35s).
        deadline = time.time() + 300
        while time.time() < deadline:
            listing = device.sh(f"ls {REPORTS_DIR}/*.json 2>/dev/null | wc -l").stdout.strip()
            marker_gone = device.sh(f"test -e {MARKER}; echo $?").stdout.strip() == "1"
            if listing.isdigit() and int(listing) >= len(DETECTOR_IDS) and marker_gone:
                time.sleep(35)  # let freerasp finish its settle window
                break
            time.sleep(8)
        else:
            die("timed out waiting for reports (device locked? harness crashed?)")
        crash = device.sh(
            "ls /var/mobile/Library/Logs/CrashReporter/ShadowHarness-*.ips 2>/dev/null").stdout.strip()
        if crash:
            die(f"harness crashed during run: {crash}")
        return collect_reports(device)
    finally:
        device.put(backup, "/var/mobile/.hr-restore.plist", "upload prefs backup")
        device.sh(
            f"killall -9 ShadowHarness 2>/dev/null; "
            f"cp -a /var/mobile/.hr-restore.plist {PREFS_REMOTE} && "
            f"chown mobile:mobile {PREFS_REMOTE} && chmod 600 {PREFS_REMOTE}; "
            f"rm -f /var/mobile/.hr-restore.plist {REPORTS_DIR}/.run-all-trigger; "
            "killall -9 cfprefsd 2>/dev/null; true", privileged=True)


def observed_baseline(reports: dict[str, dict]) -> dict:
    return {
        "_launch": "foreground",
        "_mode": "aggressive",
        "detectors": {
            identifier: {
                "outcome": reports[identifier].get("outcome"),
                "notChecked": notchecked_ids(reports[identifier]),
            }
            for identifier in DETECTOR_IDS
        },
    }


def compare(reports: dict[str, dict], expected: dict) -> list[str]:
    failures: list[str] = []
    exp_detectors = expected.get("detectors", {})
    for identifier in DETECTOR_IDS:
        value = reports[identifier]
        consistency = report_consistency_error(value, identifier)
        if consistency:
            failures.append(consistency)
            continue
        want = exp_detectors.get(identifier)
        if want is None:
            failures.append(f"{identifier}: not in baseline (add it or --update)")
            continue
        if value.get("outcome") != want.get("outcome"):
            failures.append(
                f"{identifier}: outcome {value.get('outcome')!r} != expected {want.get('outcome')!r}")
        got_nc = set(notchecked_ids(value))
        want_nc = set(want.get("notChecked", []))
        for new_id in sorted(got_nc - want_nc):
            failures.append(
                f"{identifier}: NEW notChecked {new_id!r} — a real check was downgraded to a pass; "
                "fix the hook or, if intentional, --update the baseline")
        for gone_id in sorted(want_nc - got_nc):
            failures.append(
                f"{identifier}: expected notChecked {gone_id!r} is gone — if the hook now really "
                "covers it, --update the baseline")
    return failures


def selftest() -> int:
    """Pure-logic checks (no device) — runnable in CI via verify-device-driver."""
    expected = json.loads(BASELINE.read_text())
    assert set(expected["detectors"]) == set(DETECTOR_IDS), "baseline detector ids drifted"
    clean = {"schemaVersion": 1, "sdk": {"id": "x"}, "outcome": "clean",
             "rounds": [{"clean": True, "checks": [{"passed": True, "id": "x.a", "message": "ok"}]}]}
    assert report_consistency_error(clean, "x") is None
    lie = dict(clean); lie["outcome"] = "jailbroken"
    assert report_consistency_error(lie, "x") is not None, "outcome/round inconsistency not caught"
    nc = {"rounds": [{"checks": [
        {"id": "a", "message": "notChecked: foo"},
        {"id": "b", "message": "clean under real SpringBoard launch"},
        {"id": "c", "message": "ok"}]}]}
    assert notchecked_ids(nc) == ["a", "b"], notchecked_ids(nc)
    # A hidden fail downgraded to a notChecked pass must be caught.
    reports = {i: {"schemaVersion": 1, "sdk": {"id": i}, "outcome": "clean",
                   "rounds": [{"clean": True, "checks": (
                       [{"passed": True, "id": i + ".ok", "message": "ok"}]
                       + [{"passed": True, "id": n, "message": "notChecked: x"}
                          for n in expected["detectors"][i]["notChecked"]])}]}
               for i in DETECTOR_IDS}
    assert compare(reports, expected) == [], compare(reports, expected)
    reports["batjailbreakguard"]["rounds"][0]["checks"].append(
        {"passed": True, "id": "bat.sneaky", "message": "notChecked: hidden"})
    assert any("NEW notChecked" in f and "bat.sneaky" in f for f in compare(reports, expected))
    print("PASS harness-regression selftest (baseline ids, consistency, notChecked diff)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", help="mobile@host")
    parser.add_argument("--deb", type=pathlib.Path, help="harness .deb to install first")
    parser.add_argument("--update", action="store_true",
                        help="write the observed result as the new baseline instead of asserting")
    parser.add_argument("--selftest", action="store_true",
                        help="run pure-logic checks (no device) and exit")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.device:
        die("--device mobile@host is required (or --selftest)")

    password = os.environ.get("SHADOW_DEVICE_PASSWORD", "alpine")
    device = Device(args.device, password)
    reports = run_pass(device, args.deb)

    if args.update:
        baseline = observed_baseline(reports)
        for identifier in DETECTOR_IDS:
            if report_consistency_error(reports[identifier], identifier):
                die(f"refusing to bake an inconsistent report into the baseline: {identifier}")
            if baseline["detectors"][identifier]["outcome"] != "clean":
                die(f"refusing to bake a non-clean baseline: {identifier} is "
                    f"{baseline['detectors'][identifier]['outcome']}")
        existing = json.loads(BASELINE.read_text())
        baseline = {"_comment": existing.get("_comment", ""), **baseline}
        BASELINE.write_text(json.dumps(baseline, indent=2) + "\n")
        print(f"updated baseline: {BASELINE}")
        return 0

    expected = json.loads(BASELINE.read_text())
    failures = compare(reports, expected)
    if failures:
        print("FAIL harness regression:")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(f"PASS harness regression: {len(DETECTOR_IDS)}/{len(DETECTOR_IDS)} clean "
          "(foreground/aggressive), notChecked set matches baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
