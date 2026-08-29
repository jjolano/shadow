#!/usr/bin/env bash
# Arm C runner: detector response timing on ShadowHarness.
#
# The current harness package must already be built and installed. Each run
# launches the app, waits for the asynchronous freeRASP round to settle, then
# pulls the ten per-detector JSON reports. The injected arm clears only the
# harness crash counter; the original plist is restored on every exit.
#
# Env: BENCH_RUNS (default 3), BENCH_WAIT (default 40 seconds),
#      SHADOW_DEV_HOST/SHADOW_DEV_PASS.
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
RUNS=${BENCH_RUNS:-3}
WAIT=${BENCH_WAIT:-40}
TARGET=me.jjolano.shadow.harness
HOST=${SHADOW_DEV_HOST:-mobile@10.0.1.160}
PASS=${SHADOW_DEV_PASS:-alpine}
OUT="$ROOT/tests/bench/results"
PREFS_REMOTE=/var/jb/var/mobile/Library/Preferences/me.jjolano.shadow.plist
REPORT_DIR=/var/mobile/Documents/ShadowDetectorTests

SSH=(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes \
     -o PreferredAuthentications=password -o PubkeyAuthentication=no "$HOST")

IDS=(batjailbreakguard jailmonkey roothider safetynet dttjailbreakdetection \
     jailbreakdetector securitytoolkit devicesecuritykit iossecuritysuite freerasp)

mkdir -p "$OUT"
rm -f "$OUT"/detector-*.json "$OUT/detector-timing.csv"
"${SSH[@]}" "cat $PREFS_REMOTE" > /tmp/shadow-c-prefs-original.plist

restore_prefs() {
  if [ -f /tmp/shadow-c-prefs-original.plist ]; then
    local b64
    b64=$(base64 -w0 /tmp/shadow-c-prefs-original.plist)
    printf '%s\n' "$b64" | "${SSH[@]}" "base64 -d > $PREFS_REMOTE && chmod 600 $PREFS_REMOTE"
    echo 'killall -9 cfprefsd 2>/dev/null || true' | "$ROOT/scripts/dev.sh" >/dev/null
  fi
}
trap restore_prefs EXIT

write_prefs() {
  local path="$1" b64
  b64=$(base64 -w0 "$path")
  printf '%s\n' "$b64" | "${SSH[@]}" "base64 -d > $PREFS_REMOTE && chmod 600 $PREFS_REMOTE"
  cat <<EOF | "$ROOT/scripts/dev.sh" >/dev/null
killall -9 cfprefsd 2>/dev/null || true
sleep 15
EOF
}

python3 - "$TARGET" <<'PY'
import plistlib, sys
target = sys.argv[1]
p = plistlib.load(open('/tmp/shadow-c-prefs-original.plist', 'rb'))
app = p.get(target)
if not isinstance(app, dict):
    sys.exit(f"target entry missing in prefs: {target}")
app.pop('App_Disabled', None)
p.pop(f'CrashCount.{target}', None)
plistlib.dump(p, open('/tmp/shadow-c-prefs-injected.plist', 'wb'), fmt=plistlib.FMT_BINARY)
PY

python3 - "$TARGET" <<'PY'
import plistlib, sys
target = sys.argv[1]
p = plistlib.load(open('/tmp/shadow-c-prefs-injected.plist', 'rb'))
p[target]['App_Disabled'] = True
plistlib.dump(p, open('/tmp/shadow-c-prefs-uninjected.plist', 'wb'), fmt=plistlib.FMT_BINARY)
PY

run_one() {
  local mode="$1" run="$2"

  # Remove stale reports before each launch. The app writes reports to this
  # shared evidence directory, so an absent report is a real failed run.
  cat <<EOF | "$ROOT/scripts/dev.sh" >/dev/null
rm -f $REPORT_DIR/*.json
mkdir -p $REPORT_DIR
harness_pids() {
  ps -axo pid=,args= | while read -r pid args; do
    case "\$args" in
      */ShadowHarness.app/ShadowHarness*) printf '%s\n' "\$pid" ;;
    esac
  done
}
kill_harness() {
  for pid in \$(harness_pids); do
    kill -9 "\$pid" 2>/dev/null || true
  done
}
kill_harness
sleep 2
[ -z "\$(harness_pids)" ]
uicache -a >/dev/null 2>&1 || true
uiopen --bundleid $TARGET >/dev/null 2>&1 || true
sleep $WAIT
kill_harness
[ -z "\$(harness_pids)" ]
EOF

  for id in "${IDS[@]}"; do
    local destination="$OUT/detector-$mode-$run-$id.json"
    rm -f "$destination"
    "${SSH[@]}" "cat $REPORT_DIR/$id.json" > "$destination" 2>/dev/null || rm -f "$destination"
  done
}

write_prefs /tmp/shadow-c-prefs-injected.plist
for run in $(seq 1 "$RUNS"); do
  run_one injected "$run"
done

write_prefs /tmp/shadow-c-prefs-uninjected.plist
for run in $(seq 1 "$RUNS"); do
  run_one uninjected "$run"
done

python3 "$ROOT/tests/bench/collect-c.py"
echo "arm C results in $OUT/detector-timing.csv"
