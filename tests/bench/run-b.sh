#!/usr/bin/env bash
# Arm B runner: launch-CPU benchmark on the test device.
#
# Measures cumulative launch CPU (ps TIME) and wall time for a target app,
# injected vs uninjected, N=5 runs each. The uninjected arm flips
# App_Disabled in Shadow's prefs (edited LOCALLY, shipped as base64, backed
# up and restored; cfprefsd killed between arms).
#
# Env: BENCH_TARGET (bundle id, default com.8bit.bitwarden),
#      BENCH_EXEC (process name, default Bitwarden), BENCH_RUNS (default 5),
#      SHADOW_DEV_HOST/SHADOW_DEV_PASS.
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
RUNS=${BENCH_RUNS:-5}
TARGET=${BENCH_TARGET:-com.8bit.bitwarden}
EXEC=${BENCH_EXEC:-Bitwarden}
HOST=${SHADOW_DEV_HOST:-mobile@10.0.1.160}
PASS=${SHADOW_DEV_PASS:-alpine}
OUT="$ROOT/tests/bench/results"
mkdir -p "$OUT"

SSH=(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes \
     -o PreferredAuthentications=password -o PubkeyAuthentication=no "$HOST")

PREFS_REMOTE=/var/jb/var/mobile/Library/Preferences/me.jjolano.shadow.plist

# --- pull current prefs, verify the target is injected (App_Disabled absent) ---
"${SSH[@]}" "cat $PREFS_REMOTE" > /tmp/prefs-current.plist

restore_prefs() {
  if [ -f /tmp/prefs-current.plist ]; then
    local b64
    b64=$(base64 -w0 /tmp/prefs-current.plist)
    printf '%s\n' "$b64" | "${SSH[@]}" "base64 -d > $PREFS_REMOTE && chown mobile:mobile $PREFS_REMOTE && chmod 600 $PREFS_REMOTE" || true
    printf '%s\n' 'killall -9 cfprefsd 2>/dev/null || true' | "$ROOT/scripts/dev.sh" >/dev/null || true
  fi
}
trap restore_prefs EXIT

python3 - "$TARGET" <<'PY'
import plistlib, sys
target = sys.argv[1]
p = plistlib.load(open('/tmp/prefs-current.plist', 'rb'))
app = p.get(target)
if not isinstance(app, dict):
    sys.exit(f"target entry missing in prefs: {target}")
if app.get('App_Disabled'):
    sys.exit(f"target is currently App_Disabled: {target} — aborting (restore first)")
print("target injected: OK")
PY

arm() {
  local mode="$1"
# Build the device-side loop with local values substituted, then run it
# through dev.sh (root). Pull the result separately because the loop writes
# its samples on-device.
  cat <<EOF | "$ROOT/scripts/dev.sh"
#!/var/jb/bin/sh
TARGET=$TARGET; NAME=$EXEC; RUNS=$RUNS; OUT=/var/mobile/launch-$mode.csv; MODE=$mode
target_pids() {
  ps -Ao pid=,comm= | while read -r pid comm; do
    case "\$comm" in */"\$NAME") printf '%s\n' "\$pid";; esac
  done
}
kill_target() {
  for pid in \$(target_pids); do kill -9 "\$pid" 2>/dev/null || true; done
}
echo "mode,run,wall_sec,cpu_time" > \$OUT
i=1
while [ \$i -le \$RUNS ]; do
  kill_target
  sleep 2
  [ -z "\$(target_pids)" ] || exit 1
  start=\$(date +%s)
  uiopen --bundleid "\$TARGET"
  cpu=""
  launched=""
  finished=""
  while :; do
    wall=\$(( \$(date +%s) - start ))
    # ps reports the full executable path in comm= on this device.
    line=\$(ps -Ao pid=,state=,time=,comm= | grep "/\$NAME\$" | head -1)
    if [ -n "\$line" ]; then
      launched=yes
      # Shell field splitting handles ps's variable-width whitespace.
      set -f
      set -- \$line
      set +f
      state=\$2
      cpu=\$3
      if [ "\$state" = "Ss" ]; then
        echo "\$MODE,\$i,\$wall,\$cpu" >> \$OUT
        finished=yes
        break
      fi
    fi
    if [ \$wall -gt 90 ]; then
      echo "\$MODE,\$i,TIMEOUT,\${cpu:-0}" >> \$OUT
      finished=yes
      break
    fi
    sleep 2
  done
  if [ -z "\$launched" ] && [ -z "\$finished" ]; then
    echo "\$MODE,\$i,NOLAUNCH,0" >> \$OUT
  fi
  i=\$(( i + 1 ))
  sleep 3
done
EOF

  "${SSH[@]}" "cat /var/mobile/launch-$mode.csv" > "$OUT/launch-$mode.csv"
}

# --- injected arm ---
arm injected

# --- flip prefs to App_Disabled (local edit, base64 ship) ---
DISABLED_B64=$(python3 - "$TARGET" <<'PY'
import base64, plistlib, sys
target = sys.argv[1]
p = plistlib.load(open('/tmp/prefs-current.plist', 'rb'))
p[target]['App_Disabled'] = True
plistlib.dump(p, open('/tmp/prefs-disabled.plist', 'wb'), fmt=plistlib.FMT_BINARY)
print(base64.b64encode(open('/tmp/prefs-disabled.plist', 'rb').read()).decode())
PY
)

cat <<EOF | "$ROOT/scripts/dev.sh"
echo "$DISABLED_B64" | base64 -d > $PREFS_REMOTE
chown mobile:mobile $PREFS_REMOTE
chmod 600 $PREFS_REMOTE
killall -9 cfprefsd 2>/dev/null || true
sleep 15
EOF

# --- uninjected arm ---
arm uninjected

echo "arm B results in $OUT/launch-{injected,uninjected}.csv"
