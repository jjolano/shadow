#!/usr/bin/env bash
# Arm B runner: launch-CPU benchmark on the test device.
#
# Measures cumulative launch CPU (ps TIME) and wall time for a target app,
# injected vs uninjected, N=5 runs each. The uninjected arm flips
# App_Enabled in Shadow's prefs (edited LOCALLY, shipped as base64, backed
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

PREFS_REMOTE=/var/mobile/Library/Preferences/me.jjolano.shadow.plist

# --- pull current prefs, verify the target is injected ---
"${SSH[@]}" "cat $PREFS_REMOTE" > /tmp/prefs-current.plist

write_prefs() {
  local source="$1" b64
  b64=$(base64 -w0 "$source")
  {
    printf '%s\n' "base64 -d > /var/mobile/Media/.shadow-b-prefs.plist <<'PREFS'"
    printf '%s\n' "$b64"
    printf '%s\n' 'PREFS'
    printf '%s\n' "install -o mobile -g mobile -m 0600 /var/mobile/Media/.shadow-b-prefs.plist $PREFS_REMOTE"
    printf '%s\n' 'rm -f /var/mobile/Media/.shadow-b-prefs.plist'
    printf '%s\n' 'killall -9 cfprefsd 2>/dev/null || true'
  } | "$ROOT/scripts/dev.sh"
}

restore_prefs() {
  if [ -f /tmp/prefs-current.plist ]; then
    write_prefs /tmp/prefs-current.plist || true
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
legacy_global = bool(p.get('Global_Enabled'))
if app.get('App_Disabled'):
    enabled = False
elif not p.get('SingleToggleMigrated') and legacy_global:
    enabled = True
else:
    enabled = bool(app['App_Enabled']) if 'App_Enabled' in app else legacy_global
if not enabled:
    sys.exit(f"target is currently disabled: {target} — aborting (restore first)")
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

# --- disable the app (local edit, base64 ship) ---
python3 - "$TARGET" <<'PY'
import plistlib, sys
target = sys.argv[1]
p = plistlib.load(open('/tmp/prefs-current.plist', 'rb'))
legacy_global = bool(p.get('Global_Enabled'))
migrated = bool(p.get('SingleToggleMigrated'))
for key, value in p.items():
    if not isinstance(value, dict):
        continue
    if value.get('App_Disabled'):
        enabled = False
    elif not migrated and legacy_global:
        enabled = True
    else:
        enabled = bool(value['App_Enabled']) if 'App_Enabled' in value else legacy_global
    value['App_Enabled'] = enabled
    value.pop('App_Disabled', None)
p['SingleToggleMigrated'] = True
p[target]['App_Enabled'] = False
plistlib.dump(p, open('/tmp/prefs-disabled.plist', 'wb'), fmt=plistlib.FMT_BINARY)
PY
write_prefs /tmp/prefs-disabled.plist
sleep 15

# --- uninjected arm ---
arm uninjected

echo "arm B results in $OUT/launch-{injected,uninjected}.csv"
