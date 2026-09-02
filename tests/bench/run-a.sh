#!/usr/bin/env bash
# Arm A runner: build benchprobe, ship to the test device, run N injected +
# N stock batteries, pull the CSVs into tests/bench/results/.
#
# Env: BENCH_RUNS (default 3), BENCH_ITERS (default 10000),
#      SHADOW_DEV_HOST/SHADOW_DEV_PASS (defaults match scripts/dev.sh).
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
RUNS=${BENCH_RUNS:-3}
ITERS=${BENCH_ITERS:-10000}
HOST=${SHADOW_DEV_HOST:-mobile@10.0.1.160}
PASS=${SHADOW_DEV_PASS:-alpine}
OUT="$ROOT/tests/bench/results"
BIN="$ROOT/tests/tools/benchprobe/.theos/obj/debug/arm64/benchprobe"

SSH=(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes \
     -o PreferredAuthentications=password -o PubkeyAuthentication=no "$HOST")

cd "$ROOT/tests/tools/benchprobe"
THEOS_PACKAGE_SCHEME=rootless make ARCHS="arm64" TARGET="iphone:clang:16.5:12.0" >/dev/null

# theos' debug sign step leaves the binary unsigned; the kernel SIGKILLs
# unsigned binaries at spawn (AMFI). hookprobe's deployed copy carries a
# signature (applied at package install); raw-shipped tools need it here.
/usr/local/bin/ldid -S "$BIN"

base64 -w0 "$BIN" | "${SSH[@]}" 'cat > /tmp/benchprobe.b64'

mkdir -p "$OUT"
STAMP=$(date +%Y%m%dT%H%M%SZ)

# Device-side: install + run both arms N times, leave CSVs on device.
cat <<EOF | "$ROOT/scripts/dev.sh"
base64 -d /tmp/benchprobe.b64 > /var/jb/usr/bin/benchprobe
chmod 755 /var/jb/usr/bin/benchprobe
for i in \$(seq 1 $RUNS); do
  /var/jb/usr/bin/benchprobe --iters $ITERS > /var/mobile/bench-injected-\$i.csv
  /var/jb/usr/bin/benchprobe --no-shadow --iters $ITERS > /var/mobile/bench-stock-\$i.csv
done
ls -l /var/mobile/bench-*.csv
EOF

for i in $(seq 1 "$RUNS"); do
  "${SSH[@]}" "cat /var/mobile/bench-injected-$i.csv" > "$OUT/injected-$i.csv"
  "${SSH[@]}" "cat /var/mobile/bench-stock-$i.csv" > "$OUT/stock-$i.csv"
done

echo "results in $OUT (runs=$RUNS iters=$ITERS stamp=$STAMP)"