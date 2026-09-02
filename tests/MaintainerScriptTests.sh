#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/shadow-maintainer.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
assert() { "$@" || fail "$*"; }

printf '%s\n' '#!/bin/sh' \
'printf "%s\n" "$*" >> "$FAKE_LOG"' \
'state=$(sed -n "1p" "$FAKE_STATE")' \
'case "$1" in' \
'print) case "$state" in absent) exit 1 ;; mismatch) printf " program = %s\n pid = 71\n" "$FAKE_PROGRAM" ;; *) printf " program = %s\n" "$FAKE_PROGRAM"; [ "$state" = live ] || [ "$state" = live-stuck ] && printf " pid = 71\n" ;; esac ;;' \
'kill) [ "$state" = live ] && printf "%s\n" idle > "$FAKE_STATE" ;;' \
'bootout|unload) printf "%s\n" absent > "$FAKE_STATE" ;;' \
'esac' >"$tmp/bin/launchctl"
printf '%s\n' '#!/bin/sh' \
'[ -n "${FAKE_EXACT_PID:-}" ] && kill -0 "$FAKE_EXACT_PID" 2>/dev/null && printf "%s %s\n" "$FAKE_EXACT_PID" "$FAKE_EXACT_COMM"' \
'[ -z "${FAKE_DECOYS:-}" ] || printf "%s" "$FAKE_DECOYS" | tr "|" "\n"' >"$tmp/bin/ps"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$tmp/bin/sleep"
printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$*" >> "$FAKE_LOG"' >"$tmp/bin/shdw"
chmod 700 "$tmp/bin/launchctl" "$tmp/bin/ps" "$tmp/bin/sleep" "$tmp/bin/shdw"

run_prerm() {
    : >"$tmp/log"; printf '%s\n' "$2" >"$tmp/state"
    env DPKG_MAINTSCRIPT_ARCH="$1" FAKE_LOG="$tmp/log" FAKE_STATE="$tmp/state" \
        FAKE_PROGRAM="$3" FAKE_EXACT_PID="${4:-}" FAKE_EXACT_COMM="${5:-}" \
        FAKE_DECOYS="${6:-}" SHADOW_LAUNCHCTL_BIN="$tmp/bin/launchctl" \
        SHADOW_PS_BIN="$tmp/bin/ps" SHADOW_SLEEP_BIN="$tmp/bin/sleep" \
        sh "$root/packaging/layout/DEBIAN/prerm" upgrade
}

run_prerm iphoneos-arm64 live /var/jb/usr/libexec/shadowd
assert grep -F -q 'kill SIGTERM system/me.jjolano.shadow' "$tmp/log"
assert grep -F -q 'bootout system/me.jjolano.shadow' "$tmp/log"

run_prerm iphoneos-arm64e live /usr/libexec/shadowd
assert grep -F -q 'kill SIGTERM system/me.jjolano.shadow' "$tmp/log"

run_prerm iphoneos-arm64 absent /var/jb/usr/libexec/shadowd '' '' '42 shadowd|43 /var/jb/usr/libexec/shadowd.old'
assert grep -F -q 'bootout system/me.jjolano.shadow.watcher' "$tmp/log"
if grep -F -q 'kill SIGTERM system/me.jjolano.shadow' "$tmp/log"; then fail 'basename/prefix decoy was targeted'; fi

run_prerm iphoneos-arm64 absent /var/jb/usr/libexec/shadowd

sleep 30 &
orphan=$!
run_prerm iphoneos-arm64 absent /var/jb/usr/libexec/shadowd "$orphan" /var/jb/usr/libexec/shadowd
if kill -0 "$orphan" 2>/dev/null; then fail 'exact orphan survived SIGTERM'; fi

: >"$tmp/log"; printf '%s\n' live-stuck >"$tmp/state"
if env DPKG_MAINTSCRIPT_ARCH=iphoneos-arm64 FAKE_LOG="$tmp/log" FAKE_STATE="$tmp/state" \
    FAKE_PROGRAM=/var/jb/usr/libexec/shadowd SHADOW_LAUNCHCTL_BIN="$tmp/bin/launchctl" \
    SHADOW_PS_BIN="$tmp/bin/ps" SHADOW_SLEEP_BIN="$tmp/bin/sleep" \
    sh "$root/packaging/layout/DEBIAN/prerm" upgrade; then
    fail 'timeout did not abort before dpkg removal'
fi

pkg="$tmp/pkg"
mkdir -p "$pkg/Library/LaunchDaemons" "$pkg/usr/libexec" "$pkg/usr/local/bin" "$pkg/Library/Shadow"
: >"$pkg/Library/LaunchDaemons/me.jjolano.shadow.plist"
: >"$pkg/usr/libexec/shadowd"
cp "$tmp/bin/shdw" "$pkg/usr/local/bin/shdw"
: >"$tmp/log"; printf '%s\n' mismatch >"$tmp/state"
if env DPKG_MAINTSCRIPT_ARCH=iphoneos-arm64 SHADOW_DPKG_ROOT="$pkg" SHADOW_ROOTFS_ROOT="$tmp/rootfs" \
    FAKE_LOG="$tmp/log" FAKE_STATE="$tmp/state" FAKE_PROGRAM=/unexpected/shadowd \
    SHADOW_LAUNCHCTL_BIN="$tmp/bin/launchctl" SHADOW_PS_BIN="$tmp/bin/ps" SHADOW_SLEEP_BIN="$tmp/bin/sleep" \
    sh "$root/packaging/layout/DEBIAN/postinst" configure; then
    fail 'mismatched job did not abort before bootstrap'
fi
if grep -F -q 'bootstrap system' "$tmp/log"; then fail 'postinst bootstrapped after mismatch'; fi

# An upgrade from the removed backend may leave its durable ledger/log outside
# the package payload.  The backend-free postinst may remove those exact files
# only after launchd reports the old job absent.
clean_pkg="$tmp/clean-pkg"
mkdir -p "$clean_pkg/Library/LaunchDaemons" "$clean_pkg/usr/local/bin" \
    "$clean_pkg/Library/Shadow" "$clean_pkg/var/mobile/Library/Preferences/me.jjolano.shadowd" \
    "$clean_pkg/var/log"
: >"$clean_pkg/Library/LaunchDaemons/me.jjolano.shadow.watcher.plist"
cp "$tmp/bin/shdw" "$clean_pkg/usr/local/bin/shdw"
: >"$clean_pkg/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger"
: >"$clean_pkg/var/log/shadowd.log"
: >"$tmp/log"; printf '%s\n' absent >"$tmp/state"
env DPKG_MAINTSCRIPT_ARCH=iphoneos-arm64 SHADOW_DPKG_ROOT="$clean_pkg" SHADOW_ROOTFS_ROOT="$tmp/rootfs-clean" \
    FAKE_LOG="$tmp/log" FAKE_STATE="$tmp/state" FAKE_PROGRAM=/var/jb/usr/libexec/shadowd \
    SHADOW_LAUNCHCTL_BIN="$tmp/bin/launchctl" SHADOW_PS_BIN="$tmp/bin/ps" SHADOW_SLEEP_BIN="$tmp/bin/sleep" \
    sh "$root/packaging/layout/DEBIAN/postinst" configure
if [ -e "$clean_pkg/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger" ] ||
   [ -e "$clean_pkg/var/log/shadowd.log" ]; then
    fail 'backend-free postinst retained legacy daemon state'
fi

harness_pkg="$tmp/harness-pkg"
harness_frameworks="$harness_pkg/Applications/ShadowHarness.app/Frameworks"
mkdir -p "$harness_frameworks"
: >"$harness_frameworks/shdwtestlib.dylib"
: >"$harness_frameworks/keep.txt"
for framework in BATJailbreakGuard DeviceSecurityKit IOSSecuritySuite JailbreakDetector SecurityToolkit Shadow TalsecRuntime; do
    mkdir "$harness_frameworks/$framework.framework"
done
env SHADOW_HARNESS_DPKG_ROOT="$harness_pkg" sh "$root/tests/ShadowHarness/layout/DEBIAN/postinst" configure
assert test -f "$harness_frameworks/shdwtestlib.dylib"
assert test -f "$harness_frameworks/keep.txt"
for framework in BATJailbreakGuard DeviceSecurityKit IOSSecuritySuite JailbreakDetector SecurityToolkit Shadow TalsecRuntime; do
    if [ -e "$harness_frameworks/$framework.framework" ]; then
        fail "harness postinst retained $framework.framework"
    fi
done

if grep -E '\<pgrep\>|\<seq\>|kill[[:space:]]+-[0-9]' "$root/packaging/layout/DEBIAN/prerm" "$root/packaging/layout/DEBIAN/postinst" >/dev/null; then
    fail 'forbidden maintainer command remains'
fi

printf 'PASS maintainer scripts\n'
