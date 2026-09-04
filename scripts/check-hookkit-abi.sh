#!/usr/bin/env bash
# check-hookkit-abi.sh — HookKit ABI drift detector.
#
# Shadow does NOT vendor HookKit; it compiles against, and links, the
# Theos-installed HookKit.framework (build-support/hookkit.mk). Shadow's binding
# layer (src/ShadowCore.dylib/SHDWHookSession.m + SHDWHookFallback.h) is pinned
# to a specific slice of HookKit's HK3 C ABI: a fixed ABI version, a set of
# exported functions, header inlines, opaque types, and enum/flag constants.
#
# This script verifies the installed HookKit still provides exactly that surface
# so a HookKit update that adds/removes/renames part of the ABI Shadow uses is
# surfaced for a human/agent to review — instead of only failing at some future
# compile or, worse, silently changing behaviour.
#
# It is a REVIEW gate, not a build gate: exit 1 means "the HookKit ABI Shadow
# depends on drifted — inspect and update SHDWHookSession.m / this baseline",
# not "the build is broken". Wire it into the verify pass; treat a failure as a
# prompt to adapt Shadow to the new HookKit, then refresh the baseline below.
#
# Usage: scripts/check-hookkit-abi.sh [SCHEME]   (SCHEME default: rootless)
set -euo pipefail

# --headers-only: skip the exported-symbol check (needs the framework binary).
# For CI/hosts that provision only HookKit headers; still validates ABI version,
# types, constants, and header inlines — the bulk of the drift surface.
HEADERS_ONLY=0
if [ "${1:-}" = "--headers-only" ]; then HEADERS_ONLY=1; shift; fi

LANE="${1:-rootless}"
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
: "${THEOS:?THEOS must point to Theos}"

# Map SHADOW_LANE -> HookKit framework dir, matching build-support/hookkit.mk.
# rootless/roothide are Theos schemes; the two rootful lanes are BOTH the
# default scheme with different arm64e ABIs, so they resolve under $THEOS/lib.
case "$LANE" in
    rootless)        FW_DIR="$THEOS/lib/iphone/rootless" ;;
    roothide)        FW_DIR="$THEOS/lib/iphone/roothide" ;;
    rootful-legacy)  FW_DIR="$THEOS/lib/iphone/rootful-legacy" ;;
    *)               FW_DIR="$THEOS/lib" ;;   # rootful-modern / default
esac
FW="$FW_DIR/HookKit.framework"
[ -d "$FW" ] || FW="$THEOS/lib/HookKit.framework"   # fallback
BIN="$FW/HookKit"
HDR="$FW/Headers"
[ -d "$HDR" ] || { echo "FAIL: HookKit headers not found at $HDR" >&2; exit 2; }
if [ "$HEADERS_ONLY" = 0 ] && [ ! -f "$BIN" ]; then
    echo "FAIL: HookKit binary not found at $BIN (use --headers-only to skip the export check)" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# BASELINE — the exact HookKit ABI surface Shadow's binding layer depends on.
# Regenerate deliberately (never blindly) after adapting Shadow to a HookKit
# update:  grep -rhoE '\bhk_[a-z_]+\b'  and  '\bHK_[A-Z0-9_]+\b'  over
# src/ShadowCore.dylib, then re-sort into the buckets below by kind.
# ---------------------------------------------------------------------------

# The single ABI version every hk_*_spec/config struct is stamped with.
BASELINE_ABI_VERSION="HK_ABI_VERSION_3_0"

# Functions that MUST be exported symbols in the framework binary (Shadow calls
# them across the dylib boundary).  hk_runtime_create_with_backend_override is
# resolved via dlsym and tolerated-if-absent in code, but it is present today
# and we still track it so its removal is a visible event.
BASELINE_EXPORTED_FUNCS="
hk_artifact_snapshot_copy_at
hk_artifact_snapshot_count
hk_artifact_snapshot_release
hk_hook_copy_result
hk_hook_original_slot
hk_original_slot_load
hk_plan_add_hook
hk_plan_analyze
hk_plan_commit
hk_plan_create
hk_plan_prepare
hk_plan_release
hk_report_copy_artifacts
hk_report_release
hk_runtime_create
hk_runtime_create_with_backend_override
hk_runtime_find_symbol
hk_runtime_release
hk_swift_hook
"

# Header static-inline / macro helpers Shadow calls (must exist in headers, not
# necessarily exported).
BASELINE_HEADER_INLINES="
hk_artifact_is_import_slot
hk_hook_result_refused_cleanly
hk_objc_instance_method
hk_objc_target_allow_inherited
hk_swift_target_init
"

# Opaque types / typedefs Shadow names (must appear in headers).
BASELINE_TYPES="
hk_artifact_snapshot_t
hk_artifact_t
hk_hook_result_t
hk_hook_spec_t
hk_hook_t
hk_original_requirement_t
hk_plan_t
hk_reachability_t
hk_report_t
hk_runtime_config_t
hk_runtime_t
hk_status_t
hk_swift_target_t
hk_target_kind_t
"

# Enum / flag constants Shadow uses (must be defined in headers).
BASELINE_CONSTS="
HK_ABI_VERSION_3_0
HK_AVAILABILITY_REQUIRED_NOW
HK_CONTINUATION_ANY
HK_IMAGE_ANY_LOADED
HK_IMAGE_EXACT_HEADER
HK_INSTALL_CONTEXT_EARLY_PROCESS
HK_OPERATION_MANDATORY
HK_ORIGINAL_CALLABLE_CONTINUATION
HK_ORIGINAL_DIRECT_PREDECESSOR
HK_ORIGINAL_NONE
HK_OUTCOME_ACTIVE
HK_OUTCOME_ANALYZED
HK_OUTCOME_PREPARED
HK_REACH_ENTRYPOINT
HK_REACH_EXISTING_IMPORTS
HK_REACH_OBJC_DISPATCH
HK_STATUS_OK
HK_SWIFT_NAME_DEMANGLED_SUBSTRING
HK_SYMBOL_ALIAS_EXACT_ONLY
HK_SYMBOL_NAME_C
HK_SYMBOL_NAME_SWIFT_MANGLED
HK_TARGET_FUNCTION_ADDRESS
HK_TARGET_FUNCTION_SYMBOL
HK_TARGET_OBJC_METHOD
"

fail=0
note() { echo "  DRIFT: $*" >&2; fail=1; }

echo "HookKit ABI drift check ($LANE): $FW"

# 1) ABI version: the baseline macro must still exist, and no NEWER
#    HK_ABI_VERSION_* may appear without Shadow adopting it.
if ! grep -rqE "define[[:space:]]+$BASELINE_ABI_VERSION\b" "$HDR"; then
    note "baseline ABI macro $BASELINE_ABI_VERSION no longer defined in headers"
fi
newer=$(grep -rhoE 'define[[:space:]]+HK_ABI_VERSION_[0-9]+_[0-9]+' "$HDR" 2>/dev/null \
        | awk '{print $2}' | sort -u | grep -vx "$BASELINE_ABI_VERSION" || true)
if [ -n "$newer" ]; then
    while read -r v; do [ -n "$v" ] && note "new ABI version present, Shadow still pins $BASELINE_ABI_VERSION: $v"; done <<EOF
$newer
EOF
fi

# 2) Exported functions: each baseline function must be an exported symbol.
#    Skipped in --headers-only mode (no binary available). Prefer LIEF; fall
#    back to nm if LIEF is unavailable.
if [ "$HEADERS_ONLY" = 1 ]; then
    echo "  (headers-only: exported-symbol check skipped)"
else
    EXPORTS=$(python3 - "$BIN" <<'PY' 2>/dev/null || true
import lief,sys
b=lief.parse(sys.argv[1])
print("\n".join(sorted({s.name.lstrip('_') for s in b.exported_symbols})))
PY
)
    if [ -z "$EXPORTS" ] && command -v nm >/dev/null 2>&1; then
        EXPORTS=$(nm -gU "$BIN" 2>/dev/null | awk '{print $3}' | sed 's/^_//' | sort -u || true)
    fi
    if [ -z "$EXPORTS" ]; then
        note "could not read exported symbols from $BIN (no LIEF/nm); export check inconclusive"
    else
        for f in $BASELINE_EXPORTED_FUNCS; do
            printf '%s\n' "$EXPORTS" | grep -qx "$f" || note "exported function missing from binary: $f"
        done
    fi
fi

# 3) Header inlines/macros and types: each must still appear in the headers.
for s in $BASELINE_HEADER_INLINES; do
    grep -rqE "\b$s\b" "$HDR" || note "header inline/macro missing: $s"
done
for t in $BASELINE_TYPES; do
    grep -rqE "\b$t\b" "$HDR" || note "type missing from headers: $t"
done

# 4) Constants: each must be defined in the headers.
for c in $BASELINE_CONSTS; do
    grep -rqE "\b$c\b" "$HDR" || note "constant missing from headers: $c"
done

# 5) Packaged dependency floor vs installed version (informational, never fatal
#    on its own): report the installed HookKit version next to the control-file
#    floor so a bump is visible. Parsed with a pure-Python plist reader so this
#    works on a Linux build host (no plutil) as well as on-device.
INFO="$FW/Info.plist"
inst_ver=""
if [ -f "$INFO" ] && command -v python3 >/dev/null 2>&1; then
    inst_ver=$(python3 - "$INFO" <<'PY' 2>/dev/null || true
import plistlib,sys
try:
    with open(sys.argv[1],'rb') as f: pl=plistlib.load(f)
    print(pl.get('CFBundleShortVersionString') or pl.get('CFBundleVersion') or '')
except Exception:
    pass
PY
)
fi
control="$ROOT/packaging/controls/control.$LANE"
[ -f "$control" ] || control="$ROOT/packaging/controls/control.rootless"
floor=$(grep -hoE 'hookkit[^,]*\(>= *[0-9][0-9.]*\)' "$control" 2>/dev/null \
    | grep -oE '>= *[0-9][0-9.]*' | grep -oE '[0-9][0-9.]*' | head -1 || true)
echo "  installed HookKit version: ${inst_ver:-unknown}; packaged floor ($LANE): ${floor:-unknown}"

if [ "$fail" -ne 0 ]; then
    echo "HookKit ABI drift detected — review SHDWHookSession.m against the new HookKit," >&2
    echo "adapt as needed, then regenerate the baseline in this script." >&2
    exit 1
fi
echo "OK: HookKit ABI surface Shadow depends on is intact ($LANE)"
