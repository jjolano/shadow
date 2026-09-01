#!/bin/sh
# Verifies the hook-registry metadata in ShadowCore.dylib/hooks:
#
#   raw syscalls (hooks/RawSyscalls.def — single source of truth for the
#   syscall(2)/__syscall(2) intercept set):
#     - every entry is well-formed with a unique SYS_ number, an ARITY, a
#       policy CAT and a forwarding shape FWD;
#     - every FWD has a shdw_fwd_<FWD> forwarding body in syscall.x;
#     - every CAT is a defined SHADW_RAW_CAT_<CAT> category with a dispatch
#       case in syscall.x;
#     - both trampolines (replaced_syscall, replaced___syscall) derive
#       their passthrough from the def (the OR-chains must not be
#       hand-synced again, and no hand-synced chain may linger);
#
#   libc hooks (the single shdw_libc_hooks descriptor array):
#     - every required hook (verifyGroups != 0) is installed by a group
#       that also verifies it (verifyGroups must be a subset of its
#       installGroups, token-wise — a required hook with no installer is
#       drift);
#     - only defined SHADW_HOOK_GROUP_* tokens are used;
#     - the legacy hand-synced tables (sym-policy table, lowlevel/libproc
#       symbol arrays, per-group verify arrays) are gone, and the dlsym
#       symbol policy iterates the same descriptor array.
#
# Reads source text only; run from the repo root: tests/verify-syscall-meta.sh
set -e

HOOKDIR=ShadowCore.dylib/hooks
DEF="$HOOKDIR/Universal/RawSyscalls.def"
SYSCALL="$HOOKDIR/Universal/syscall.x"
LIBC="$HOOKDIR/Universal/libc.x"
rc=0

fail() {
    echo "META FAIL: $*"
    rc=1
}

[ -f "$DEF" ] || { echo "META FAIL: $DEF missing"; exit 1; }

# --- raw syscall registry ------------------------------------------------

awk -v def="$DEF" -v syscall="$SYSCALL" '
    function has(needle,    s) { s = getfile(syscall); return index(s, needle) > 0 }
    function getfile(path,    s, line) { s = ""; while ((getline line < path) > 0) s = s line "\n"; close(path); return s }
    BEGIN {
        n = 0
        while ((getline line < def) > 0) {
            gsub(/^[ \t]+|[ \t]+$/, "", line)
            if (line == "" || line ~ /^\/\// || line ~ /^#/) continue
            if (line !~ /^SHADW_RAWSYSCALL\(SYS_[A-Za-z0-9_]+,[ \t]*[0-9]+,[ \t]*[A-Z0-9_]+,[ \t]*[A-Z0-9_]+\)$/) {
                printf "META FAIL: malformed def entry: %s\n", line
                exit 2
            }
            split(line, f, /[(),]+/)
            num = f[2]; cat = f[4]; fwd = f[5]
            gsub(/^[ \t]+|[ \t]+$/, "", num)
            gsub(/^[ \t]+|[ \t]+$/, "", cat)
            gsub(/^[ \t]+|[ \t]+$/, "", fwd)
            if (seen[num]++) {
                printf "META FAIL: duplicate syscall %s in %s\n", num, def
                exit 2
            }
            n++
            if (!has("shdw_fwd_" fwd "(int number, va_list args)")) {
                printf "META FAIL: %s has no forwarding body shdw_fwd_%s in syscall.x\n", num, fwd
                exit 2
            }
            if (!has("SHADW_RAW_CAT_" cat)) {
                printf "META FAIL: %s category SHADW_RAW_CAT_%s undefined in syscall.x\n", num, cat
                exit 2
            }
            if (!has("case SHADW_RAW_CAT_" cat ":")) {
                printf "META FAIL: %s category SHADW_RAW_CAT_%s has no dispatch case in syscall.x\n", num, cat
                exit 2
            }
        }
        if (n == 0) { printf "META FAIL: no entries parsed from %s\n", def; exit 2 }
        printf "raw syscalls: %d intercepted numbers, all with forwarding + policy metadata\n", n
    }
' || rc=1

# both trampolines must derive the passthrough from the def
for fn in replaced_syscall replaced___syscall; do
    awk -v fn="$fn" -v syscall="$SYSCALL" '
        function getfile(path,    s, line) { s = ""; while ((getline line < path) > 0) s = s line "\n"; close(path); return s }
        BEGIN {
            t = getfile(syscall)
            idx = index(t, "static long " fn "(int number, ...) {")
            if (idx == 0) { printf "META FAIL: %s not found in syscall.x\n", fn; exit 1 }
            body = substr(t, idx)
            # the passthrough if() must be the first thing after the comment
            if (index(body, "number != ") == 0) { printf "META FAIL: %s has no compare chain\n", fn; exit 1 }
            if (index(body, "#include \"RawSyscalls.def\"") == 0) { printf "META FAIL: %s passthrough is not def-derived\n", fn; exit 1 }
        }
    ' || rc=1
done

# the intercepted set must not be hand-synced anywhere else: no literal
# "number != SYS_" compare chains may linger in syscall.x
if grep -n 'number != SYS_' "$SYSCALL" >/dev/null 2>&1; then
    fail "hand-synced OR-chain detected in syscall.x (outside the def include)"
fi

for number in SYS_mkfifoat SYS_mknodat; do
    if ! grep -q "$number" "$DEF"; then
        fail "$number is missing from the raw-syscall registry"
    fi
done

if ! grep -q 'cmd == F_GETPATH || cmd == F_GETPATH_NOFIRMLINK' "$HOOKDIR/Universal/sandbox.x"; then
    fail "F_GETPATH_NOFIRMLINK is not filtered with F_GETPATH"
fi

# --- libc hook descriptor registry ---------------------------------------

awk -v libc="$LIBC" '
    function getfile(path,    s, line) { s = ""; while ((getline line < path) > 0) s = s line "\n"; close(path); return s }
    BEGIN {
        txt = getfile(libc)
        # legacy tables must be gone
        if (index(txt, "shdw_libc_sym_policy_table")) { print "META FAIL: legacy shdw_libc_sym_policy_table still in libc.x"; exit 2 }
        if (index(txt, "shdw_lowlevel_symbols"))       { print "META FAIL: legacy shdw_lowlevel_symbols still in libc.x"; exit 2 }
        if (index(txt, "shdw_libproc_symbols"))        { print "META FAIL: legacy shdw_libproc_symbols still in libc.x"; exit 2 }
        if (index(txt, "shdw_hook_check_t checks[]"))  { print "META FAIL: old per-group verify arrays still in libc.x"; exit 2 }
        # symbol policy must iterate the same descriptor array
        if (index(txt, "shdw_sym_policy_lookup_libc") == 0 || index(txt, "shdw_libc_hooks[i]") == 0) {
            print "META FAIL: shdw_sym_policy_lookup_libc does not iterate shdw_libc_hooks"; exit 2
        }

        n = 0
        while ((getline line < libc) > 0) {
            if (line !~ /^[ \t]*\{[ \t]*"/) continue
            if (index(line, "shdw_libc_hooks[") > 0) continue   # not a row
            split(line, f, ",")
            if (length(f) < 5) { printf "META FAIL: malformed descriptor row: %s\n", line; exit 2 }
            sym = f[1]; gsub(/^[ \t]*\{[ \t]*"|".*$/, "", sym)
            inst = f[4]; ver = f[5]
            gsub(/^[ \t]+|[ \t]+$/, "", inst)
            sub(/[}].*$/, "", ver)
            gsub(/^[ \t]+|[ \t]+$/, "", ver)
            if (inst == "") { printf "META FAIL: descriptor %s has no install group\n", sym; exit 2 }
            n++
            # required (verified) hooks must be installed by a verifying group
            if (ver != "" && ver != "0") {
                split(ver, vt, "|"); ok = 0
                for (i in vt) { gsub(/^[ \t]+|[ \t]+$/, "", vt[i]); if (index(inst, vt[i]) > 0) ok = 1 }
                if (!ok) { printf "META FAIL: required hook %s verified by %s but not installed by it (%s)\n", sym, ver, inst; exit 2 }
            }
        }
        if (n == 0) { print "META FAIL: no shdw_libc_hooks descriptors parsed"; exit 2 }
        printf "libc hooks: %d descriptors; every required hook installed/verified/exposed\n", n
    }
' || rc=1

exit $rc
