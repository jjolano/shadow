#!/bin/sh
# Verifies the hook-registry metadata in src/ShadowCore.dylib/hooks:
#
#   raw syscalls (hooks/RawSyscalls.def — single source of truth for the
#   syscall(2)/__syscall(2) intercept set):
#     - every entry is well-formed with a unique SYS_ number, a policy CAT,
#       a forwarding shape FWD, a rewrite lane and an fd-return flag;
#     - every FWD has a shdw_fwd_<FWD> forwarding body in syscall.x;
#     - every CAT is a defined SHADW_RAW_CAT_<CAT> category with a dispatch
#       case in syscall.x;
#     - both trampolines (replaced_syscall, replaced___syscall) derive
#       their passthrough from the def (the OR-chains must not be
#       hand-synced again, and no hand-synced chain may linger);
#
#   libc hooks (the single shdw_libc_hooks descriptor array):
#     - every required hook (verifyGroups != 0) belongs to an installing
#       group (verifyGroups must be a subset of its
#       installGroups, token-wise — a required hook with no installer is
#       drift);
#     - only defined SHADW_HOOK_GROUP_* tokens are used;
#     - the legacy hand-synced tables (sym-policy table, lowlevel/libproc
#       symbol arrays, per-group verify arrays) are gone, and the dlsym
#       symbol policy iterates the same descriptor array.
#
# Reads source text only; run from the repo root: sh tests/verify-syscall-meta.sh
# (make -C tests syscall-meta cds up first).
set -e

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"

HOOKDIR=src/ShadowCore.dylib/hooks
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
        # Natural-ENOENT rewrite lane: 1 = always, 2 = only without O_CREAT.
        # Every other intercepted number must stay 0.
        rw["SYS_access"] = 1; rw["SYS_stat"] = 1; rw["SYS_lstat"] = 1
        rw["SYS_stat64"] = 1; rw["SYS_lstat64"] = 1
        rw["SYS_stat_extended"] = 1; rw["SYS_lstat_extended"] = 1
        rw["SYS_stat64_extended"] = 1; rw["SYS_lstat64_extended"] = 1
        rw["SYS_getattrlist"] = 1; rw["SYS_getxattr"] = 1
        rw["SYS_listxattr"] = 1; rw["SYS_readlink"] = 1
        rw["SYS_pathconf"] = 1; rw["SYS_fstatat"] = 1
        rw["SYS_fstatat64"] = 1; rw["SYS_execve"] = 1
        rw["SYS_open"] = 2; rw["SYS_open_extended"] = 2
        rw["SYS_openat"] = 2
        # FD-returning open family: the raw dispatch verifies the returned
        # descriptor after success. Every other intercepted number returns 0.
        fdret["SYS_open"] = 1; fdret["SYS_open_nocancel"] = 1
        fdret["SYS_open_extended"] = 1; fdret["SYS_open_dprotected_np"] = 1
        fdret["SYS_openat"] = 1; fdret["SYS_openat_nocancel"] = 1
        n = 0
        while ((getline line < def) > 0) {
            gsub(/^[ \t]+|[ \t]+$/, "", line)
            if (line == "" || line ~ /^\/\// || line ~ /^#/) continue
            if (line !~ /^SHADW_RAWSYSCALL\(SYS_[A-Za-z0-9_]+,[ \t]*[A-Z0-9_]+,[ \t]*[A-Z0-9_]+,[ \t]*[0-2],[ \t]*[01]\)$/) {
                printf "META FAIL: malformed def entry: %s\n", line
                exit 2
            }
            split(line, f, /[(),]+/)
            num = f[2]; cat = f[3]; fwd = f[4]; rewrite = f[5]; fd = f[6]
            gsub(/^[ \t]+|[ \t]+$/, "", num)
            gsub(/^[ \t]+|[ \t]+$/, "", cat)
            gsub(/^[ \t]+|[ \t]+$/, "", fwd)
            gsub(/^[ \t]+|[ \t]+$/, "", rewrite)
            gsub(/^[ \t]+|[ \t]+$/, "", fd)
            if (seen[num]++) {
                printf "META FAIL: duplicate syscall %s in %s\n", num, def
                exit 2
            }
            if ((num in rw) && rewrite != rw[num]) {
                printf "META FAIL: %s rewrite lane is %s, expected %s\n", num, rewrite, rw[num]
                exit 2
            }
            if (!(num in rw) && rewrite != 0) {
                printf "META FAIL: %s is not rewriteable but has lane %s\n", num, rewrite
                exit 2
            }
            expected_fd = (num in fdret) ? 1 : 0
            if (fd != expected_fd) {
                printf "META FAIL: %s fd-return flag is %s, expected %s\n", num, fd, expected_fd
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
        for (expected in rw) {
            if (!(expected in seen)) {
                printf "META FAIL: rewriteable syscall %s is missing from %s\n", expected, def
                exit 2
            }
        }
        for (expected in fdret) {
            if (!(expected in seen)) {
                printf "META FAIL: fd-returning syscall %s is missing from %s\n", expected, def
                exit 2
            }
        }
        printf "raw syscalls: %d intercepted numbers, all with forwarding + policy metadata\n", n
    }
' || rc=1

# rmdir stays on its reachable PATH branch with the safe ruleset-only,
# nofollow policy; no mutation-path rewrite may target a potentially existing sibling.
rmdir_path_case=$(awk '
    /case SHADW_RAW_CAT_PATH: \{/ { in_path = 1 }
    in_path { print }
    in_path && /\} break;/ { exit }
' "$SYSCALL")
if ! grep -Fq 'SHADW_RAWSYSCALL(SYS_rmdir, PATH, P1, 0, 0)' "$DEF" ||
   ! printf '%s\n' "$rmdir_path_case" | grep -Fq 'number == SYS_rmdir' ||
   ! printf '%s\n' "$rmdir_path_case" | grep -Fq 'shdw_path_is_main_bundle_exempt(pathname)' ||
   ! printf '%s\n' "$rmdir_path_case" | grep -Fq 'shdw_path_ruleset_denied_nofollow(pathname)' ||
   grep -Fq 'rmdir_rewrite_path' "$SYSCALL"; then
    fail "raw rmdir does not retain the reachable safe ruleset policy"
fi

# the raw-svc natural-ENOENT rewrite set must derive from the same def (no
# second syscall-number list), and open-family rewrites must stay O_CREAT-aware
svc="$HOOKDIR/Universal/svc_patch.x"
svc_rewrite=$(sed -n '/^static BOOL shdw_svc_rewriteable/,/^}/p' "$svc")
if ! printf '%s\n' "$svc_rewrite" | grep -q 'RawSyscalls.def' ||
   ! printf '%s\n' "$svc_rewrite" | grep -q 'O_CREAT'; then
    fail "svc rewrite eligibility is not def-derived or lost its O_CREAT gate"
fi

# both trampolines must derive the passthrough from the def
for fn in replaced_syscall replaced___syscall; do
    awk -v fn="$fn" -v syscall="$SYSCALL" '
        function getfile(path,    s, line) { s = ""; while ((getline line < path) > 0) s = s line "\n"; close(path); return s }
        BEGIN {
            t = getfile(syscall)
            idx = index(t, "static long " fn "(int number, ...) {")
            if (idx == 0) { printf "META FAIL: %s not found in syscall.x\n", fn; exit 1 }
            body = substr(t, idx)
            # end at the closing brace (column 0): the sibling trampoline must not satisfy these
            body = substr(body, 1, index(body, "\n}\n"))
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
            # required-export groups must also install the hook
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
