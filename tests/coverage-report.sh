#!/bin/sh
# Engine coverage report (runs inside the GNUstep container).
#
# Builds a gcov-instrumented harness, runs EVERY battery (unit rootless +
# rooted, adversary rootless + rooted, detector), then reports:
#   1. per-file line coverage of the decision-engine sources
#   2. per-method coverage of the engine entry points the hook layer
#      dispatches into, cross-referenced with the hooked-API groups each
#      method serves (from ShadowCore.dylib/hooks/*.x call sites).
#
# The hook layer itself (HookKit interposition) is device-only; what IS
# coverable is the engine every hook funnels into — a hooked API group is
# "covered" when the engine methods it calls are exercised by the harness.

set -e

GCOV="llvm-cov-18 gcov"

rm -f tests/*.gcda tests/*.gcno tests/*.gcov
sh tests/build-linux.sh --coverage

echo "running batteries (coverage build)..."
tests/harness --rootless > /dev/null
tests/harness --rooted > /dev/null
tests/harness --rootless --adversary > /dev/null
tests/harness --rooted --adversary > /dev/null
tests/harness --rootless --detector > /dev/null
tests/harness --rootless --benign > /dev/null

echo
echo "=== engine methods vs hooked API groups ==="
# Hook-group mapping is from the actual call sites in ShadowCore.dylib/hooks/.
# method_percent: run gcov -f and pair each "Function 'name'" with the
# "Lines executed" summary that follows it. The .gcov outputs go to a
# scratch dir so they never pollute the repo.
mkdir -p /tmp/covout
method_percent() {
    (cd /tmp/covout && $GCOV -o "/src/tests/harness-$1" -f "/src/Shadow.framework/$1.m" 2>/dev/null) \
        | awk -v pat="$2" '
            /^Function .*/ { fn = $0 }
            /^Lines executed/ && fn ~ pat { print $2; found = 1; exit }
            END { if(!found) print "unexecuted" }'
}

report() { # file, gcov pattern, label, hook groups
    pct=$(method_percent "$1" "$2")
    echo "  $3: $pct  [$4]"
}

report Core.m "isCPathRestricted" "isCPathRestricted" "libc, libc_lowlevel, dyld, sandbox, syscall"
report Core.m "isPathRestricted:options" "isPathRestricted:options:" "libc, libc_lowlevel, dyld, sandbox, syscall, NSFileManager, NSString, NSData, NSArray, NSDictionary, NSFileHandle, NSBundle, NSProcessInfo, UIImage"
report Core.m "isURLRestricted:options" "isURLRestricted:options:" "NSFileManager, NSURL, NSString, NSData, NSArray, NSDictionary, NSFileHandle, NSFileVersion, NSFileWrapper, NSBundle, LSApplicationWorkspace, UIApplication"
report Core.m "isSchemeRestricted" "isSchemeRestricted" "LSApplicationWorkspace"
report Core.m "isBundleIDRestricted" "isBundleIDRestricted" "LSApplicationWorkspace"
report Core.m "isProtectedImagePath" "isProtectedImagePath" "dyld, objc, NSBundle, UIImage"
report Core.m "isAddrRestricted" "isAddrRestricted" "dyld, objc, mem, sandbox, NSThread, NSBundle"
report Core.m "evaluatePathRestriction" "evaluatePathRestriction" "internal (all path lanes)"
report Core+Utilities.m "filterPathArray" "filterPathArray" "NSFileManager"
report Core+Utilities.m "fileNoSuchFileErrorForPath" "fileNoSuchFileErrorForPath:" "NSFileManager, NSURL, NSArray, NSData, NSDictionary, NSFileHandle, NSFileVersion, NSFileWrapper, NSBundle"
report Core+Utilities.m "getStandardizedPath" "getStandardizedPath" "internal (all path lanes)"
report Core+Utilities.m "generateDatabase" "generateDatabase" "SystemRules/shadowd (no hook file)"
report Backend.m "isPathRestricted" "isPathRestricted" "backend path engine"
report Backend.m "isSchemeRestricted" "isSchemeRestricted" "backend scheme engine"
report Backend.m "isBundleIDRestricted" "isBundleIDRestricted" "backend bundle-id engine"
report Backend.m "_checkRulesetChanges" "_checkRulesetChanges" "reload path"
report Ruleset.m "isPathCompliant" "isPathCompliant" "ruleset compliance"
report Ruleset.m "isPathWhitelisted" "isPathWhitelisted" "ruleset whitelist"
report Ruleset.m "isPathBlacklisted" "isPathBlacklisted" "ruleset blacklist"
report Ruleset.m "rulesetWithURL" "rulesetWithURL" "ruleset load/reload"

echo
echo "note: % = executed lines of the method; unexecuted = method never reached by any battery"
