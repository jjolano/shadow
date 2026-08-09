// Candidate 5 — RestrictionQuery typed entry + differential-parity tests.
//
// Self-contained host assertions (the tests/Makefile + build-linux.sh wiring
// is owned by the orchestrator; see the report's "exact lines to add").
// RunRestrictionTests() is called AFTER the harness has staged the fixture
// rulesets and the virtual FS. Staged ruleset state:
//   001-BaseRules.plist  blacklists /usr/sbin/fstab, /usr/bin/ssh and
//                        /usr/lib/libghost.dylib exactly (plus prefix rules)
//   002-Overrides.plist  whitelists /usr/bin/ssh exactly (whitelist beats the
//                        exact blacklist on the path itself), /usr/sbin/sshd
//                        and /var/mobile/Media as prefixes
// So in the running state /usr/sbin/fstab is RESTRICTED and /usr/bin/ssh is
// ALLOWED (main.m:357-358 asserts the same pair, pass/fail mirrored here).
// Virtual FS: fixtures/fs/jb/usr/{bin,sbin} exist (ssh, fstab); libghost
// doesn't.
//
// Two layers:
//   1. Grounded verdicts that hold in BOTH rooted and rootless modes
//      (write probes skip the existence gates — device-accurate; the read
//      probes are mode-independent by construction, see each check).
//   2. Differential-parity asserts: the typed entry must agree with the
//      legacy dictionary entry on every option shape, and — via KVC access
//      to the backend's engine (test-only category below) — the NEW engine
//      and the LEGACY engine inside the differential dispatcher must agree.
//      The harness builds the framework sources with -DDEBUG, so any engine
//      divergence ALSO prints "[Shadow] DIFFERENTIAL MISMATCH" to stderr —
//      the orchestrator can grep the harness output for that string.
//
// Returns the number of failures (0 = clean).

#import <Foundation/Foundation.h>
#import <Shadow.h>
#import <Shadow/Core.h>
#import <Shadow/RestrictionQuery.h>
#import <Shadow/Backend.h>
#import "RestrictionEngine.h"

#import <stdio.h>

static int rg = 0;
static int rf = 0;

#define RCHECK(_cond, _name) do { \
    if(_cond) { rg++; } else { rf++; printf("FAIL: %s\n", _name); } \
} while(0)

static Shadow* shdw(void) {
    return [Shadow sharedInstance];
}

static NSDictionary* writeOpts(void) {
    return @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};
}

// Test-only access to the differential internals (implementation methods; the
// dispatcher runs both engines per query, this lets the test assert agreement
// directly with the divergence context).
@interface ShadowRestrictionEngine (RestrictionTestsAccess)
- (BOOL)_legacyPathRestrictedQuery:(ShadowRestrictionQuery *)query;
- (BOOL)_newPathRestrictedQuery:(ShadowRestrictionQuery *)query;
@end

static ShadowRestrictionEngine* engine(void) {
    ShadowBackend* backend = [shdw() valueForKey:@"backend"];
    return [backend valueForKey:@"engine"];
}

// Builds the typed query a legacy options dict translates to (mirrors
// shdwQueryFromOptions in Core.m).
static ShadowRestrictionQuery* queryFromDict(NSString* path, NSDictionary* options) {
    ShadowRestrictionQuery* query = [ShadowRestrictionQuery queryWithPath:path];

    if(!options) {
        return query;
    }

    id resolve = [options objectForKey:kShadowRestrictionEnableResolve];

    if(resolve && ![resolve boolValue]) {
        query.flags &= ~ShadowRestrictionFlagResolve;
    }

    if([[options objectForKey:kShadowRestrictionNoFollow] boolValue]) {
        query.flags |= ShadowRestrictionFlagNoFollow;
    }

    if([[options objectForKey:kShadowRestrictionOperation] isEqualToString:kShadowRestrictionOpWrite]) {
        query.operation = ShadowRestrictionOperationWrite;
    }

    NSString* wd = [options objectForKey:kShadowRestrictionWorkingDir];

    if(wd) {
        query.workingDirectory = wd;
    }

    return query;
}

int RunRestrictionTests(void) {
    Shadow* shadow = shdw();
    ShadowRestrictionEngine* eng = engine();

    RCHECK(eng != nil, "engine reachable through backend");

    // --- typed entry: guard shapes -----------------------------------------
    RCHECK(![shadow isPathRestrictedQuery:nil], "typed nil query allowed");
    RCHECK(![shadow isPathRestrictedQuery:[ShadowRestrictionQuery queryWithPath:nil]], "typed nil path allowed");
    RCHECK(![shadow isPathRestrictedQuery:[ShadowRestrictionQuery queryWithPath:@""]], "typed empty path allowed");
    RCHECK(![shadow isPathRestrictedQuery:[ShadowRestrictionQuery queryWithPath:@"/"]], "typed root allowed");
    RCHECK(![shadow isPathRestrictedQuery:[ShadowRestrictionQuery queryWithPath:@"~definitely-not-a-user/foo"]], "typed unresolvable tilde allowed");

    // --- grounded verdicts (both modes; see file header) ------------------
    // /usr/sbin/fstab: blacklisted exactly (001) and NOT whitelisted (002
    // only whitelists the /usr/sbin/sshd prefix) — the canonical restricted
    // path in the staged state (mirrors main.m:357).
    BOOL fstabRestricted = [shadow isPathRestricted:@"/usr/sbin/fstab"];
    RCHECK(fstabRestricted, "typed /usr/sbin/fstab restricted");

    // /usr/bin/ssh: whitelisted exactly by 002-Overrides, which beats the
    // exact blacklist on the path itself (mirrors main.m:358).
    RCHECK(![shadow isPathRestricted:@"/usr/bin/ssh"], "whitelist exact overrides blacklist exact (002-Overrides)");

    RCHECK(![shadow isPathRestricted:@"/usr/lib/libghost.dylib"], "absent exact-file read allowed (existence gate)");
    RCHECK([shadow isPathRestricted:@"/usr/lib/libghost.dylib" options:writeOpts()], "absent exact-file write denied (gate-skipping)");
    RCHECK([shadow isURLRestricted:[NSURL fileURLWithPath:@"/usr/lib/libghost.dylib"] options:writeOpts()], "absent exact-file URL write denied");

    // working-dir relative resolution: fstab exists in the jb fixture tree,
    // so the rootless existence gate passes and the exact blacklist applies
    // in both modes.
    RCHECK([shadow isPathRestricted:@"fstab" options:@{kShadowRestrictionWorkingDir : @"/usr/sbin"}], "relative fstab via workingDir restricted");
    RCHECK(![shadow isPathRestricted:@"ssh" options:@{kShadowRestrictionWorkingDir : @"/usr/bin"}], "relative ssh via workingDir resolves to whitelisted /usr/bin/ssh");
    RCHECK([shadow isPathRestricted:@"/usr/sbin/fstab" options:@{kShadowRestrictionWorkingDir : @"/"}], "workingDir inert for absolute path");

    // --- legacy dict <-> typed entry parity (every option shape) ----------
    NSArray* paths = @[
        @"/usr/bin/ssh",
        @"/usr/sbin/fstab",
        @"/usr/lib/libghost.dylib",
        @"/var/mobile/Media/DCIM/1.jpg",
        @"fstab",
        @"ssh",
        @"Library/Preferences/x",
        @"~/../var/jb/usr/bin/ssh",
        @"/"
    ];

    NSArray* optionShapes = @[
        [NSNull null],                                            // nil options
        @{},                                                      // empty options
        @{kShadowRestrictionOperation : kShadowRestrictionOpWrite},
        @{kShadowRestrictionWorkingDir : @"/usr/sbin"},
        @{kShadowRestrictionWorkingDir : @"/usr/bin"},
        @{kShadowRestrictionWorkingDir : @"/"},
        @{kShadowRestrictionNoFollow : @YES},
        @{kShadowRestrictionEnableResolve : @NO},
        @{kShadowRestrictionOperation : kShadowRestrictionOpWrite,
          kShadowRestrictionWorkingDir : @"/var/jb"},
        @{kShadowRestrictionNoFollow : @YES,
          kShadowRestrictionWorkingDir : @"/usr/bin"},
        @{kShadowRestrictionEnableResolve : @NO,
          kShadowRestrictionOperation : kShadowRestrictionOpWrite}
    ];

    for(NSString* path in paths) {
        for(id shape in optionShapes) {
            NSDictionary* options = ([shape isKindOfClass:[NSNull class]]) ? nil : shape;
            BOOL viaDict = [shadow isPathRestricted:path options:options];
            BOOL viaTyped = [shadow isPathRestrictedQuery:queryFromDict(path, options)];
            RCHECK((viaDict == viaTyped), ([[NSString stringWithFormat:@"dict/typed parity: %@ %@", path, options ?: @"(nil)"] UTF8String]));

            // Differential agreement of the two engines for the same query
            // (the plan's DEBUG differential, asserted directly; the legacy
            // engine is authoritative, so a divergence here is a finding).
            ShadowRestrictionQuery* q = queryFromDict(path, options);
            BOOL legacy = [eng _legacyPathRestrictedQuery:q];
            BOOL fresh = [eng _newPathRestrictedQuery:q];
            RCHECK((legacy == fresh), ([[NSString stringWithFormat:@"engine parity: %@ %@ (legacy=%d fresh=%d)", path, options ?: @"(nil)", legacy, fresh] UTF8String]));
        }
    }

    // --- typed-native usage: defaults match the facade ---------------------
    RCHECK([shadow isPathRestrictedQuery:[ShadowRestrictionQuery queryWithPath:@"/usr/sbin/fstab"]] == fstabRestricted,
        "typed defaults == plain read");

    // Default-shaped queries are cacheable; explicit resolve-off queries are
    // not (legacy parity) — both must still agree with the facade verdict.
    ShadowRestrictionQuery* noResolve = [ShadowRestrictionQuery queryWithPath:@"/usr/sbin/fstab"];
    noResolve.flags = 0;
    RCHECK([shadow isPathRestrictedQuery:noResolve] == fstabRestricted, "resolve-off typed query agrees");

    printf("RestrictionTests: %d passed, %d failed\n", rg, rf);
    return rf;
}