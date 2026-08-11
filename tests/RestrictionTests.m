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
// Three layers:
//   1. Grounded verdicts that hold in BOTH rooted and rootless modes
//      (write probes skip the existence gates — device-accurate; the read
//      probes are mode-independent by construction, see each check).
//   2. Parity asserts: the typed entry must agree with the dictionary entry on
//      every option shape, and both must agree with the engine's own evaluator
//      reached by KVC (test-only category below) — the option translation and
//      the decision caches must never change a verdict.
//   3. The restricted image range table's lookup (RunRestrictedRangeTests).
//
// These asserts carried the Candidate 5 cutover: they compared the legacy and
// resolver engines until parity held, and the legacy engine was then deleted.
//
// Returns the number of failures (0 = clean).

#import <Foundation/Foundation.h>
#import <Shadow.h>
#import <Shadow/Core.h>
#import <Shadow/RestrictionQuery.h>
#import <Shadow/Backend.h>
#import "RestrictionEngine.h"
#import "ranges.h"

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

// Test-only access to the engine's implementation entry point, so a verdict
// can be asserted against the evaluator directly and not only through the
// facade's caching/translation layers.
@interface ShadowRestrictionEngine (RestrictionTestsAccess)
- (BOOL)_newPathRestrictedQuery:(ShadowRestrictionQuery *)query;
@end

static ShadowRestrictionEngine* engine(void) {
    ShadowBackend* backend = [shdw() valueForKey:@"backend"];
    return [backend valueForKey:@"engine"];
}

// --- restricted image range table ------------------------------------------
// The dylib answers -[Shadow isAddrRestricted:] from a snapshot of restricted
// image spans instead of re-resolving and re-judging the image path on every
// intercepted call. shdw_ranges_lookup is the whole decision; the dylib only
// wraps it with the atomics and the fallback. It is plain C over ranges.h, so
// it is testable here without any of hooks.h's iOS-only dependencies.
//
// The two UNKNOWN cases are what matter: both mean "answer from the real
// predicate instead", and getting either wrong silently under-reports
// restricted addresses — the unsafe direction.
static void RunRestrictedRangeTests(void) {
    shdw_restricted_ranges_t t = { .count = 2, .overflowed = 0, .generation = 7 };
    t.range[0] = (shdw_range_t){ .base = 0x1000, .end = 0x2000 };
    t.range[1] = (shdw_range_t){ .base = 0x8000, .end = 0x9000 };

    RCHECK(shdw_ranges_lookup(&t, 7, 0x1000) == SHDW_RANGE_YES, "ranges: first byte of a range is inside");
    RCHECK(shdw_ranges_lookup(&t, 7, 0x1fff) == SHDW_RANGE_YES, "ranges: last byte of a range is inside");
    RCHECK(shdw_ranges_lookup(&t, 7, 0x8500) == SHDW_RANGE_YES, "ranges: second range is searched too");
    RCHECK(shdw_ranges_lookup(&t, 7, 0x2000) == SHDW_RANGE_NO, "ranges: end is exclusive");
    RCHECK(shdw_ranges_lookup(&t, 7, 0x4000) == SHDW_RANGE_NO, "ranges: address between ranges is outside");
    RCHECK(shdw_ranges_lookup(&t, 7, 0) == SHDW_RANGE_NO, "ranges: NULL is not restricted");

    // Stale stamp: a ruleset reload can flip an already-loaded image's verdict
    // without any image event, so entries classified under an older generation
    // must not be answered from.
    RCHECK(shdw_ranges_lookup(&t, 8, 0x1000) == SHDW_RANGE_UNKNOWN, "ranges: older generation is unusable");
    RCHECK(shdw_ranges_lookup(&t, 8, 0x4000) == SHDW_RANGE_UNKNOWN, "ranges: stale table cannot answer misses either");

    // Truncated table: the missing entries would read as "not restricted".
    shdw_restricted_ranges_t over = t;
    over.overflowed = 1;
    RCHECK(shdw_ranges_lookup(&over, 7, 0x4000) == SHDW_RANGE_UNKNOWN, "ranges: overflowed table cannot answer");
    RCHECK(shdw_ranges_lookup(&over, 7, 0x1000) == SHDW_RANGE_UNKNOWN, "ranges: overflowed table cannot answer hits either");

    shdw_restricted_ranges_t empty = { .count = 0, .overflowed = 0, .generation = 7 };
    RCHECK(shdw_ranges_lookup(&empty, 7, 0x1000) == SHDW_RANGE_NO, "ranges: empty table restricts nothing");
    RCHECK(shdw_ranges_lookup(NULL, 7, 0x1000) == SHDW_RANGE_UNKNOWN, "ranges: absent table cannot answer");
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

            // The facade's answer must be the evaluator's answer: the layers
            // between them (option translation, the decision caches) must not
            // change a verdict for any option shape.
            ShadowRestrictionQuery* q = queryFromDict(path, options);
            BOOL direct = [eng _newPathRestrictedQuery:q];
            RCHECK((direct == viaTyped), ([[NSString stringWithFormat:@"facade/engine parity: %@ %@ (engine=%d facade=%d)", path, options ?: @"(nil)", direct, viaTyped] UTF8String]));
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

    RunRestrictedRangeTests();

    printf("RestrictionTests: %d passed, %d failed\n", rg, rf);
    return rf;
}