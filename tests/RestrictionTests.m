// Public restriction-interface and restricted-range tests.

#import <Foundation/Foundation.h>
#import <Shadow.h>
#import <Shadow/Core.h>
#import "ranges.h"

#import <stdio.h>

static int rg = 0;
static int rf = 0;

#define RCHECK(_cond, _name) do { \
    if(_cond) { rg++; } else { rf++; printf("FAIL: %s\n", _name); } \
} while(0)

static NSDictionary* writeOpts(void) {
    return @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};
}

static void RunRestrictedRangeTests(void) {
    shdw_restricted_ranges_t t = { .count = 2, .overflowed = 0, .generation = 7 };
    t.range[0] = (shdw_range_t){ .base = 0x1000, .end = 0x2000 };
    t.range[1] = (shdw_range_t){ .base = 0x8000, .end = 0x9000 };

    RCHECK(shdw_ranges_lookup(&t, 7, 0x1000) == SHDW_RANGE_YES, "ranges: first byte is inside");
    RCHECK(shdw_ranges_lookup(&t, 7, 0x1fff) == SHDW_RANGE_YES, "ranges: last byte is inside");
    RCHECK(shdw_ranges_lookup(&t, 7, 0x8500) == SHDW_RANGE_YES, "ranges: second range searched");
    RCHECK(shdw_ranges_lookup(&t, 7, 0x2000) == SHDW_RANGE_NO, "ranges: end is exclusive");
    RCHECK(shdw_ranges_lookup(&t, 7, 0x4000) == SHDW_RANGE_NO, "ranges: gap is outside");
    RCHECK(shdw_ranges_lookup(&t, 7, 0) == SHDW_RANGE_NO, "ranges: NULL is outside");
    RCHECK(shdw_ranges_lookup(&t, 8, 0x1000) == SHDW_RANGE_UNKNOWN, "ranges: stale hit is unknown");
    RCHECK(shdw_ranges_lookup(&t, 8, 0x4000) == SHDW_RANGE_UNKNOWN, "ranges: stale miss is unknown");

    shdw_restricted_ranges_t over = t;
    over.overflowed = 1;
    RCHECK(shdw_ranges_lookup(&over, 7, 0x4000) == SHDW_RANGE_UNKNOWN, "ranges: overflowed miss is unknown");
    RCHECK(shdw_ranges_lookup(&over, 7, 0x1000) == SHDW_RANGE_UNKNOWN, "ranges: overflowed hit is unknown");

    shdw_restricted_ranges_t empty = { .count = 0, .overflowed = 0, .generation = 7 };
    RCHECK(shdw_ranges_lookup(&empty, 7, 0x1000) == SHDW_RANGE_NO, "ranges: empty table restricts nothing");
    RCHECK(shdw_ranges_lookup(NULL, 7, 0x1000) == SHDW_RANGE_UNKNOWN, "ranges: absent table is unknown");
}

int RunRestrictionTests(void) {
    Shadow* shadow = [Shadow sharedInstance];

    RCHECK(![shadow isPathRestricted:nil], "nil path allowed");
    RCHECK(![shadow isPathRestricted:@""], "empty path allowed");
    RCHECK(![shadow isPathRestricted:@"/"], "root allowed");
    RCHECK(![shadow isPathRestricted:@"~definitely-not-a-user/foo"], "unresolvable tilde allowed");

    RCHECK([shadow isPathRestricted:@"/usr/sbin/fstab"], "blacklisted fstab restricted");
    RCHECK(![shadow isPathRestricted:@"/usr/bin/ssh"], "whitelist overrides blacklist");
    RCHECK(![shadow isPathRestricted:@"/usr/lib/libghost.dylib"], "absent exact-file read allowed");
    RCHECK([shadow isPathRestricted:@"/usr/lib/libghost.dylib" options:writeOpts()], "absent exact-file write denied");
    RCHECK([shadow isURLRestricted:[NSURL fileURLWithPath:@"/usr/lib/libghost.dylib"] options:writeOpts()], "URL write denied");

    RCHECK([shadow isPathRestricted:@"fstab" options:@{kShadowRestrictionWorkingDir : @"/usr/sbin"}], "relative fstab restricted");
    RCHECK(![shadow isPathRestricted:@"ssh" options:@{kShadowRestrictionWorkingDir : @"/usr/bin"}], "relative ssh whitelisted");
    RCHECK([shadow isPathRestricted:@"/usr/sbin/fstab" options:@{kShadowRestrictionWorkingDir : @"/"}], "working directory ignored for absolute path");
    RCHECK([shadow isPathRestricted:@"/usr/sbin/fstab" options:@{kShadowRestrictionEnableResolve : @NO}], "resolve-off restriction preserved");
    RCHECK([shadow isPathRestricted:@"/usr/sbin/fstab" options:@{kShadowRestrictionNoFollow : @YES}], "no-follow restriction preserved");

    RunRestrictedRangeTests();
    printf("RestrictionTests: %d passed, %d failed\n", rg, rf);
    return rf;
}
