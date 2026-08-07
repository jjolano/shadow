#import <Shadow/Core+Utilities.h>
#import <Shadow/Backend.h>
#import <Shadow/Ruleset.h>
#import <RootBridge.h>

#import "../common.h"

#import <stdatomic.h>

// Last time the ruleset dir was scanned. Atomic: multiple hook threads race the
// 1s gate, and a plain double lets several of them scan the same interval.
static _Atomic(double) lastRulesetCheck = 0.0;

@interface ShadowBackend () {
    // Sorted ruleset URLs from the last load; the per-second change check
    // stats these cached URLs instead of re-enumerating + re-sorting the dir.
    NSArray<NSURL *>* rulesetURLs;
}
@end

@implementation ShadowBackend

- (instancetype)init {
    if((self = [super init])) {
        cache_restricted = [NSCache new];
        // 1024 entries ≈ tens of KB: the queried-path working set plus its
        // cached ancestors is a few hundred in practice, so this bounds memory
        // without thrashing the hot path.
        [cache_restricted setCountLimit:1024];
        rulesets = [self _loadRulesets];
    }

    return self;
}

- (double)_fileMtime:(NSString *)path {
    NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    NSDate* mod_date = [attrs fileModificationDate];

    return mod_date ? [mod_date timeIntervalSinceReferenceDate] : 0.0;
}

- (NSArray<RulesetEngine *>*)_loadRulesets {
    // C0-2: these are Shadow's own file reads (dir listing, plist loads,
    // mtime stats). Without the internal scope the tweak's own
    // NSFileManager/NSDictionary hooks would filter them — and once
    // /Library/Shadow is itself a restricted path (C0-5), Shadow would deny
    // itself its own rulesets. The scope flag is read by the hook layer via
    // +[Shadow shdwIsInternalRead]; nested scopes (via _reloadRulesets) are
    // depth-counted in Core.m.
    SHADOW_INTERNAL_SCOPE;

    NSMutableArray<RulesetEngine *>* result = [NSMutableArray new];
    NSMutableArray<NSNumber *>* mtimes = [NSMutableArray new];

    NSFileManager* fm = [NSFileManager defaultManager];
    NSString* dir = [RootBridge getJBPath:@SHADOW_RULESETS];

    rulesetDirMtime = [self _fileMtime:dir];

    NSArray* ruleset_urls = [fm contentsOfDirectoryAtURL:[NSURL fileURLWithPath:dir isDirectory:YES] includingPropertiesForKeys:@[] options:0 error:nil];

    if(ruleset_urls) {
        // Sort by file name so both load order and the mtime snapshot are deterministic.
        ruleset_urls = [ruleset_urls sortedArrayUsingComparator:^NSComparisonResult(NSURL* a, NSURL* b) {
            return [[a lastPathComponent] compare:[b lastPathComponent]];
        }];

        rulesetURLs = ruleset_urls;

        for(NSURL* url in ruleset_urls) {
            RulesetEngine* ruleset = [RulesetEngine rulesetWithURL:url];

            if(ruleset) {
                NSDictionary* info = [[ruleset payloadDictionary] objectForKey:@"RulesetInfo"];

                if(info) {
                    NSLog(@"[Backend] loaded ruleset: '%@' by %@ (%@)", [info objectForKey:@"Name"], [info objectForKey:@"Author"], url);
                } else {
                    NSLog(@"[Backend] loaded ruleset: %@", url);
                }

                [result addObject:ruleset];
            } else {
                NSLog(@"[Backend] failed to load ruleset: %@", url);
            }

            // Snapshot every file in the dir (all plists load; a stray non-plist is still tracked so its rewrite is caught).
            [mtimes addObject:@([self _fileMtime:[url path]])];
        }
    }

    rulesetFileMtimes = [mtimes copy];

    // Rulesets were just (re)loaded; don't re-scan on the first decision.
    atomic_store_explicit(&lastRulesetCheck, [NSDate timeIntervalSinceReferenceDate], memory_order_release);
    return [result copy];
}

- (void)_reloadRulesets {
    rulesets = [self _loadRulesets];
    rulesetGeneration += 1;
    [cache_restricted removeAllObjects];
}

- (void)_checkRulesetChanges {
    // C0-2: the dir/file mtime stats are Shadow's own reads — see
    // _loadRulesets. _reloadRulesets nests a _loadRulesets scope; the depth
    // counter in Core.m keeps the scope busy until this one exits.
    SHADOW_INTERNAL_SCOPE;

    double now = [NSDate timeIntervalSinceReferenceDate];
    double last = atomic_load_explicit(&lastRulesetCheck, memory_order_acquire);

    if(now - last < 1.0) {
        return;
    }

    // Claim this interval; exactly one thread scans per second.
    double expected = last;

    if(!atomic_compare_exchange_strong_explicit(&lastRulesetCheck, &expected, now, memory_order_acq_rel, memory_order_acquire)) {
        return;
    }

    NSString* dir = [RootBridge getJBPath:@SHADOW_RULESETS];

    // All ruleset files live directly in this dir and the generated ruleset is
    // written with atomically:YES (rename), so a dir-mtime change catches adds,
    // removes and renames. In-place edits don't touch the dir mtime and are
    // caught by the per-file stats on the cached URL list below.
    if([self _fileMtime:dir] != rulesetDirMtime) {
        [self _reloadRulesets];
        return;
    }

    NSArray<NSURL*>* urls = rulesetURLs;

    for(NSUInteger i = 0; i < [urls count]; i++) {
        if([self _fileMtime:[[urls objectAtIndex:i] path]] != [[rulesetFileMtimes objectAtIndex:i] doubleValue]) {
            [self _reloadRulesets];
            return;
        }
    }
}

- (BOOL)isPathRestricted:(NSString *)path {
    if(!path || [path length] == 0 || [path isEqualToString:@"/"] || ![path isAbsolutePath]) {
        return NO;
    }

    [self _checkRulesetChanges];

    NSUInteger gen = rulesetGeneration;

    // Header types this cache as <NSString *, NSArray *>; entries are packed
    // NSNumbers, so cast (header is public and unchanged).
    NSNumber* cached = (NSNumber *)[cache_restricted objectForKey:path];

    if(cached) {
        // Packed as (generation << 1) | restricted: one NSNumber per entry
        // instead of a 2-element array, with identical generation invalidation.
        unsigned long long v = [cached unsignedLongLongValue];

        if((NSUInteger)(v >> 1) == gen) {
            return (v & 1) != 0;
        }
    }

    // pass 1: compliance (hard veto)
    for(RulesetEngine* ruleset in rulesets) {
        if(![ruleset isPathCompliant:path]) {
            [cache_restricted setObject:(NSArray *)(id)@(((unsigned long long)gen << 1) | 1) forKey:path];
            return YES;
        }
    }

    // pass 2: whitelist
    BOOL whitelisted = NO;

    for(RulesetEngine* ruleset in rulesets) {
        if([ruleset isPathWhitelisted:path]) {
            whitelisted = YES;
            break;
        }
    }

    // pass 3: blacklist
    BOOL blacklisted = NO;

    for(RulesetEngine* ruleset in rulesets) {
        if([ruleset isPathBlacklisted:path]) {
            blacklisted = YES;
            break;
        }
    }

    BOOL restricted = blacklisted && !whitelisted;

    if(!restricted) {
        restricted = [self isPathRestricted:[path stringByDeletingLastPathComponent]];
    }

    [cache_restricted setObject:(NSArray *)(id)@(((unsigned long long)gen << 1) | (restricted ? 1 : 0)) forKey:path];
    return restricted;
}

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    if(!scheme || [scheme length] == 0) {
        return NO;
    }

    [self _checkRulesetChanges];

    // C0-3: compare case-insensitively — detectors probe case variants
    // ("Cydia", "SILEO") to dodge exact matches. Rulesets additionally
    // normalize their entries to lowercase at load (Ruleset.m _compile).
    NSString* scheme_lower = [scheme lowercaseString];

    // Add some exceptions (direct compares: no per-call array allocation).
    if([scheme_lower isEqualToString:@"file"] || [scheme_lower isEqualToString:@"http"] || [scheme_lower isEqualToString:@"https"]) {
        return NO;
    }

    BOOL restricted = NO;

    // Check rulesets
    for(RulesetEngine* ruleset in rulesets) {
        if([ruleset isSchemeRestricted:scheme_lower]) {
            restricted = YES;
            break;
        }
    }

    return restricted;
}

// C0-3: ruleset-driven bundle-ID check (the static well-known list lives in
// -[Shadow isBundleIDRestricted:], which consults this for the user-extensible
// half). Rulesets normalize their entries to lowercase at load.
- (BOOL)isBundleIDRestricted:(NSString *)bundleID {
    if(!bundleID || [bundleID length] == 0) {
        return NO;
    }

    [self _checkRulesetChanges];

    NSString* bundleID_lower = [bundleID lowercaseString];

    for(RulesetEngine* ruleset in rulesets) {
        if([ruleset isBundleIDRestricted:bundleID_lower]) {
            return YES;
        }
    }

    return NO;
}
@end
