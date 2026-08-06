#import <Shadow/Core+Utilities.h>
#import <Shadow/Backend.h>
#import <Shadow/Ruleset.h>
#import <RootBridge.h>

#import "../common.h"

static double lastRulesetCheck = 0.0;

@implementation ShadowBackend

- (instancetype)init {
    if((self = [super init])) {
        cache_restricted = [NSCache new];
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
    return [result copy];
}

- (void)_reloadRulesets {
    rulesets = [self _loadRulesets];
    [cache_restricted removeAllObjects];
}

- (void)_checkRulesetChanges {
    double now = [NSDate timeIntervalSinceReferenceDate];

    if(now - lastRulesetCheck < 1.0) {
        return;
    }

    lastRulesetCheck = now;

    NSFileManager* fm = [NSFileManager defaultManager];
    NSString* dir = [RootBridge getJBPath:@SHADOW_RULESETS];

    if([self _fileMtime:dir] != rulesetDirMtime) {
        [self _reloadRulesets];
        return;
    }

    NSArray* urls = [fm contentsOfDirectoryAtURL:[NSURL fileURLWithPath:dir isDirectory:YES] includingPropertiesForKeys:@[] options:0 error:nil];

    if(!urls || [urls count] != [rulesetFileMtimes count]) {
        [self _reloadRulesets];
        return;
    }

    urls = [urls sortedArrayUsingComparator:^NSComparisonResult(NSURL* a, NSURL* b) {
        return [[a lastPathComponent] compare:[b lastPathComponent]];
    }];

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

    NSNumber* cached = [cache_restricted objectForKey:path];

    if(cached) {
        return [cached boolValue];
    }

    // pass 1: compliance (hard veto)
    for(RulesetEngine* ruleset in rulesets) {
        if(![ruleset isPathCompliant:path]) {
            [cache_restricted setObject:@(YES) forKey:path];
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

    [cache_restricted setObject:@(restricted) forKey:path];
    return restricted;
}

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    if(!scheme || [scheme length] == 0) {
        return NO;
    }

    [self _checkRulesetChanges];

    // Add some exceptions
    NSArray* exceptions = @[@"file", @"http", @"https"];

    if([exceptions containsObject:scheme]) {
        return NO;
    }

    BOOL restricted = NO;

    // Check rulesets
    for(RulesetEngine* ruleset in rulesets) {
        if([ruleset isSchemeRestricted:scheme]) {
            restricted = YES;
            break;
        }
    }

    return restricted;
}
@end
