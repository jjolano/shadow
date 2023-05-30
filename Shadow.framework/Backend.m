#import <Shadow/Core+Utilities.h>
#import <Shadow/Backend.h>
#import <Shadow/Ruleset.h>
#import <RootBridge.h>

#import "../common.h"

@implementation ShadowBackend

- (instancetype)init {
    if((self = [super init])) {
        cache_restricted = [NSCache new];
        rulesets = [[self class] _loadRulesets];
    }

    return self;
}

+ (NSArray<ShadowRuleset *> *)_loadRulesets {
    NSMutableArray<ShadowRuleset *>* result = [NSMutableArray new];

    NSURL* ruleset_path_url = [NSURL fileURLWithPath:[RootBridge getJBPath:@SHADOW_RULESETS] isDirectory:YES];
    NSArray* ruleset_urls = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:ruleset_path_url includingPropertiesForKeys:@[] options:0 error:nil];

    if(ruleset_urls) {
        for(NSURL* url in ruleset_urls) {
            ShadowRuleset* ruleset = [ShadowRuleset rulesetWithURL:url];

            if(ruleset) {
                NSDictionary* info = [[ruleset internalDictionary] objectForKey:@"RulesetInfo"];

                if(info) {
                    NSLog(@"[ShadowBackend] loaded ruleset: '%@' by %@ (%@)", [info objectForKey:@"Name"], [info objectForKey:@"Author"], url);
                } else {
                    NSLog(@"[ShadowBackend] loaded ruleset: %@", url);
                }

                [result addObject:ruleset];
            } else {
                NSLog(@"[ShadowBackend] failed to load ruleset: %@", url);
            }
        }
    }

    return [result copy];
}

- (BOOL)isPathRestricted:(NSString *)path {
    if(!path || [path length] == 0 || [path isEqualToString:@"/"] || ![path isAbsolutePath]) {
        return NO;
    }

    NSNumber* cached = [cache_restricted objectForKey:path];

    if(cached) {
        return [cached boolValue];
    }

    __block BOOL compliant = YES;
    __block BOOL blacklisted = NO;
    __block BOOL whitelisted = NO;

    // Check rulesets
    [rulesets enumerateObjectsWithOptions:NSEnumerationConcurrent usingBlock:^(ShadowRuleset* ruleset, NSUInteger idx, BOOL* stop) {
        if(![ruleset isPathCompliant:path]) {
            compliant = NO;
            *stop = YES;
        } else {
            if([ruleset isPathWhitelisted:path]) {
                whitelisted = YES;
                *stop = YES;
            } else {
                if([ruleset isPathBlacklisted:path]) {
                    blacklisted = YES;
                }
            }
        }
    }];

    BOOL restricted = !compliant || (blacklisted && !whitelisted);

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

    // Add some exceptions
    NSArray* exceptions = @[@"file", @"http", @"https"];

    if([exceptions containsObject:scheme]) {
        return NO;
    }

    __block BOOL restricted = NO;

    // Check rulesets
    [rulesets enumerateObjectsWithOptions:NSEnumerationConcurrent usingBlock:^(ShadowRuleset* ruleset, NSUInteger idx, BOOL* stop) {
        if([ruleset isSchemeRestricted:scheme]) {
            restricted = YES;
            *stop = YES;
        }
    }];

    return restricted;
}
@end
