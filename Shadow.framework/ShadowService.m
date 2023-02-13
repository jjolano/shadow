#import "ShadowService.h"
#import "ShadowService+Restriction.h"
#import "ShadowService+Settings.h"

#import "../common.h"
#import "../vendor/rootless.h"

#import <AppSupport/CPDistributedMessagingCenter.h>

@implementation ShadowService {
    NSCache<NSString *, NSNumber *>* cache_restricted;
    NSCache<NSString *, NSNumber *>* cache_compliant;
    NSCache<NSString *, NSNumber *>* cache_urlscheme;

    NSArray* rulesets;
    CPDistributedMessagingCenter* center;
}

- (void)addRuleset:(NSDictionary *)ruleset {
    // Preprocess ruleset
    NSMutableDictionary* ruleset_processed = [ruleset mutableCopy];

    NSArray* wpred = [ruleset objectForKey:@"WhitelistPredicates"];
    NSArray* bpred = [ruleset objectForKey:@"BlacklistPredicates"];

    if(wpred && [wpred count]) {
        NSMutableArray* wpred_new = [NSMutableArray new];

        for(NSString* pred_str in wpred) {
            NSPredicate* pred = [NSPredicate predicateWithFormat:pred_str];
            [wpred_new addObject:pred];
        }

        NSPredicate* wpred_compound = [NSCompoundPredicate orPredicateWithSubpredicates:wpred_new];
        [ruleset_processed setObject:wpred_compound forKey:@"WhitelistPredicates"];
    }

    if(bpred && [bpred count]) {
        NSMutableArray* bpred_new = [NSMutableArray new];

        for(NSString* pred_str in bpred) {
            NSPredicate* pred = [NSPredicate predicateWithFormat:pred_str];
            [bpred_new addObject:pred];
        }

        NSPredicate* bpred_compound = [NSCompoundPredicate orPredicateWithSubpredicates:bpred_new];
        [ruleset_processed setObject:bpred_compound forKey:@"BlacklistPredicates"];
    }

    // Add processed ruleset to our class
    rulesets = [rulesets arrayByAddingObject:[ruleset_processed copy]];
}

- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo {
    NSDictionary* response = nil;

    if([name isEqualToString:@"resolvePath"]) {
        NSString* path = [userInfo objectForKey:@"path"];

        if(path) {
            response = @{
                @"path" : [path stringByStandardizingPath]
            };
        }
    } else if([name isEqualToString:@"isPathCompliant"]) {
        NSString* path = [userInfo objectForKey:@"path"];

        BOOL compliant = YES;

        if(path && [path isAbsolutePath]) {
            for(NSDictionary* ruleset in rulesets) {
                if(![[self class] isPathCompliant:path withRuleset:ruleset]) {
                    compliant = NO;
                    break;
                }
            }
        }

        response = @{
            @"compliant" : @(compliant)
        };
    } else if([name isEqualToString:@"isPathRestricted"]) {
        NSString* path = [userInfo objectForKey:@"path"];

        // Check if path is restricted.
        BOOL restricted = NO;

        if(path && [path isAbsolutePath]) {
            NSLog(@"%@: %@", name, path);

            // Check rulesets
            if(!restricted) {
                for(NSDictionary* ruleset in rulesets) {
                    if([[self class] isPathBlacklisted:path withRuleset:ruleset]) {
                        restricted = YES;
                        break;
                    }
                }
            }

            if(restricted) {
                for(NSDictionary* ruleset in rulesets) {
                    if([[self class] isPathWhitelisted:path withRuleset:ruleset]) {
                        restricted = NO;
                        break;
                    }
                }
            }
        }

        response = @{
            @"restricted" : @(restricted)
        };
    } else if([name isEqualToString:@"isURLSchemeRestricted"]) {
        NSString* scheme = [userInfo objectForKey:@"scheme"];

        BOOL restricted = NO;

        if(scheme) {
            // Check rulesets
            for(NSDictionary* ruleset in rulesets) {
                NSSet* bschemes = [ruleset objectForKey:@"BlacklistURLSchemes"];

                if([bschemes containsObject:scheme]) {
                    restricted = YES;
                    break;
                }
            }
        }

        response = @{
            @"restricted" : @(restricted)
        };
    } else if([name isEqualToString:@"getPreferences"]) {
        NSString* bundleIdentifier = [userInfo objectForKey:@"bundleIdentifier"];
        response = [[self class] getPreferences:bundleIdentifier];
    }

    return response;
}

- (void)startService {
    [self connectService];

    if(center) {
        [center runServerOnCurrentThread];

        // Register messages.
        SEL handler = @selector(handleMessageNamed:withUserInfo:);

        [center registerForMessageName:@"isPathCompliant" target:self selector:handler];
        [center registerForMessageName:@"isPathRestricted" target:self selector:handler];
        [center registerForMessageName:@"isURLSchemeRestricted" target:self selector:handler];
        [center registerForMessageName:@"resolvePath" target:self selector:handler];
        [center registerForMessageName:@"getPreferences" target:self selector:handler];
    }
}

- (void)loadRulesets {
    // load rulesets
    NSArray* ruleset_urls = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:[NSURL fileURLWithPath:ROOT_PATH_NS(@SHADOW_RULESETS) isDirectory:YES] includingPropertiesForKeys:@[] options:0 error:nil];

    if(ruleset_urls) {
        for(NSURL* url in ruleset_urls) {
            NSDictionary* ruleset = [NSDictionary dictionaryWithContentsOfURL:url];

            if(ruleset) {
                [self addRuleset:ruleset];

                NSDictionary* info = [ruleset objectForKey:@"RulesetInfo"];

                if(info) {
                    NSLog(@"loaded ruleset '%@' by %@", [info objectForKey:@"Name"], [info objectForKey:@"Author"]);
                } else {
                    NSLog(@"loaded ruleset %@", [[url path] lastPathComponent]);
                }
            } else {
                NSLog(@"failed to load ruleset at url %@", url);
            }
        }
    }
}

- (void)connectService {
    if(center) {
        // service already connected
        return;
    }

    center = [CPDistributedMessagingCenter centerNamed:@MACH_SERVICE_NAME];
}

- (NSDictionary *)sendIPC:(NSString *)messageName withArgs:(NSDictionary *)args useService:(BOOL)service {
    if(service) {
        if(center) {
            NSError* error = nil;
            NSDictionary* result = [center sendMessageAndReceiveReplyName:messageName userInfo:args error:&error];
            return error ? nil : result;
        }

        return nil;
    }

    return [self handleMessageNamed:messageName withUserInfo:args];
}

- (NSDictionary *)sendIPC:(NSString *)messageName withArgs:(NSDictionary *)args {
    return [self sendIPC:messageName withArgs:args useService:YES];
}

- (NSString *)resolvePath:(NSString *)path {
    NSDictionary* response = [self sendIPC:@"resolvePath" withArgs:@{@"path" : path} useService:NO];

    if(response) {
        path = [response objectForKey:@"path"];
    }

    return path;
}

- (BOOL)isPathCompliant:(NSString *)path {
    if(!path || [path length] == 0 || [path isEqualToString:@"/"]) {
        return NO;
    }

    NSNumber* cached = [cache_compliant objectForKey:path];

    if(cached) {
        return [cached boolValue];
    }

    NSDictionary* response = [self sendIPC:@"isPathCompliant" withArgs:@{@"path" : path} useService:(![rulesets count])];

    if(response) {
        BOOL compliant = [[response objectForKey:@"compliant"] boolValue];
        [cache_compliant setObject:@(compliant) forKey:path];
        return compliant;
    }

    return YES;
}

- (BOOL)isPathRestricted:(NSString *)path {
    if(!path || [path length] == 0 || [path isEqualToString:@"/"]) {
        return NO;
    }

    NSNumber* cached = [cache_restricted objectForKey:path];

    if(cached) {
        return [cached boolValue];
    }

    NSDictionary* response = [self sendIPC:@"isPathRestricted" withArgs:@{@"path" : path} useService:(![rulesets count])];

    if(response) {
        BOOL restricted = [[response objectForKey:@"restricted"] boolValue];

        if(!restricted) {
            BOOL responseParent = [self isPathRestricted:[path stringByDeletingLastPathComponent]];

            if(responseParent) {
                restricted = YES;
            }
        }

        [cache_restricted setObject:@(restricted) forKey:path];
        return restricted;
    }

    return NO;
}

- (BOOL)isURLSchemeRestricted:(NSString *)scheme {
    if(!scheme) {
        return NO;
    }

    NSNumber* cached = [cache_urlscheme objectForKey:scheme];

    if(cached) {
        return [cached boolValue];
    }

    NSDictionary* response = [self sendIPC:@"isURLSchemeRestricted" withArgs:@{@"scheme" : scheme} useService:(![rulesets count])];

    if(response) {
        BOOL restricted = [[response objectForKey:@"restricted"] boolValue];
        [cache_urlscheme setObject:@(restricted) forKey:scheme];
        return restricted;
    }

    return NO;
}

- (NSDictionary *)getVersions {
    return @{
        @"build_date" : [NSString stringWithFormat:@"%@ %@", @__DATE__, @__TIME__]
    };
}

- (instancetype)init {
    if((self = [super init])) {
        center = nil;
        rulesets = @[];

        cache_restricted = [NSCache new];
        cache_compliant = [NSCache new];
        cache_urlscheme = [NSCache new];
    }

    return self;
}
@end
