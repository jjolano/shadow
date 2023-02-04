#import "ShadowService.h"
#import "ShadowService+Restriction.h"
#import "ShadowService+Settings.h"

#import "../common.h"
#import "../vendor/rootless.h"

#import <AppSupport/CPDistributedMessagingCenter.h>

@implementation ShadowService {
    NSCache<NSString *, NSNumber *>* cache;

    NSString* dpkgPath;
    NSArray* rulesets;
    CPDistributedMessagingCenter* center;
}

- (void)addRuleset:(NSDictionary *)ruleset {
    // Preprocess ruleset
    NSMutableDictionary* ruleset_processed = [ruleset mutableCopy];

    NSArray* wpred = ruleset[@"WhitelistPredicates"];
    NSArray* bpred = ruleset[@"BlacklistPredicates"];

    if(wpred) {
        NSMutableArray* wpred_new = [NSMutableArray new];

        for(NSString* pred_str in wpred) {
            NSPredicate* pred = [NSPredicate predicateWithFormat:pred_str];
            [wpred_new addObject:pred];
        }

        NSPredicate* wpred_compound = [NSCompoundPredicate orPredicateWithSubpredicates:wpred_new];
        [ruleset_processed setObject:wpred_compound forKey:@"WhitelistPredicates"];
    }

    if(bpred) {
        NSMutableArray* bpred_new = [NSMutableArray new];

        for(NSString* pred_str in bpred) {
            NSPredicate* pred = [NSPredicate predicateWithFormat:pred_str];
            [bpred_new addObject:pred];
        }

        NSPredicate* bpred_compound = [NSCompoundPredicate orPredicateWithSubpredicates:bpred_new];
        [ruleset_processed setObject:bpred_compound forKey:@"BlacklistPredicates"];
    }

    rulesets = [rulesets arrayByAddingObject:[ruleset_processed copy]];
}

- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo {
    if(!name) {
        return nil;
    }

    NSDictionary* response = nil;

    if([name isEqualToString:@"resolvePath"]) {
        if(!userInfo) {
            return nil;
        }

        NSString* rawPath = userInfo[@"path"];

        if(!rawPath) {
            return nil;
        }

        // Resolve and standardize path.
        NSString* path = [rawPath stringByStandardizingPath];

        response = @{
            @"path" : path
        };
    } else if([name isEqualToString:@"isPathRestricted"]) {
        if(!userInfo) {
            return nil;
        }
        
        NSString* path = userInfo[@"path"];

        if(path && [path isAbsolutePath] && rulesets) {
            NSLog(@"%@: %@", name, path);
        
            // Check if path is restricted.
            BOOL restricted = NO;

            // Check rulesets
            if(!restricted) {
                for(NSDictionary* ruleset in rulesets) {
                    if(![[self class] isPathCompliant:path withRuleset:ruleset]) {
                        restricted = YES;
                        break;
                    }
                }
            }

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

            response = @{
                @"restricted" : @(restricted)
            };
        }
    } else if([name isEqualToString:@"isURLSchemeRestricted"]) {
        if(!userInfo) {
            return nil;
        }
        
        NSString* scheme = userInfo[@"scheme"];

        if(!scheme) {
            return nil;
        }

        BOOL restricted = NO;

        if(!restricted && rulesets) {
            // Check rulesets
            for(NSDictionary* ruleset in rulesets) {
                NSSet* bschemes = ruleset[@"BlacklistURLSchemes"];
                if(bschemes && [bschemes containsObject:scheme]) {
                    restricted = YES;
                    break;
                }
            }
        }

        response = @{
            @"restricted" : @(restricted)
        };
    } else if([name isEqualToString:@"getPreferences"]) {
        if(!userInfo) {
            return nil;
        }

        NSString* bundleIdentifier = userInfo[@"bundleIdentifier"];

        if(!bundleIdentifier) {
            return nil;
        }

        response = [[self class] getPreferences:bundleIdentifier];
    }

    return response;
}

- (void)startService {
    dpkgPath = ROOT_PATH_NS(@"/usr/bin/dpkg-query");

    if(![[NSFileManager defaultManager] fileExistsAtPath:dpkgPath]) {
        dpkgPath = nil;
    }

    [self connectService];

    if(center) {
        [center runServerOnCurrentThread];

        // Register messages.
        SEL handler = @selector(handleMessageNamed:withUserInfo:);

        [center registerForMessageName:@"isPathRestricted" target:self selector:handler];
        [center registerForMessageName:@"isURLSchemeRestricted" target:self selector:handler];
        [center registerForMessageName:@"resolvePath" target:self selector:handler];
        [center registerForMessageName:@"getPreferences" target:self selector:handler];
    }
}

- (void)loadRulesets {
    NSString* ruleset_path = ROOT_PATH_NS(@SHADOW_RULESETS);

    // load rulesets
    NSArray* ruleset_urls = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:[NSURL fileURLWithPath:ruleset_path isDirectory:YES] includingPropertiesForKeys:@[] options:0 error:nil];

    if(ruleset_urls) {
        for(NSURL* url in ruleset_urls) {
            NSDictionary* ruleset = [NSDictionary dictionaryWithContentsOfURL:url];

            if(ruleset) {
                NSDictionary* info = ruleset[@"RulesetInfo"];

                if(info) {
                    NSLog(@"loaded ruleset '%@' by %@", info[@"Name"], info[@"Author"]);
                } else {
                    NSLog(@"loaded ruleset %@", [[url path] lastPathComponent]);
                }

                [self addRuleset:ruleset];
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
    return [self sendIPC:messageName withArgs:args useService:(center != nil)];
}

- (NSString *)resolvePath:(NSString *)path {
    if(!path) {
        return nil;
    }

    NSDictionary* response = [self sendIPC:@"resolvePath" withArgs:@{@"path" : path} useService:(center != nil)];

    if(response) {
        path = response[@"path"];
    }

    return path;
}

- (BOOL)isPathRestricted:(NSString *)path {
    if(!path || [path isEqualToString:@"/"] || [path length] == 0) {
        return NO;
    }

    NSNumber* cached = [cache objectForKey:path];

    if(cached) {
        return [cached boolValue];
    }

    NSDictionary* response = [self sendIPC:@"isPathRestricted" withArgs:@{@"path" : path} useService:(rulesets == nil)];

    if(response) {
        BOOL restricted = [response[@"restricted"] boolValue];

        if(!restricted) {
            BOOL responseParent = [self isPathRestricted:[path stringByDeletingLastPathComponent]];

            if(responseParent) {
                restricted = YES;
            }
        }

        [cache setObject:@(restricted) forKey:path];
        return restricted;
    }

    return NO;
}

- (BOOL)isURLSchemeRestricted:(NSString *)scheme {
    if(!scheme) {
        return NO;
    }

    NSDictionary* response = [self sendIPC:@"isURLSchemeRestricted" withArgs:@{@"scheme" : scheme} useService:(rulesets == nil)];

    if(response) {
        return [response[@"restricted"] boolValue];
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
        dpkgPath = nil;
        rulesets = @[];

        cache = [NSCache new];
    }

    return self;
}
@end
