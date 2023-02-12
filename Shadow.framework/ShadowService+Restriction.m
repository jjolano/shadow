#import "ShadowService+Restriction.h"

@implementation ShadowService (Restriction)
+ (BOOL)isPathCompliant:(NSString *)path withRuleset:(NSDictionary *)ruleset {
    // Verify structure
    NSDictionary* ruleset_fss = [ruleset objectForKey:@"FileSystemStructure"];

    if(!ruleset_fss || [ruleset_fss objectForKey:path] || ![path isAbsolutePath]) {
        // no need to check further
        return YES;
    }
    
    NSString* path_tmp = path;
    NSArray* ruleset_fss_base = nil;

    do {
        path_tmp = [path_tmp stringByDeletingLastPathComponent];
        ruleset_fss_base = [ruleset_fss objectForKey:path_tmp];
    } while(!ruleset_fss_base && ![path_tmp isEqualToString:@"/"]);

    if(ruleset_fss_base) {
        BOOL compliant = NO;

        for(NSString* name in ruleset_fss_base) {
            NSString* ruleset_path = [path_tmp stringByAppendingPathComponent:name];

            if([path hasPrefix:ruleset_path]) {
                compliant = YES;
                break;
            }
        }

        if(!compliant) {
            NSLog(@"isPathCompliant: path '%@' not compliant (key: %@)", path, path_tmp);
            return NO;
        }
    }

    return YES;
}

+ (BOOL)isPathWhitelisted:(NSString *)path withRuleset:(NSDictionary *)ruleset {
    // Check whitelisted exact paths
    NSSet* ruleset_wepath = [ruleset objectForKey:@"WhitelistExactPaths"];

    if([ruleset_wepath containsObject:path]) {
        return YES;
    }

    // Check whitelisted paths
    NSArray* ruleset_wpath = [ruleset objectForKey:@"WhitelistPaths"];

    if(ruleset_wpath) {
        for(NSString* wpath in ruleset_wpath) {
            if([path hasPrefix:wpath]) {
                return YES;
            }
        }
    }

    // Check whitelisted predicates
    NSPredicate* ruleset_wpred = [ruleset objectForKey:@"WhitelistPredicates"];

    if([ruleset_wpred evaluateWithObject:path]) {
        return YES;
    }

    return NO;
}

+ (BOOL)isPathBlacklisted:(NSString *)path withRuleset:(NSDictionary *)ruleset {
    // Check blacklisted exact paths
    NSSet* ruleset_bepath = [ruleset objectForKey:@"BlacklistExactPaths"];

    if([ruleset_bepath containsObject:path]) {
        return YES;
    }

    // Check blacklisted paths
    NSArray* ruleset_bpath = [ruleset objectForKey:@"BlacklistPaths"];

    if(ruleset_bpath) {
        for(NSString* bpath in ruleset_bpath) {
            if([path hasPrefix:bpath]) {
                return YES;
            }
        }
    }

    // Check blacklisted predicates
    NSPredicate* ruleset_bpred = [ruleset objectForKey:@"BlacklistPredicates"];

    if([ruleset_bpred evaluateWithObject:path]) {
        return YES;
    }

    return NO;
}
@end
