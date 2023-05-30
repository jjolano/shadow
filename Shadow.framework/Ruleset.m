#import <Shadow/Ruleset.h>

@implementation ShadowRuleset
@synthesize internalDictionary;

- (instancetype)init {
    if((self = [super init])) {
        set_urlschemes = nil;
        set_whitelist = nil;
        set_blacklist = nil;

        pred_whitelist = nil;
        pred_blacklist = nil;
    }

    return self;
}

+ (instancetype)rulesetWithURL:(NSURL *)url {
    NSDictionary* ruleset_dict = [NSDictionary dictionaryWithContentsOfURL:url];

    if(ruleset_dict) {
        ShadowRuleset* ruleset = [self new];
        [ruleset setInternalDictionary:ruleset_dict];
        [ruleset _compile];
        return ruleset;
    }

    return nil;
}

+ (instancetype)rulesetWithPath:(NSString *)path {
    NSURL* file_url = [NSURL fileURLWithPath:path isDirectory:NO];
    return [self rulesetWithURL:file_url];
}

- (void)_compile {
    NSOperationQueue* queue = [NSOperationQueue new];
    [queue setQualityOfService:NSOperationQualityOfServiceUserInteractive];

    NSArray* urlschemes = [internalDictionary objectForKey:@"BlacklistURLSchemes"];

    if(urlschemes) {
        [queue addOperationWithBlock:^{
            set_urlschemes = [NSSet setWithArray:urlschemes];
        }];
    }

    NSArray* whitelist_paths = [internalDictionary objectForKey:@"WhitelistExactPaths"];

    if(whitelist_paths) {
        [queue addOperationWithBlock:^{
            set_whitelist = [NSSet setWithArray:whitelist_paths];
        }];
    }

    NSArray* blacklist_paths = [internalDictionary objectForKey:@"BlacklistExactPaths"];

    if(blacklist_paths) {
        [queue addOperationWithBlock:^{
            set_blacklist = [NSSet setWithArray:blacklist_paths];
        }];
    }

    NSArray* whitelist_preds = [internalDictionary objectForKey:@"WhitelistPredicates"];

    if(whitelist_preds) {
        [queue addOperationWithBlock:^{
            NSMutableArray<NSPredicate *>* preds = [NSMutableArray new];

            for(NSString* pred_str in whitelist_preds) {
                [preds addObject:[NSPredicate predicateWithFormat:pred_str]];
            }

            pred_whitelist = [NSCompoundPredicate orPredicateWithSubpredicates:preds];
        }];
    }

    NSArray* blacklist_preds = [internalDictionary objectForKey:@"BlacklistPredicates"];

    if(blacklist_preds) {
        [queue addOperationWithBlock:^{
            NSMutableArray<NSPredicate *>* preds = [NSMutableArray new];

            for(NSString* pred_str in blacklist_preds) {
                [preds addObject:[NSPredicate predicateWithFormat:pred_str]];
            }

            pred_blacklist = [NSCompoundPredicate orPredicateWithSubpredicates:preds];
        }];
    }

    [queue waitUntilAllOperationsAreFinished];
}

- (BOOL)isPathCompliant:(NSString *)path {
    NSDictionary* structure = [internalDictionary objectForKey:@"FileSystemStructure"];

    // Skip checks if ruleset doesn't define a structure or if path is a key.
    if(!structure || [structure objectForKey:path]) {
        return YES;
    }

    // Find the closest key in the structure.
    NSString* path_tmp = path;
    NSArray* structure_base = nil;

    do {
        path_tmp = [path_tmp stringByDeletingLastPathComponent];
        structure_base = [structure objectForKey:path_tmp];
    } while(!structure_base && ![path_tmp isEqualToString:@"/"]);

    // Check if path begins with any of the structure's child paths.
    if(structure_base) {
        BOOL compliant = NO;

        for(NSString* name in structure_base) {
            NSString* structure_path = [path_tmp stringByAppendingPathComponent:name];

            if([path hasPrefix:structure_path]) {
                compliant = YES;
                break;
            }
        }

        return compliant;
    }

    return YES;
}

- (BOOL)isPathWhitelisted:(NSString *)path {
    if([set_whitelist containsObject:path] || [pred_whitelist evaluateWithObject:path]) {
        return YES;
    }

    NSArray* array_whitelist = [internalDictionary objectForKey:@"WhitelistPaths"];

    if(array_whitelist) {
        for(NSString* whitelist_path in array_whitelist) {
            if([path hasPrefix:whitelist_path]) {
                return YES;
            }
        }
    }

    return NO;
}

- (BOOL)isPathBlacklisted:(NSString *)path {
    if([set_blacklist containsObject:path] || [pred_blacklist evaluateWithObject:path]) {
        return YES;
    }

    NSArray* array_blacklist = [internalDictionary objectForKey:@"BlacklistPaths"];

    if(array_blacklist) {
        for(NSString* blacklist_path in array_blacklist) {
            if([path hasPrefix:blacklist_path]) {
                return YES;
            }
        }
    }

    return NO;
}

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    return [set_urlschemes containsObject:scheme];
}
@end
