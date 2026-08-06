#import <Shadow/Ruleset.h>

@implementation RulesetEngine
@synthesize payloadDictionary;

- (instancetype)init {
    if((self = [super init])) {
        set_urlschemes = nil;
        set_whitelist = nil;
        set_blacklist = nil;
        array_whitelist = nil;
        array_blacklist = nil;

        pred_whitelist = nil;
        pred_blacklist = nil;
    }

    return self;
}

+ (instancetype)rulesetWithURL:(NSURL *)url {
    NSDictionary* ruleset_dict = [NSDictionary dictionaryWithContentsOfURL:url];

    if(ruleset_dict) {
        RulesetEngine* ruleset = [self new];
        [ruleset setPayloadDictionary:ruleset_dict];
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

    NSArray* urlschemes = [payloadDictionary objectForKey:@"BlacklistURLSchemes"];

    if(urlschemes) {
        [queue addOperationWithBlock:^{
            set_urlschemes = [NSSet setWithArray:urlschemes];
        }];
    }

    NSArray* whitelist_paths = [payloadDictionary objectForKey:@"WhitelistExactPaths"];

    if(whitelist_paths) {
        [queue addOperationWithBlock:^{
            set_whitelist = [NSSet setWithArray:whitelist_paths];
        }];
    }

    NSArray* blacklist_paths = [payloadDictionary objectForKey:@"BlacklistExactPaths"];

    if(blacklist_paths) {
        [queue addOperationWithBlock:^{
            set_blacklist = [NSSet setWithArray:blacklist_paths];
        }];
    }

    NSArray* whitelist_prefixes = [payloadDictionary objectForKey:@"WhitelistPaths"];

    if(whitelist_prefixes) {
        [queue addOperationWithBlock:^{
            array_whitelist = [self _normalizePaths:whitelist_prefixes];
        }];
    }

    NSArray* blacklist_prefixes = [payloadDictionary objectForKey:@"BlacklistPaths"];

    if(blacklist_prefixes) {
        [queue addOperationWithBlock:^{
            array_blacklist = [self _normalizePaths:blacklist_prefixes];
        }];
    }

    NSArray* whitelist_preds = [payloadDictionary objectForKey:@"WhitelistPredicates"];

    if(whitelist_preds) {
        [queue addOperationWithBlock:^{
            NSMutableArray<NSPredicate *>* preds = [NSMutableArray new];

            for(NSString* pred_str in whitelist_preds) {
                [preds addObject:[NSPredicate predicateWithFormat:pred_str]];
            }

            pred_whitelist = [NSCompoundPredicate orPredicateWithSubpredicates:preds];
        }];
    }

    NSArray* blacklist_preds = [payloadDictionary objectForKey:@"BlacklistPredicates"];

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

- (BOOL)path:(NSString *)path hasComponentPrefix:(NSString *)prefix {
    NSUInteger prefix_len = [prefix length];

    if(prefix_len == 0 || [prefix isEqualToString:@"/"]) {
        return YES;
    }

    if(prefix_len == [path length]) {
        return [path isEqualToString:prefix];
    }

    return [path hasPrefix:prefix] && [path characterAtIndex:prefix_len] == '/';
}

- (BOOL)path:(NSString *)path hasFilenamePrefix:(NSString *)prefix {
    NSUInteger prefix_len = [prefix length];

    if(prefix_len == 0 || [prefix isEqualToString:@"/"]) {
        return YES;
    }

    if(prefix_len == [path length]) {
        return [path isEqualToString:prefix];
    }

    // Prefix may end mid-filename (com.apple -> com.apple.locationd.plist), but must
    // not span a slash boundary (com.apple -> com.appleEvil/subdir/file is a miss).
    // Search from prefix_len + 1: the boundary char itself may be '/'.
    return [path hasPrefix:prefix] && [path rangeOfString:@"/" options:0 range:NSMakeRange(prefix_len + 1, [path length] - prefix_len - 1)].location == NSNotFound;
}

- (NSArray<NSString *>*)_normalizePaths:(NSArray<NSString *>*)paths {
    NSMutableArray<NSString *>* normalized = [NSMutableArray new];

    for(NSString* raw in paths) {
        NSString* entry = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

        if([entry length] == 0) {
            continue;
        }

        if(![entry isEqualToString:@"/"] && [entry hasSuffix:@"/"]) {
            entry = [entry substringToIndex:[entry length] - 1];
        }

        [normalized addObject:entry];
    }

    return [normalized copy];
}

- (BOOL)isPathCompliant:(NSString *)path {
    NSDictionary* structure = [payloadDictionary objectForKey:@"FileSystemStructure"];

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

            if([self path:path hasComponentPrefix:structure_path]) {
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

    for(NSString* whitelist_path in array_whitelist) {
        if([self path:path hasFilenamePrefix:whitelist_path]) {
            return YES;
        }
    }

    return NO;
}

- (BOOL)isPathBlacklisted:(NSString *)path {
    if([set_blacklist containsObject:path] || [pred_blacklist evaluateWithObject:path]) {
        return YES;
    }

    for(NSString* blacklist_path in array_blacklist) {
        if([self path:path hasFilenamePrefix:blacklist_path]) {
            return YES;
        }
    }

    return NO;
}

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    return [set_urlschemes containsObject:scheme];
}
@end
