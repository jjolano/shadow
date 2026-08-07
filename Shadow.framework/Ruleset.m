#import <Shadow/Ruleset.h>

@interface RulesetEngine () {
    // Compiled lookup tables (built in _compile, mirroring set_whitelist etc.):
    // prefix rules grouped by parent directory so a path only compares the
    // prefixes relevant to its own parent, and FileSystemStructure children
    // compiled to sets so matching is a single set lookup per node.
    NSDictionary<NSString *, NSSet<NSString *>*>* dict_whitelist;
    NSDictionary<NSString *, NSSet<NSString *>*>* dict_blacklist;
    BOOL whitelist_match_all; // a bare "/" prefix matches every path
    BOOL blacklist_match_all;
    NSDictionary<NSString *, NSSet<NSString *>*>* dict_structure;
    NSSet<NSString *>* set_bundleids; // C0-3: BlacklistBundleIDs, lowercased at load
}

// Malformed-ruleset guards: validate/filter entries before compiling so a bad
// ruleset is logged and skipped, never fatal.
- (NSArray<NSString *>*)_validatedStringArray:(id)value forKey:(NSString *)key;
- (NSDictionary*)_validatedStructure:(id)value;
@end

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
    @synchronized([RulesetEngine class]) {
        // Last-known-good per URL: if a later reload fails, keep serving the
        // previously parsed ruleset instead of dropping it.
        static NSMutableDictionary* lastKnownGood = nil;

        if(!lastKnownGood) {
            lastKnownGood = [NSMutableDictionary new];
        }

        NSDictionary* ruleset_dict = nil;

        @try {
            ruleset_dict = [NSDictionary dictionaryWithContentsOfURL:url];
        } @catch(NSException* exception) {
            NSLog(@"[Ruleset] exception parsing %@: %@", url, exception);
        }

        if(ruleset_dict) {
            RulesetEngine* ruleset = [self new];
            [ruleset setPayloadDictionary:ruleset_dict];

            @try {
                [ruleset _compile];
            } @catch(NSException* exception) {
                NSLog(@"[Ruleset] exception compiling %@: %@", url, exception);
                ruleset = nil;
            }

            if(ruleset) {
                [lastKnownGood setObject:ruleset forKey:[url path]];
                return ruleset;
            }
        }

        RulesetEngine* previous = [lastKnownGood objectForKey:[url path]];

        if(previous) {
            NSLog(@"[Ruleset] failed to load %@; serving last-known-good ruleset", url);
            return previous;
        }
    }

    return nil;
}

+ (instancetype)rulesetWithPath:(NSString *)path {
    NSURL* file_url = [NSURL fileURLWithPath:path isDirectory:NO];
    return [self rulesetWithURL:file_url];
}

// Filters a payload value to an NSArray of NSStrings; non-array values and
// non-string entries are logged and skipped (malformed rulesets never crash).
- (NSArray<NSString *>*)_validatedStringArray:(id)value forKey:(NSString *)key {
    if(![value isKindOfClass:[NSArray class]]) {
        if(value) {
            NSLog(@"[Ruleset] invalid %@: expected array, got %@; ignoring", key, [value class]);
        }

        return nil;
    }

    NSMutableArray* result = [NSMutableArray new];

    for(id entry in value) {
        if([entry isKindOfClass:[NSString class]]) {
            [result addObject:entry];
        } else {
            NSLog(@"[Ruleset] invalid %@ entry (got %@); skipping", key, [entry class]);
        }
    }

    return result;
}

// Filters FileSystemStructure to a dict of arrays of strings; anything else is
// logged and skipped.
- (NSDictionary*)_validatedStructure:(id)value {
    if(![value isKindOfClass:[NSDictionary class]]) {
        if(value) {
            NSLog(@"[Ruleset] invalid FileSystemStructure: expected dictionary, got %@; ignoring", [value class]);
        }

        return nil;
    }

    NSMutableDictionary* result = [NSMutableDictionary new];

    for(id key in value) {
        id children = [value objectForKey:key];

        if(![key isKindOfClass:[NSString class]]) {
            NSLog(@"[Ruleset] invalid FileSystemStructure key (got %@); skipping", [key class]);
            continue;
        }

        if(![children isKindOfClass:[NSArray class]]) {
            NSLog(@"[Ruleset] invalid FileSystemStructure value for '%@' (got %@); skipping", key, [children class]);
            continue;
        }

        NSMutableArray* strings = [NSMutableArray new];

        for(id child in children) {
            if([child isKindOfClass:[NSString class]]) {
                [strings addObject:child];
            } else {
                NSLog(@"[Ruleset] invalid FileSystemStructure child under '%@' (got %@); skipping", key, [child class]);
            }
        }

        [result setObject:strings forKey:key];
    }

    return result;
}

- (void)_compile {
    NSOperationQueue* queue = [NSOperationQueue new];
    [queue setQualityOfService:NSOperationQualityOfServiceUserInteractive];

    // Type-validate entries before compiling; malformed values are logged and
    // skipped, never fatal.
    NSArray* urlschemes = [self _validatedStringArray:[payloadDictionary objectForKey:@"BlacklistURLSchemes"] forKey:@"BlacklistURLSchemes"];

    if(urlschemes) {
        [queue addOperationWithBlock:^{
            // C0-3: normalize schemes to lowercase at load (match time also
            // lowercases the query — see isSchemeRestricted:) so a
            // case-variant probe ("Cydia" vs "cydia") can never bypass a
            // scheme rule.
            NSMutableSet* lower = [NSMutableSet setWithCapacity:[urlschemes count]];

            for(NSString* scheme in urlschemes) {
                [lower addObject:[scheme lowercaseString]];
            }

            set_urlschemes = [lower copy];
        }];
    }

    NSArray* whitelist_paths = [self _validatedStringArray:[payloadDictionary objectForKey:@"WhitelistExactPaths"] forKey:@"WhitelistExactPaths"];

    if(whitelist_paths) {
        [queue addOperationWithBlock:^{
            set_whitelist = [NSSet setWithArray:whitelist_paths];
        }];
    }

    NSArray* blacklist_paths = [self _validatedStringArray:[payloadDictionary objectForKey:@"BlacklistExactPaths"] forKey:@"BlacklistExactPaths"];

    if(blacklist_paths) {
        [queue addOperationWithBlock:^{
            set_blacklist = [NSSet setWithArray:blacklist_paths];
        }];
    }

    NSArray* whitelist_prefixes = [self _validatedStringArray:[payloadDictionary objectForKey:@"WhitelistPaths"] forKey:@"WhitelistPaths"];

    if(whitelist_prefixes) {
        [queue addOperationWithBlock:^{
            dict_whitelist = [self _compilePrefixDict:whitelist_prefixes matchAll:&whitelist_match_all];
        }];
    }

    NSArray* blacklist_prefixes = [self _validatedStringArray:[payloadDictionary objectForKey:@"BlacklistPaths"] forKey:@"BlacklistPaths"];

    if(blacklist_prefixes) {
        [queue addOperationWithBlock:^{
            dict_blacklist = [self _compilePrefixDict:blacklist_prefixes matchAll:&blacklist_match_all];
        }];
    }

    NSDictionary* structure = [self _validatedStructure:[payloadDictionary objectForKey:@"FileSystemStructure"]];

    if(structure) {
        [queue addOperationWithBlock:^{
            NSMutableDictionary* compiled = [NSMutableDictionary dictionaryWithCapacity:[structure count]];

            for(NSString* key in structure) {
                [compiled setObject:[NSSet setWithArray:[structure objectForKey:key]] forKey:key];
            }

            dict_structure = [compiled copy];
        }];
    }

    // C0-3: bundle-ID blacklist, normalized to lowercase at load (matches the
    // scheme normalization above) so case-variant bundle-ID probes can never
    // bypass a rule.
    NSArray* bundleids = [self _validatedStringArray:[payloadDictionary objectForKey:@"BlacklistBundleIDs"] forKey:@"BlacklistBundleIDs"];

    if(bundleids) {
        [queue addOperationWithBlock:^{
            NSMutableSet* lower = [NSMutableSet setWithCapacity:[bundleids count]];

            for(NSString* bundleID in bundleids) {
                [lower addObject:[bundleID lowercaseString]];
            }

            set_bundleids = [lower copy];
        }];
    }

    NSArray* whitelist_preds = [self _validatedStringArray:[payloadDictionary objectForKey:@"WhitelistPredicates"] forKey:@"WhitelistPredicates"];

    if(whitelist_preds) {
        [queue addOperationWithBlock:^{
            NSMutableArray<NSPredicate *>* preds = [NSMutableArray new];

            for(NSString* pred_str in whitelist_preds) {
                @try {
                    [preds addObject:[NSPredicate predicateWithFormat:pred_str]];
                } @catch(NSException* exception) {
                    NSLog(@"[Ruleset] invalid predicate '%@': %@; skipping", pred_str, exception);
                }
            }

            if([preds count] > 0) {
                pred_whitelist = [NSCompoundPredicate orPredicateWithSubpredicates:preds];
            }
        }];
    }

    NSArray* blacklist_preds = [self _validatedStringArray:[payloadDictionary objectForKey:@"BlacklistPredicates"] forKey:@"BlacklistPredicates"];

    if(blacklist_preds) {
        [queue addOperationWithBlock:^{
            NSMutableArray<NSPredicate *>* preds = [NSMutableArray new];

            for(NSString* pred_str in blacklist_preds) {
                @try {
                    [preds addObject:[NSPredicate predicateWithFormat:pred_str]];
                } @catch(NSException* exception) {
                    NSLog(@"[Ruleset] invalid predicate '%@': %@; skipping", pred_str, exception);
                }
            }

            if([preds count] > 0) {
                pred_blacklist = [NSCompoundPredicate orPredicateWithSubpredicates:preds];
            }
        }];
    }

    [queue waitUntilAllOperationsAreFinished];
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

// Normalizes prefix rules exactly like the old _normalizePaths (trim, strip
// trailing slash) and groups them by parent directory: parent -> set of full
// prefixes. A bare "/" entry matches every path (same as hasFilenamePrefix)
// and is recorded in *outMatchAll instead of the dict.
- (NSDictionary<NSString *, NSSet<NSString *>*>*)_compilePrefixDict:(NSArray<NSString *>*)paths matchAll:(BOOL*)outMatchAll {
    NSMutableDictionary* dict = [NSMutableDictionary new];
    BOOL match_all = NO;

    for(NSString* raw in paths) {
        NSString* entry = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

        if([entry length] == 0) {
            continue;
        }

        if(![entry isEqualToString:@"/"] && [entry hasSuffix:@"/"]) {
            entry = [entry substringToIndex:[entry length] - 1];
        }

        if([entry isEqualToString:@"/"]) {
            match_all = YES;
            continue;
        }

        NSString* parent = [entry stringByDeletingLastPathComponent];
        NSMutableSet* bucket = [dict objectForKey:parent];

        if(!bucket) {
            bucket = [NSMutableSet new];
            [dict setObject:bucket forKey:parent];
        }

        [bucket addObject:entry];
    }

    *outMatchAll = match_all;
    return dict;
}

// hasFilenamePrefix matches a path in exactly two cases: the prefix IS the
// path's parent (every direct child matches), or the prefix shares the path's
// parent and its last component is a prefix of the basename. Both cases are
// keyed by the path's parent, so rules for other directories are never
// compared; the per-candidate check below is the exact original test.
- (BOOL)_path:(NSString *)path matchesPrefixDict:(NSDictionary<NSString *, NSSet<NSString *>*>*)dict matchAll:(BOOL)matchAll {
    if(!dict) {
        return NO;
    }

    if(matchAll) {
        return YES;
    }

    NSString* parent = [path stringByDeletingLastPathComponent];
    NSSet* same_parent = [dict objectForKey:parent];

    if(same_parent) {
        for(NSString* prefix in same_parent) {
            if([self path:path hasFilenamePrefix:prefix]) {
                return YES;
            }
        }
    }

    // Prefix equals the path's parent: it is keyed under the parent's own parent.
    return [[dict objectForKey:[parent stringByDeletingLastPathComponent]] containsObject:parent];
}

- (BOOL)isPathCompliant:(NSString *)path {
    NSDictionary* structure = dict_structure;

    // Skip checks if ruleset doesn't define a structure or if path is a key.
    if(!structure || [structure objectForKey:path]) {
        return YES;
    }

    // Find the closest key in the structure.
    NSString* path_tmp = path;
    NSSet* structure_base = nil;

    do {
        path_tmp = [path_tmp stringByDeletingLastPathComponent];
        structure_base = [structure objectForKey:path_tmp];
    } while(!structure_base && ![path_tmp isEqualToString:@"/"]);

    // A child matches iff it is the next path component after the key, so one
    // component extraction plus one set lookup replaces the per-child scan.
    if(structure_base) {
        // Under the relative-root key ("") stringByAppendingPathComponent adds
        // no separator, so an empty or "/" child yields a match-all prefix.
        if([path_tmp length] == 0 && ([structure_base containsObject:@""] || [structure_base containsObject:@"/"])) {
            return YES;
        }

        // Offset past the key plus its separator. The empty key (relative
        // root) has no separator, so the next component starts at 0.
        NSUInteger base = ([path_tmp length] <= 1) ? [path_tmp length] : [path_tmp length] + 1;
        NSRange slash = [path rangeOfString:@"/" options:0 range:NSMakeRange(base, [path length] - base)];
        NSString* component = (slash.location == NSNotFound)
            ? [path substringFromIndex:base]
            : [path substringWithRange:NSMakeRange(base, slash.location - base)];

        return [structure_base containsObject:component];
    }

    return YES;
}

- (BOOL)isPathWhitelisted:(NSString *)path {
    // Exact set and prefix lookups first; the compound predicate last (it is a
    // pure boolean over the input path, so OR-ing it in later is identical).
    if([set_whitelist containsObject:path]) {
        return YES;
    }

    if([self _path:path matchesPrefixDict:dict_whitelist matchAll:whitelist_match_all]) {
        return YES;
    }

    return pred_whitelist ? [pred_whitelist evaluateWithObject:path] : NO;
}

- (BOOL)isPathBlacklisted:(NSString *)path {
    if([set_blacklist containsObject:path]) {
        return YES;
    }

    if([self _path:path matchesPrefixDict:dict_blacklist matchAll:blacklist_match_all]) {
        return YES;
    }

    return pred_blacklist ? [pred_blacklist evaluateWithObject:path] : NO;
}

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    if(!scheme || [scheme length] == 0) {
        return NO;
    }

    // C0-3: schemes are normalized to lowercase at load (_compile); lowercase
    // the query here too so a case-variant probe can never bypass a rule.
    return [set_urlschemes containsObject:[scheme lowercaseString]];
}

- (BOOL)isBundleIDRestricted:(NSString *)bundleID {
    if(!bundleID || [bundleID length] == 0) {
        return NO;
    }

    // C0-3: same normalization as the scheme set — lowercase at load,
    // lowercase the query here.
    return [set_bundleids containsObject:[bundleID lowercaseString]];
}
@end
