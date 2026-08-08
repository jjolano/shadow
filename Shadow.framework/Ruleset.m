#import <Shadow/Ruleset.h>

// Compiled-ruleset cache: the lookup tables _compile builds are archived next
// to the ruleset plist and restored while the plist's mtime and size are
// unchanged, so every injected process skips the plist parse and recompile of
// MB-scale generated rulesets at spawn. The cache is a pure speedup: any
// miss, mismatch, unreadable or corrupt cache falls back to the parse +
// compile path, and every restore is type-validated so a bad cache can never
// crash a lookup.
NSString* const kShadowRulesetCacheSuffix = @".shadowcache";
// Bumped to 2: v2 archives the reduced RulesetInfo-only payload instead of
// the full payload graph (old v1 cache files are rejected by the version
// check and rebuilt).
static const NSInteger kShadowRulesetCacheVersion = 2;

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

// Compiled-cache helpers (see rulesetWithURL:). Best-effort: a cache miss or
// any failure returns/does nothing, never failing the compile path.
+ (RulesetEngine *)_rulesetFromCompiledCacheForURL:(NSURL *)url;
+ (void)_writeCompiledCacheForRuleset:(RulesetEngine *)ruleset url:(NSURL *)url;
- (BOOL)_restoreFromCache:(NSDictionary *)cached;
@end

@implementation RulesetEngine
@synthesize payloadDictionary;

+ (instancetype)rulesetWithURL:(NSURL *)url {
    @synchronized([RulesetEngine class]) {
        // Last-known-good per URL: if a later reload fails, keep serving the
        // previously parsed ruleset instead of dropping it.
        static NSMutableDictionary* lastKnownGood = nil;

        if(!lastKnownGood) {
            lastKnownGood = [NSMutableDictionary new];
        }

        NSDictionary* ruleset_dict = nil;

        // Try the compiled cache first: while the plist's mtime+size are
        // unchanged, the archived lookup tables are exactly what _compile
        // would build, so skip the plist parse and recompile entirely.
        RulesetEngine* fromCache = [self _rulesetFromCompiledCacheForURL:url];

        if(fromCache) {
            [lastKnownGood setObject:fromCache forKey:[url path]];
            return fromCache;
        }

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
                [self _writeCompiledCacheForRuleset:ruleset url:url];
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

// NSNull is stored for nil fields so every cache entry has every key; this
// unwraps it back to nil after validation.
static id shdwCacheUnwrapNil(id value) {
    return [value isKindOfClass:[NSNull class]] ? nil : value;
}

// Loads and validates the compiled cache for a ruleset URL. Returns nil on a
// miss, an mtime/size mismatch, an unreadable/corrupt archive, or a
// type-invalid payload — callers then fall back to parse + compile.
+ (RulesetEngine *)_rulesetFromCompiledCacheForURL:(NSURL *)url {
    NSString* plistPath = [url path];
    NSDictionary* plistAttrs = [[NSFileManager defaultManager] attributesOfItemAtPath:plistPath error:nil];

    if(!plistAttrs) {
        return nil;
    }

    NSDictionary* cached = nil;

    // The modern NSKeyedUnarchiver entry points (initForReadingFromData:…,
    // unarchivedObjectOfClass:…) require iOS 11; the deployment target (Makefile TARGET) is iOS 12, and the modern
    // iOS 11 entry points are out of scope, so the legacy API is the correct one here — deprecation
    // suppression is deliberate, not debt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    @try {
        cached = [NSKeyedUnarchiver unarchiveObjectWithFile:[plistPath stringByAppendingString:kShadowRulesetCacheSuffix]];
    } @catch(NSException* exception) {
        // Corrupt archive: fall back to compiling from the plist.
        cached = nil;
    }
#pragma clang diagnostic pop

    // The cache is only reusable while the plist it was compiled from is
    // byte-identical, as evidenced by an unchanged mtime and size.
    if(![cached isKindOfClass:[NSDictionary class]]
        || ![[cached objectForKey:@"version"] isEqualToNumber:@(kShadowRulesetCacheVersion)]
        || ![[cached objectForKey:@"mtime"] isEqualToNumber:@([[plistAttrs fileModificationDate] timeIntervalSinceReferenceDate])]
        || ![[cached objectForKey:@"size"] isEqualToNumber:@([plistAttrs fileSize])]) {
        return nil;
    }

    RulesetEngine* ruleset = [self new];

    if(![ruleset _restoreFromCache:cached]) {
        return nil;
    }

    return ruleset;
}

// Type-validates and installs the cached compiled state. Returns NO on any
// type mismatch so the caller falls back to _compile; the cache file is
// Shadow's own artifact but a corrupt or stale-format file must never crash
// a lookup.
- (BOOL)_restoreFromCache:(NSDictionary *)cached {
    if(![[cached objectForKey:@"payload"] isKindOfClass:[NSDictionary class]]) {
        return NO;
    }

    for(NSString* key in @[@"schemes", @"whitelist", @"blacklist", @"bundleids"]) {
        id value = [cached objectForKey:key];

        if(![value isKindOfClass:[NSSet class]]) {
            if([value isKindOfClass:[NSNull class]]) {
                continue;
            }

            return NO;
        }

        for(id member in value) {
            if(![member isKindOfClass:[NSString class]]) {
                return NO;
            }
        }
    }

    for(NSString* key in @[@"whitelist_prefixes", @"blacklist_prefixes", @"structure"]) {
        id value = [cached objectForKey:key];

        if(![value isKindOfClass:[NSDictionary class]]) {
            if([value isKindOfClass:[NSNull class]]) {
                continue;
            }

            return NO;
        }

        for(id dictKey in value) {
            if(![dictKey isKindOfClass:[NSString class]]) {
                return NO;
            }

            id set = [value objectForKey:dictKey];

            if(![set isKindOfClass:[NSSet class]]) {
                return NO;
            }

            for(id member in set) {
                if(![member isKindOfClass:[NSString class]]) {
                    return NO;
                }
            }
        }
    }

    for(NSString* key in @[@"pred_whitelist", @"pred_blacklist"]) {
        id value = [cached objectForKey:key];

        if(![value isKindOfClass:[NSPredicate class]] && ![value isKindOfClass:[NSNull class]]) {
            return NO;
        }
    }

    if(![[cached objectForKey:@"whitelist_match_all"] isKindOfClass:[NSNumber class]]
        || ![[cached objectForKey:@"blacklist_match_all"] isKindOfClass:[NSNumber class]]) {
        return NO;
    }

    payloadDictionary = [cached objectForKey:@"payload"];
    set_urlschemes = shdwCacheUnwrapNil([cached objectForKey:@"schemes"]);
    set_whitelist = shdwCacheUnwrapNil([cached objectForKey:@"whitelist"]);
    set_blacklist = shdwCacheUnwrapNil([cached objectForKey:@"blacklist"]);
    set_bundleids = shdwCacheUnwrapNil([cached objectForKey:@"bundleids"]);
    dict_whitelist = shdwCacheUnwrapNil([cached objectForKey:@"whitelist_prefixes"]);
    dict_blacklist = shdwCacheUnwrapNil([cached objectForKey:@"blacklist_prefixes"]);
    dict_structure = shdwCacheUnwrapNil([cached objectForKey:@"structure"]);
    pred_whitelist = shdwCacheUnwrapNil([cached objectForKey:@"pred_whitelist"]);
    pred_blacklist = shdwCacheUnwrapNil([cached objectForKey:@"pred_blacklist"]);
    whitelist_match_all = [[cached objectForKey:@"whitelist_match_all"] boolValue];
    blacklist_match_all = [[cached objectForKey:@"blacklist_match_all"] boolValue];
    return YES;
}

// Best-effort archive of the compiled state next to the plist, keyed by the
// plist's mtime and size. Never fails the compile path: unreadable or
// read-only rulesets dirs just skip caching.
+ (void)_writeCompiledCacheForRuleset:(RulesetEngine *)ruleset url:(NSURL *)url {
    // After _compile the full payload is dead weight: the compiled lookup
    // tables are the working set (their strings are shared with the payload,
    // so nothing is lost by releasing the container shells), and the only
    // remaining consumer is Backend's load log, which reads the small
    // RulesetInfo sub-dict. Archive that reduced payload — the old cache
    // embedded the whole FileSystemStructure twice (raw + compiled) — and
    // shrink the live ruleset's retained payload to match, releasing the
    // MB-scale container shells of a generated SystemRules for the process
    // lifetime. A ruleset without RulesetInfo keeps an empty payload, which
    // Backend logs identically (its objectForKey: then returns nil, the same
    // as before).
    NSDictionary* info = [[ruleset payloadDictionary] objectForKey:@"RulesetInfo"];
    NSDictionary* reducedPayload = info ? @{@"RulesetInfo" : info} : @{};
    [ruleset setPayloadDictionary:reducedPayload];

    NSString* plistPath = [url path];
    NSDictionary* plistAttrs = [[NSFileManager defaultManager] attributesOfItemAtPath:plistPath error:nil];

    if(!plistAttrs) {
        return;
    }

    NSDictionary* cached = @{
        @"version" : @(kShadowRulesetCacheVersion),
        @"mtime" : @([[plistAttrs fileModificationDate] timeIntervalSinceReferenceDate]),
        @"size" : @([plistAttrs fileSize]),
        @"payload" : reducedPayload,
        @"schemes" : ruleset->set_urlschemes ?: [NSNull null],
        @"whitelist" : ruleset->set_whitelist ?: [NSNull null],
        @"blacklist" : ruleset->set_blacklist ?: [NSNull null],
        @"bundleids" : ruleset->set_bundleids ?: [NSNull null],
        @"whitelist_prefixes" : ruleset->dict_whitelist ?: [NSNull null],
        @"blacklist_prefixes" : ruleset->dict_blacklist ?: [NSNull null],
        @"structure" : ruleset->dict_structure ?: [NSNull null],
        @"pred_whitelist" : ruleset->pred_whitelist ?: [NSNull null],
        @"pred_blacklist" : ruleset->pred_blacklist ?: [NSNull null],
        @"whitelist_match_all" : @(ruleset->whitelist_match_all),
        @"blacklist_match_all" : @(ruleset->blacklist_match_all)
    };

    // Legacy archiver: iOS 11 entry points are out of scope and the
    // deployment target is iOS 12 (Makefile TARGET) — see the unarchive side above.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    @try {
        NSData* data = [NSKeyedArchiver archivedDataWithRootObject:cached];

        if(data) {
            [data writeToFile:[plistPath stringByAppendingString:kShadowRulesetCacheSuffix] atomically:YES];
        }
    } @catch(NSException* exception) {
        // Best-effort only.
    }
#pragma clang diagnostic pop
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
    // Type-validate entries before compiling; malformed values are logged and
    // skipped, never fatal.
    NSArray* urlschemes = [self _validatedStringArray:[payloadDictionary objectForKey:@"BlacklistURLSchemes"] forKey:@"BlacklistURLSchemes"];

    if(urlschemes) {
        // C0-3: normalize schemes to lowercase at load (match time also
        // lowercases the query — see isSchemeRestricted:) so a
        // case-variant probe ("Cydia" vs "cydia") can never bypass a
        // scheme rule.
        NSMutableSet* lower = [NSMutableSet setWithCapacity:[urlschemes count]];

        for(NSString* scheme in urlschemes) {
            [lower addObject:[scheme lowercaseString]];
        }

        set_urlschemes = [lower copy];
    }

    NSArray* whitelist_paths = [self _validatedStringArray:[payloadDictionary objectForKey:@"WhitelistExactPaths"] forKey:@"WhitelistExactPaths"];

    if(whitelist_paths) {
        set_whitelist = [NSSet setWithArray:whitelist_paths];
    }

    NSArray* blacklist_paths = [self _validatedStringArray:[payloadDictionary objectForKey:@"BlacklistExactPaths"] forKey:@"BlacklistExactPaths"];

    if(blacklist_paths) {
        set_blacklist = [NSSet setWithArray:blacklist_paths];
    }

    NSArray* whitelist_prefixes = [self _validatedStringArray:[payloadDictionary objectForKey:@"WhitelistPaths"] forKey:@"WhitelistPaths"];

    if(whitelist_prefixes) {
        dict_whitelist = [self _compilePrefixDict:whitelist_prefixes matchAll:&whitelist_match_all];
    }

    NSArray* blacklist_prefixes = [self _validatedStringArray:[payloadDictionary objectForKey:@"BlacklistPaths"] forKey:@"BlacklistPaths"];

    if(blacklist_prefixes) {
        dict_blacklist = [self _compilePrefixDict:blacklist_prefixes matchAll:&blacklist_match_all];
    }

    NSDictionary* structure = [self _validatedStructure:[payloadDictionary objectForKey:@"FileSystemStructure"]];

    if(structure) {
        NSMutableDictionary* compiled = [NSMutableDictionary dictionaryWithCapacity:[structure count]];

        for(NSString* key in structure) {
            [compiled setObject:[NSSet setWithArray:[structure objectForKey:key]] forKey:key];
        }

        dict_structure = [compiled copy];
    }

    // C0-3: bundle-ID blacklist, normalized to lowercase at load (matches the
    // scheme normalization above) so case-variant bundle-ID probes can never
    // bypass a rule.
    NSArray* bundleids = [self _validatedStringArray:[payloadDictionary objectForKey:@"BlacklistBundleIDs"] forKey:@"BlacklistBundleIDs"];

    if(bundleids) {
        NSMutableSet* lower = [NSMutableSet setWithCapacity:[bundleids count]];

        for(NSString* bundleID in bundleids) {
            [lower addObject:[bundleID lowercaseString]];
        }

        set_bundleids = [lower copy];
    }

    NSArray* whitelist_preds = [self _validatedStringArray:[payloadDictionary objectForKey:@"WhitelistPredicates"] forKey:@"WhitelistPredicates"];

    if(whitelist_preds) {
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
    }

    NSArray* blacklist_preds = [self _validatedStringArray:[payloadDictionary objectForKey:@"BlacklistPredicates"] forKey:@"BlacklistPredicates"];

    if(blacklist_preds) {
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
    }
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
