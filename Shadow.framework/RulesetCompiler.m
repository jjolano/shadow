#import <Shadow/Ruleset.h>
#import "RulesetPrivate.h"
#import "RulesetCompiler.h"

// Candidate 5: RulesetCompiler — parse + validate + compile + persist. The
// matching side stays in Ruleset.m; everything else (including the per-URL
// last-known-good and the compiled-cache read/write, v2 format untouched)
// lives here. Framework-internal: not exported, not in exported_symbols.txt.

// Bumped to 2: v2 archives the reduced RulesetInfo-only payload instead of
// the full payload graph (old v1 cache files are rejected by the version
// check and rebuilt).
static const NSInteger kShadowRulesetCacheVersion = 2;

@implementation ShadowRulesetCompiler

// Full load path for one ruleset URL: compiled cache first (while the
// plist's mtime+size are unchanged), then parse + compile, then persist.
// Per-URL last-known-good: if a later reload fails, keep serving the
// previously parsed ruleset instead of dropping it. Verbatim move of the old
// +[RulesetEngine rulesetWithURL:].
+ (RulesetEngine *)compileRulesetAtURL:(NSURL *)url {
    @synchronized([RulesetEngine class]) {
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
            RulesetEngine* ruleset = [RulesetEngine new];
            ruleset.payloadDictionary = ruleset_dict;

            @try {
                [self _compileRuleset:ruleset];
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
// type-invalid payload — callers then fall back to parse + compile. Verbatim
// move of the old +[RulesetEngine _rulesetFromCompiledCacheForURL:].
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

    RulesetEngine* ruleset = [RulesetEngine new];

    if(![self _restoreFromCache:cached intoRuleset:ruleset]) {
        return nil;
    }

    return ruleset;
}

// Type-validates and installs the cached compiled state. Returns NO on any
// type mismatch so the caller falls back to _compile; the cache file is
// Shadow's own artifact but a corrupt or stale-format file must never crash
// a lookup. Verbatim move of the old -[RulesetEngine _restoreFromCache:].
+ (BOOL)_restoreFromCache:(NSDictionary *)cached intoRuleset:(RulesetEngine *)ruleset {
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

    ruleset.payloadDictionary = [cached objectForKey:@"payload"];
    ruleset->set_urlschemes = shdwCacheUnwrapNil([cached objectForKey:@"schemes"]);
    ruleset->set_whitelist = shdwCacheUnwrapNil([cached objectForKey:@"whitelist"]);
    ruleset->set_blacklist = shdwCacheUnwrapNil([cached objectForKey:@"blacklist"]);
    ruleset->set_bundleids = shdwCacheUnwrapNil([cached objectForKey:@"bundleids"]);
    ruleset->dict_whitelist = shdwCacheUnwrapNil([cached objectForKey:@"whitelist_prefixes"]);
    ruleset->dict_blacklist = shdwCacheUnwrapNil([cached objectForKey:@"blacklist_prefixes"]);
    ruleset->dict_structure = shdwCacheUnwrapNil([cached objectForKey:@"structure"]);
    ruleset->pred_whitelist = shdwCacheUnwrapNil([cached objectForKey:@"pred_whitelist"]);
    ruleset->pred_blacklist = shdwCacheUnwrapNil([cached objectForKey:@"pred_blacklist"]);
    ruleset->whitelist_match_all = [[cached objectForKey:@"whitelist_match_all"] boolValue];
    ruleset->blacklist_match_all = [[cached objectForKey:@"blacklist_match_all"] boolValue];
    return YES;
}

// Best-effort archive of the compiled state next to the plist, keyed by the
// plist's mtime and size. Never fails the compile path: unreadable or
// read-only rulesets dirs just skip caching. Verbatim move of the old
// +[RulesetEngine _writeCompiledCacheForRuleset:url:]; v2 format, no v3
// writer yet.
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
    NSDictionary* info = [ruleset.payloadDictionary objectForKey:@"RulesetInfo"];
    NSDictionary* reducedPayload = info ? @{@"RulesetInfo" : info} : @{};
    ruleset.payloadDictionary = reducedPayload;

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
// Verbatim move of the old -[RulesetEngine _validatedStringArray:forKey:].
+ (NSArray<NSString *>*)validatedStringArray:(id)value forKey:(NSString *)key {
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
// logged and skipped. Verbatim move of the old -[RulesetEngine
// _validatedStructure:].
+ (NSDictionary*)validatedStructure:(id)value {
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

// Compiles a ruleset's payload into its lookup tables. Verbatim move of the
// old -[RulesetEngine _compile].
+ (void)_compileRuleset:(RulesetEngine *)ruleset {
    NSDictionary* payload = ruleset.payloadDictionary;

    // Type-validate entries before compiling; malformed values are logged and
    // skipped, never fatal.
    NSArray* urlschemes = [self validatedStringArray:[payload objectForKey:@"BlacklistURLSchemes"] forKey:@"BlacklistURLSchemes"];

    if(urlschemes) {
        // C0-3: normalize schemes to lowercase at load (match time also
        // lowercases the query — see isSchemeRestricted:) so a
        // case-variant probe ("Cydia" vs "cydia") can never bypass a
        // scheme rule.
        NSMutableSet* lower = [NSMutableSet setWithCapacity:[urlschemes count]];

        for(NSString* scheme in urlschemes) {
            [lower addObject:[scheme lowercaseString]];
        }

        ruleset->set_urlschemes = [lower copy];
    }

    NSArray* whitelist_paths = [self validatedStringArray:[payload objectForKey:@"WhitelistExactPaths"] forKey:@"WhitelistExactPaths"];

    if(whitelist_paths) {
        ruleset->set_whitelist = [NSSet setWithArray:whitelist_paths];
    }

    NSArray* blacklist_paths = [self validatedStringArray:[payload objectForKey:@"BlacklistExactPaths"] forKey:@"BlacklistExactPaths"];

    if(blacklist_paths) {
        ruleset->set_blacklist = [NSSet setWithArray:blacklist_paths];
    }

    NSArray* whitelist_prefixes = [self validatedStringArray:[payload objectForKey:@"WhitelistPaths"] forKey:@"WhitelistPaths"];

    if(whitelist_prefixes) {
        ruleset->dict_whitelist = [self compilePrefixDict:whitelist_prefixes matchAll:&ruleset->whitelist_match_all];
    }

    NSArray* blacklist_prefixes = [self validatedStringArray:[payload objectForKey:@"BlacklistPaths"] forKey:@"BlacklistPaths"];

    if(blacklist_prefixes) {
        ruleset->dict_blacklist = [self compilePrefixDict:blacklist_prefixes matchAll:&ruleset->blacklist_match_all];
    }

    NSDictionary* structure = [self validatedStructure:[payload objectForKey:@"FileSystemStructure"]];

    if(structure) {
        NSMutableDictionary* compiled = [NSMutableDictionary dictionaryWithCapacity:[structure count]];

        for(NSString* key in structure) {
            [compiled setObject:[NSSet setWithArray:[structure objectForKey:key]] forKey:key];
        }

        ruleset->dict_structure = [compiled copy];
    }

    // C0-3: bundle-ID blacklist, normalized to lowercase at load (matches the
    // scheme normalization above) so case-variant bundle-ID probes can never
    // bypass a rule.
    NSArray* bundleids = [self validatedStringArray:[payload objectForKey:@"BlacklistBundleIDs"] forKey:@"BlacklistBundleIDs"];

    if(bundleids) {
        NSMutableSet* lower = [NSMutableSet setWithCapacity:[bundleids count]];

        for(NSString* bundleID in bundleids) {
            [lower addObject:[bundleID lowercaseString]];
        }

        ruleset->set_bundleids = [lower copy];
    }

    NSArray* whitelist_preds = [self validatedStringArray:[payload objectForKey:@"WhitelistPredicates"] forKey:@"WhitelistPredicates"];

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
            ruleset->pred_whitelist = [NSCompoundPredicate orPredicateWithSubpredicates:preds];
        }
    }

    NSArray* blacklist_preds = [self validatedStringArray:[payload objectForKey:@"BlacklistPredicates"] forKey:@"BlacklistPredicates"];

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
            ruleset->pred_blacklist = [NSCompoundPredicate orPredicateWithSubpredicates:preds];
        }
    }
}

// Normalizes prefix rules exactly like the old _normalizePaths (trim, strip
// trailing slash) and groups them by parent directory: parent -> set of full
// prefixes. A bare "/" entry matches every path (same as hasFilenamePrefix)
// and is recorded in *outMatchAll instead of the dict. Verbatim move of the
// old -[RulesetEngine _compilePrefixDict:matchAll:].
+ (NSDictionary<NSString *, NSSet<NSString *>*>*)compilePrefixDict:(NSArray<NSString *>*)paths matchAll:(BOOL*)outMatchAll {
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
@end