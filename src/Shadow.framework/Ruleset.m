#import "Ruleset.h"
#import "RulesetPrivate.h"
#import "RulesetCompiler.h"

// Candidate 5: Ruleset.m retains matching only. Parsing, validation,
// compilation and compiled-cache persistence moved to RulesetCompiler.m;
// +rulesetWithURL: delegates there (per-URL last-known-good preserved).

NSString* const kShadowRulesetCacheSuffix = @".shadowcache";

@implementation RulesetEngine
@synthesize payloadDictionary;

+ (instancetype)rulesetWithURL:(NSURL *)url {
    return [ShadowRulesetCompiler compileRulesetAtURL:url];
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

// Binary search over a sorted flat array of paths.
- (BOOL)_structureContains:(NSArray*)array path:(NSString*)path {
    if(!array || !path) return NO;
    NSUInteger idx = [array indexOfObject:path inSortedRange:NSMakeRange(0, [array count]) options:NSBinarySearchingFirstEqual usingComparator:^NSComparisonResult(id a, id b) {
        return [(NSString*)a compare:(NSString*)b];
    }];
    return idx != NSNotFound;
}

- (BOOL)isPathCompliant:(NSString *)path {
    NSArray* dirs = array_structure_dirs;
    NSArray* paths = array_structure_paths;

    // Skip checks if ruleset doesn't define a structure or if path is a key.
    if(!dirs || !paths || [self _structureContains:paths path:path]) {
        return YES;
    }

    // Walk up strict ancestors to the deepest structure key (dir), then check
    // the next component after it against the full path set — the exact old
    // dict semantics (deepest key + children lookup) with binary search.
    NSString* tmp = [path stringByDeletingLastPathComponent];

    while(tmp.length > 0) {
        if([self _structureContains:dirs path:tmp]) {
            // Offset past the key plus its separator. A "/" key (tmp.length 1)
            // has no trailing separator, so the next component starts at 1.
            NSUInteger base = (tmp.length <= 1) ? tmp.length : tmp.length + 1;
            NSRange slash = [path rangeOfString:@"/" options:0 range:NSMakeRange(base, [path length] - base)];
            NSString* component = (slash.location == NSNotFound)
                ? [path substringFromIndex:base]
                : [path substringWithRange:NSMakeRange(base, slash.location - base)];

            return [self _structureContains:paths path:[tmp stringByAppendingPathComponent:component]];
        }

        NSString* parent = [tmp stringByDeletingLastPathComponent];

        if([parent isEqualToString:tmp]) {
            break;   // reached "/" or ""
        }

        tmp = parent;
    }

    return YES;   // no stock ancestor: paths outside the zones stay visible
}

- (BOOL)isPathWhitelisted:(NSString *)path {
    return [self _path:path matchesSet:set_whitelist prefixDict:dict_whitelist matchAll:whitelist_match_all predicate:pred_whitelist];
}

- (BOOL)isPathBlacklisted:(NSString *)path {
    return [self _path:path matchesSet:set_blacklist prefixDict:dict_blacklist matchAll:blacklist_match_all predicate:pred_blacklist];
}

// Exact set and prefix lookups first; the compound predicate last (it is a pure
// boolean over the input path, so OR-ing it in later is identical).
- (BOOL)_path:(NSString *)path matchesSet:(NSSet *)set prefixDict:(NSDictionary *)dict matchAll:(BOOL)matchAll predicate:(NSPredicate *)pred {
    if([set containsObject:path]) {
        return YES;
    }

    if([self _path:path matchesPrefixDict:dict matchAll:matchAll]) {
        return YES;
    }

    return pred ? [pred evaluateWithObject:path] : NO;
}

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    // C0-3: schemes are normalized to lowercase at load (_compile); the helper
    // lowercases the query too so a case-variant probe can never bypass a rule.
    return [self _value:scheme inRestrictedSet:set_urlschemes];
}

- (BOOL)isBundleIDRestricted:(NSString *)bundleID {
    return [self _value:bundleID inRestrictedSet:set_bundleids];
}

// nil/empty query is never restricted; otherwise membership in the lowercased
// load-time set (shared by scheme + bundle-ID checks).
- (BOOL)_value:(NSString *)value inRestrictedSet:(NSSet *)set {
    if(!value || [value length] == 0) {
        return NO;
    }

    return [set containsObject:[value lowercaseString]];
}
@end
