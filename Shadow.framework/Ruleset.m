#import <Shadow/Ruleset.h>
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