#ifndef shadow_ruleset_private_h
#define shadow_ruleset_private_h

#import "Ruleset.h"

// Framework-internal RulesetEngine layout, shared by Ruleset.m (matching only)
// and ShadowRulesetCompiler.m (parse/compile/cache/persist). All ivars moved
// out of the public header + the old Ruleset.m extension so the compiler can
// install compiled state; @public is scoped to this private header (never
// shipped, never part of the public API).
@interface RulesetEngine () {
    @public
    // Compiled lookup tables (built by the compiler's _compile, mirroring
    // set_whitelist etc.): prefix rules grouped by parent directory so a path
    // only compares the prefixes relevant to its own parent, and
    // FileSystemStructure children compiled to sets so matching is a single
    // set lookup per node.
    NSDictionary<NSString *, NSSet<NSString *>*>* dict_whitelist;
    NSDictionary<NSString *, NSSet<NSString *>*>* dict_blacklist;
    BOOL whitelist_match_all; // a bare "/" prefix matches every path
    BOOL blacklist_match_all;
    NSDictionary<NSString *, NSSet<NSString *>*>* dict_structure;
    NSSet<NSString *>* set_bundleids; // C0-3: BlacklistBundleIDs, lowercased at load

    // Compiled sets/predicates (were declared in the public Ruleset.h; moved
    // here so the compiler can write them).
    NSSet<NSString *>* set_urlschemes;
    NSSet<NSString *>* set_whitelist;
    NSSet<NSString *>* set_blacklist;
    NSPredicate* pred_whitelist;
    NSPredicate* pred_blacklist;
}

@property (copy, nonatomic, readwrite) NSDictionary* payloadDictionary;
@end
#endif
