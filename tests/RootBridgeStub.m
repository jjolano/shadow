// Host-side RootBridge implementation for the test harness.
//
// The real RootBridge derives jbroot/rootless state from where its own image
// is installed. A host binary has no jailbreak, so the harness injects the
// equivalent facts directly:
//
//   - "rootless" means: /Library/... and /usr/... paths map to a fixture
//     jbroot directory (<work>/jb), mirroring the device layout. SHADOW_RULESETS
//     always resolves to the staged rulesets dir, in both modes — a host has
//     no /Library/Shadow/Rulesets.
//   - "rooted" means: paths pass through unchanged (device-rooted behavior),
//     again except SHADOW_RULESETS.
//
// NOTE: Core.m's rootless existence gates call real access() on LITERAL
// "/var/jb"-prefixed paths — they never round-trip through getJBPath — so on
// the host those gates always fail. Consequences for assertions are documented
// in README.md; the decision-engine paths that matter (rulesets, vetoes,
// whitelists, C0-1 write probes, /var/** decisions, fast-paths) still run
// unmodified.

#import <RootBridge.h>
#import "RootBridgeStub.h"

#import "../common.h"

static NSString* gJBPath;      // fixture jbroot; nil = rooted mode
static NSString* gRulesetsDir; // staged rulesets dir (both modes)

@implementation RootBridge

+ (void)shdwHarnessSetJBPath:(NSString*)jbPath rulesetsDir:(NSString*)rulesetsDir {
    gJBPath = [jbPath copy];
    gRulesetsDir = [rulesetsDir copy];
}

+ (BOOL)isJBRootless {
    return gJBPath != nil;
}

+ (NSString*)getJBPath:(NSString*)path {
    if(path && [path isEqualToString:@SHADOW_RULESETS]) {
        return gRulesetsDir;
    }

    // Mirrors the real RootBridge: /Library, /usr and /Applications live
    // under the jbroot on rootless jailbreaks.
    if(gJBPath && path
        && ([path hasPrefix:@"/Library/"] || [path hasPrefix:@"/usr/"] || [path hasPrefix:@"/Applications/"])) {
        return [gJBPath stringByAppendingString:path];
    }

    return path;
}

@end
