// Host-side path shim for the test harness (no jailbreak, no theos prefix).
//
// The production seam (Shadow.framework/Headers/Shadow/JBPath.h) is
// compile-time: rooted passes through, rootless prepends the compile-time
// THEOS_PACKAGE_INSTALL_PREFIX. A host build has no jailbreak and no prefix,
// so under SHADOW_TEST_HARNESS the seam routes through this shim instead,
// which the harness drives:
//
//   - shdw_harness_set_jbpath(nil)     -> rooted mode: paths pass through
//   - shdw_harness_set_jbpath(fixture) -> rootless mode: /Library, /usr and
//     /Applications paths map into the fixture jbroot (mirroring the device
//     layout; SHADOW_RULESETS resolves to the staged rulesets dir in both
//     modes, since a host has no /Library/Shadow/Rulesets)
//
// The engine's rootless existence gates still call access()/realpath() on
// LITERAL "/var/jb"-prefixed paths (they never round-trip through JBPath);
// fsinterpose.c maps those into the fixture tree, exactly as documented in
// tests/README.md.

#import <Foundation/Foundation.h>
#import "ShdwPathShim.h"

#import "../src/common.h"

static NSString* gJBPath;      // fixture jbroot; nil = rooted mode
static NSString* gRulesetsDir; // staged rulesets dir (both modes)

void shdw_harness_set_jbpath(NSString* jbPath, NSString* rulesetsDir) {
    gJBPath = [jbPath copy];
    gRulesetsDir = [rulesetsDir copy];
}

BOOL shdw_harness_rootless(void) {
    return gJBPath != nil;
}

NSString* shdw_harness_jbpath(NSString* path) {
    NSString* rulesets = @SHADOW_RULESETS;

    if(path && ([path isEqualToString:rulesets]
        || [path hasPrefix:[rulesets stringByAppendingString:@"/"]])) {
        return [gRulesetsDir stringByAppendingString:[path substringFromIndex:[rulesets length]]];
    }

    // Mirrors the legacy RootBridge behavior (and the production seam's
    // prefix rule): /Library, /usr and /Applications live under the jbroot
    // on rootless jailbreaks.
    if(gJBPath && path
        && ([path hasPrefix:@"/Library/"] || [path hasPrefix:@"/usr/"] || [path hasPrefix:@"/Applications/"])) {
        return [gJBPath stringByAppendingString:path];
    }

    return path;
}
