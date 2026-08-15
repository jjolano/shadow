// Host-side path shim declarations (SHADOW_TEST_HARNESS builds only; see
// ShdwPathShim.m and the JBPath.h seam).

#ifndef shdw_pathshim_h
#define shdw_pathshim_h

#import <Foundation/Foundation.h>

// jbPath: fixture jbroot directory, or nil for rooted mode.
// rulesetsDir: staged rulesets directory (both modes).
void shdw_harness_set_jbpath(NSString* _Nullable jbPath, NSString* _Nonnull rulesetsDir);

BOOL shdw_harness_rootless(void);

NSString* _Nullable shdw_harness_jbpath(NSString* _Nullable path);

#endif // shdw_pathshim_h
