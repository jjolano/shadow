#ifndef shadow_write_policy_h
#define shadow_write_policy_h

#import <Foundation/Foundation.h>

#import "SHDWPlugin.h"

// Path-scope helper shared by the restriction engine and the C hook wrappers.
static inline BOOL SHDWPathIsWithin(NSString *path, NSString *root) {
  return path.length && root.length &&
         ([path isEqualToString:root] ||
          [path hasPrefix:[root stringByAppendingString:@"/"]]);
}

// Once a detector is established, external writes reproduce a stock app
// sandbox's boundary: the app bundle is read-only, its own container and app
// group containers are writable, everything else is denied. This is the ONE
// verdict implementation; callers differ only in the scope they already know:
//   * RestrictionEngine passes its immutable context (actual group paths);
//   * the C hook wrapper passes the live Shadow scope and the broad group
//     root, because it cannot enumerate contexts.
// enabled is the detector-triggered policy flag, owned by the dylib; path must
// already be absolute and standardized by the caller.
static inline BOOL
SHDWDetectorWritePathDenied(NSString *path, BOOL enabled, BOOL hasAppSandbox,
                            NSString *bundlePath, NSString *homePath,
                            NSArray<NSString *> *groupContainerPaths,
                            NSString *groupRootPrefix) {
  if (!enabled || !hasAppSandbox || !path.length) {
    return NO;
  }

  // Detector runners write their evidence under Documents; that subtree is
  // test support, not app behavior.
  NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
  if (SHDWIsDetectorTestBundleID(bundleID) &&
      SHDWPathIsWithin(path, @"/var/mobile/Documents/ShadowDetectorTests")) {
    return NO;
  }

  if (SHDWPathIsWithin(path, bundlePath)) {
    return YES;
  }

  if (SHDWPathIsWithin(path, homePath) || [path isEqualToString:@"/dev/null"]) {
    return NO;
  }

  for (NSString *group in groupContainerPaths) {
    if (SHDWPathIsWithin(path, group)) {
      return NO;
    }
  }

  if (groupRootPrefix && SHDWPathIsWithin(path, groupRootPrefix)) {
    return NO;
  }

  return YES;
}

#endif // shadow_write_policy_h
