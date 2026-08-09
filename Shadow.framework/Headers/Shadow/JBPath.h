#ifndef shadow_jbpath_h
#define shadow_jbpath_h

#import <Foundation/Foundation.h>

// Jailbreak-root path seam. Three rootless conventions exist in the wild:
// - Rooted (unc0ver/checkra1n rootful): everything lives at the real root.
// - Legacy rootless (Dopamine/palera1n): fixed /var/jb bootstrap.
// - roothide: random-named `jbroot`, no /var/jb at all, resolved via
//   libroothide's jbroot() API.
//
// Theos bakes the install prefix into every build via
// THEOS_PACKAGE_INSTALL_PREFIX ("" rooted, "/var/jb" rootless; the roothide
// scheme defines SHADOW_ROOTHIDE and links libroothide). The seam therefore
// needs no runtime library — the mapping is a compile-time constant folded
// from sizeof(THEOS_PACKAGE_INSTALL_PREFIX) ("" is length 1, "/var/jb" is 8):
//   - rooted:  identity (JBIsRootless() == NO)
//   - rootless: prepend the compile-time prefix (JBIsRootless() == YES)
//   - roothide: jbroot() (JBIsRootless() == YES)
//
// Only /Library, /usr and /Applications are jailbreak-prefixed (matching the
// legacy RootBridge behavior); everything else — /var/mobile, /tmp, relative
// paths — passes through untouched, so already-prefixed paths and non-JB
// paths are never double-prefixed.
#ifdef SHADOW_ROOTHIDE
#import <roothide.h>
#define JBPath(p) jbroot(p)
#define JBIsRootless() YES
#elif defined(SHADOW_TEST_HARNESS)
// Host test harness: no jailbreak, no theos prefix. The harness provides
// shdw_harness_set_jbpath(nil|fixture) (tests/ShdwPathShim.m) — nil = rooted
// pass-through, non-nil = rootless fixture mapping.
#import "ShdwPathShim.h"
#define JBPath(p) shdw_harness_jbpath(p)
#define JBIsRootless() shdw_harness_rootless()
#else
#ifndef THEOS_PACKAGE_INSTALL_PREFIX
#define THEOS_PACKAGE_INSTALL_PREFIX ""
#endif
#define JBIsRootless() (sizeof(THEOS_PACKAGE_INSTALL_PREFIX) > 1)
#define JBPath(p) (JBIsRootless() && ([p hasPrefix:@"/Library/"] || [p hasPrefix:@"/usr/"] || [p hasPrefix:@"/Applications/"]) \
    ? [@THEOS_PACKAGE_INSTALL_PREFIX stringByAppendingString:p] : p)
#endif

#endif // shadow_jbpath_h
