#ifndef shadow_jbpath_h
#define shadow_jbpath_h

#import <Foundation/Foundation.h>

// Jailbreak-root path seam. Two rootless conventions exist in the wild:
// - Legacy rootless (Dopamine/palera1n): fixed /var/jb, resolved via RootBridge.
// - roothide: random-named `jbroot`, no /var/jb at all, resolved via
//   libroothide's jbroot() API. RootBridge maps to /var/jb, which is wrong
//   there — so the roothide flavor must compile these out.
//
// Build the roothide flavor with -DSHADOW_ROOTHIDE (theos roothide scheme);
// every other flavor falls through to RootBridge unchanged.
#ifdef SHADOW_ROOTHIDE
#import <roothide.h>
#define JBPath(p) jbroot(p)
#define JBIsRootless() YES
#else
#import <RootBridge.h>
#define JBPath(p) [RootBridge getJBPath:p]
#define JBIsRootless() [RootBridge isJBRootless]
#endif

#endif // shadow_jbpath_h