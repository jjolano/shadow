#ifndef shadow_capabilities_h
#define shadow_capabilities_h

#import <Foundation/Foundation.h>

// Runtime capability checks for the Settings UI, based on available HookKit
// backends.
// Controllers call SHDWApplyHookGroupGating: on their loaded specifiers to
// disable toggles whose backend is missing, with a footer note explaining why.

// Hook-group capability matrix. groupID is the plist id (e.g. "Hook_Memory").
// Supported = the selected/available backends can actually run the group's
// hooks. Mirrors the backend routing in ShadowCore.dylib/dylib.x.
BOOL SHDWHookGroupSupported(NSString* groupID);

// Localized footer reason for an unsupported group, or nil if supported.
NSString* SHDWHookGroupUnsupportedReason(NSString* groupID);

// Iterate loaded specifiers; disable unsupported toggle cells and append the
// reason to the enclosing group's footerText. Safe on any specifier array
// (App/Hooks/Dangerous plists).
void SHDWApplyHookGroupGating(NSArray* specifiers);

#endif
