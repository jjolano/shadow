#import "SHDWCapabilities.h"

BOOL SHDWHookGroupSupported(NSString* groupID) {
    // HK3 routes each request against the injected process. The Preferences
    // bundle cannot inspect that route without attempting a live hook, so it
    // must not disable controls based on retired provider discovery.
    (void)groupID;
    return YES;
}

NSString* SHDWHookGroupUnsupportedReason(NSString* groupID) {
    (void)groupID;
    return nil;
}

void SHDWApplyHookGroupGating(NSArray* specifiers) {
    (void)specifiers;
}
