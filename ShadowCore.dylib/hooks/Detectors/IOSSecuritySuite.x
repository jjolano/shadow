#import "hooks.h"

static BOOL s_enabled = NO;

void shadowhook_IOSSecuritySuite_configure(NSDictionary* prefs) {
    s_enabled = [prefs[SHDWDetectorPatchIOSSecuritySuiteID] boolValue];
}

void shadowhook_IOSSecuritySuite(SHDWHookSession* hooks) {
    if(!s_enabled) return;
    shadowhook_libc_iossecuritysuite(hooks);
    shadowhook_NSFileManagerSymbolicLinks(hooks);
    shadowhook_LSApplicationWorkspaceCanOpenURL(hooks);
}
