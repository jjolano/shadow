#import "hooks.h"

void shadowhook_IOSSecuritySuite(SHDWHookSession* hooks) {
    shadowhook_libc_iossecuritysuite(hooks);
    shadowhook_NSFileManagerSymbolicLinks(hooks);
    shadowhook_LSApplicationWorkspaceCanOpenURL(hooks);
}
