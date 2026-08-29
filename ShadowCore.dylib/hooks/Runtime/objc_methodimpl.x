#import "hooks.h"

IMP (*original_method_getImplementation)(Method m);

static IMP replaced_method_getImplementation_detector(Method method) {
    IMP current = original_method_getImplementation(method);
    if(!isCallerExternal()) return current;

    IMP original = SHDWOriginalImplementationForMethod(method);
    if (original) return original;

    // HookKit %hook for UIApplication.canOpenURL and NSFileManager.fileExists
    // are not in SHDW table (hookkit stores original in its own slot). Use
    // the captured originals from AppEnvironment.x for those specific selectors.
    SEL sel = method ? method_getName(method) : NULL;
    if (sel) {
        if (sel == sel_registerName("canOpenURL:")) {
            void *hookOrig = shdw_UIApplicationCanOpenURLOriginal();
            if (hookOrig) return (IMP)hookOrig;
        }
        if (sel == sel_registerName("fileExistsAtPath:")) {
            void *hookOrig = shdw_NSFileManagerFileExistsOriginal();
            if (hookOrig) return (IMP)hookOrig;
        }
    }
    return current;
}

// Promoted to Always for swizzling stealth: every external caller sees the
// original IMP via SHDWOriginalImplementationForMethod, hiding HookKit's
// %hook replacements (UIApplication.canOpenURL etc.) from
// DeviceSecurityKit-style dladdr checks. Tier2 keeps the same hook for
// detector escalation symmetry.
void shadowhook_objc_methodimpl(SHDWHookSession* hooks) {
    if(!original_method_getImplementation) {
        original_method_getImplementation = method_getImplementation;
    }
    [hooks hookRebindSymbol:@"method_getImplementation"
            withReplacement:replaced_method_getImplementation_detector
                   outOldPtr:NULL];
}

void shadowhook_objc_methodimpl_detector(SHDWHookSession* hooks) {
    shadowhook_objc_methodimpl(hooks);
    [hooks hookRebindSymbol:@"method_getImplementation"
            withReplacement:replaced_method_getImplementation_detector
                   outOldPtr:NULL];
}
