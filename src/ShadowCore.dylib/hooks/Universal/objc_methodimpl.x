#import "UniversalHooks.h"

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
            void *hookOrig = SHDWCanOpenURLOriginal();
            if (hookOrig) return (IMP)hookOrig;
        }
        if (sel == sel_registerName("fileExistsAtPath:")) {
            void *hookOrig = shdw_universal_file_exists_original();
            if (hookOrig) return (IMP)hookOrig;
        }
    }
    return current;
}

// Promoted to Always for swizzling stealth: every external caller sees the
// original IMP via SHDWOriginalImplementationForMethod, hiding HookKit's
// %hook replacements (UIApplication.canOpenURL etc.) from
// Adapter-side dladdr checks. Tier2 keeps the same hook for
// detector escalation symmetry.
void shdw_universal_objc_methodimpl(SHDWHookSession* hooks) {
    if(!original_method_getImplementation) {
        original_method_getImplementation = method_getImplementation;
    }
    [hooks hookRebindSymbol:@"method_getImplementation"
            withReplacement:replaced_method_getImplementation_detector
                   outOldPtr:NULL];
}

void shdw_universal_objc_methodimpl_detector(SHDWHookSession* hooks) {
    // The ctor already installs this rebind. Repeating the same HookKit
    // request back-to-back can invalidate the existing import-slot plan.
    shdw_universal_objc_methodimpl(hooks);
}

// Rebind method_getImplementation in a specific (late-loaded) detector image so
// a framework dlopen'd after the ctor still sees the original IMP for hooked
// methods (swizzling stealth). Pairs with shdw_universal_objc_rebind_image.
void shdw_universal_objc_methodimpl_rebind_image(SHDWHookSession* hooks, const void* imageHeader) {
    if(!imageHeader) return;
    if(!original_method_getImplementation) {
        original_method_getImplementation = method_getImplementation;
    }
    [hooks hookRebindSymbol:@"method_getImplementation"
            withReplacement:replaced_method_getImplementation_detector
                   outOldPtr:NULL
              inCallerImage:imageHeader];
}
