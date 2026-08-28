#import "hooks.h"

IMP (*original_method_getImplementation)(Method m);

static IMP replaced_method_getImplementation_detector(Method method) {
    IMP current = original_method_getImplementation(method);
    if(!isCallerExternal()) return current;

    IMP original = SHDWOriginalImplementationForMethod(method);
    return original ?: current;
}

// The generic path stays native: returning NULL for a hidden IMP breaks
// legitimate swizzlers. Detector-integrity Tier 2 may rebind this API to the
// type-correct predecessors recorded by SHDWHookSession.
void shadowhook_objc_methodimpl(SHDWHookSession* hooks) {
    (void)hooks;

    if(!original_method_getImplementation) {
        original_method_getImplementation = method_getImplementation;
    }
}

void shadowhook_objc_methodimpl_detector(SHDWHookSession* hooks) {
    shadowhook_objc_methodimpl(hooks);
    [hooks hookRebindSymbol:@"method_getImplementation"
            withReplacement:replaced_method_getImplementation_detector
                   outOldPtr:NULL];
}
