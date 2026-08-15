#import "hooks.h"

IMP (*original_method_getImplementation)(Method m);

// method_getImplementation has no declaring-Class argument. Interposing it
// to hide Shadow-owned IMPs therefore breaks legitimate swizzlers on public
// classes: they get a NULL predecessor and later branch through address 0.
// Keep the native API live and retain hiding in the class-aware metadata hooks.
void shadowhook_objc_methodimpl(HKSubstitutor* hooks) {
    (void)hooks;

    if(!original_method_getImplementation) {
        original_method_getImplementation = method_getImplementation;
    }
}
