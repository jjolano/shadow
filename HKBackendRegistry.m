#import "Internal/HKBackendInternal.h"

#import <dlfcn.h>

#import "native/hk_native.h"
#import "native/hk_swift.h"

#pragma mark - Backend registry

// One table drives selection, availability, type reporting and the info dicts;
// adding a backend is one entry here plus its picker rows in
// hk_category_priorities (the single source of truth for category membership).
// Order is priority order.

// fishhook is compiled in, so it is the floor that is always present.
static BOOL fishhook_available(void) {
    return YES;
}

// litehook is compiled in and available on all archs.
static BOOL litehook_available(void) {
    return YES;
}

static BOOL native_available(void) {
    return hk_native_supported() ? YES : NO;
}

// Swift vtables: available when the arch supports the engine (arm64/arm64e),
// the Swift 5 ABI runtime is present (iOS 12.2+), and swift_demangle
// resolves. libswiftCore is a plain system dylib — never a jailbreak path,
// so no RootBridge. The probe result is cached unconditionally, success or
// failure: a Swift runtime that appears after the first probe is not retried.
static BOOL swift_available(void) {
    static BOOL cached = NO;
    static BOOL available = NO;

    if(cached) {
        return available;
    }

    if(hk_swift_supported()) {
        if(@available(iOS 12.2, *)) {
            hk_swift_demangle = (hk_swift_demangle_fn)dlsym(RTLD_DEFAULT, "swift_demangle");

            if(!hk_swift_demangle) {
                void *core = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_LAZY);

                if(core) {
                    hk_swift_demangle = (hk_swift_demangle_fn)dlsym(core, "swift_demangle");
                }
            }

            available = hk_swift_demangle != NULL;
        }
    }

    cached = YES;

    return available;
}

// Dobby is compiled in on arm64/arm64e only (the vendored static lib has no
// armv7 slice); the table entry stays on every arch so the count is stable.
static BOOL dobby_available(void) {
#if defined(__arm64__) || defined(__arm64e__)
    return YES;
#else
    return NO;
#endif
}

const HKBackendDescriptor *hk_backends(size_t *outCount) {
    static HKBackendDescriptor table[9];
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        table[0] = (HKBackendDescriptor){ HK_LIB_ELLEKIT, [HKElleKitBackend class], @"ellekit", @"ElleKit", libhooker_available, YES, YES };
        table[1] = (HKBackendDescriptor){ HK_LIB_SUBSTRATE, [HKSubstrateBackend class], @"substrate", @"Cydia Substrate", substrate_available, YES, NO };
        table[2] = (HKBackendDescriptor){ HK_LIB_SUBSTITUTE, [HKSubstituteBackend class], @"substitute", @"Substitute", substitute_available, YES, NO };
        // Never automatic: HookKit's own engine is opt-in so that devices with
        // a battle-tested library installed keep using it.
        table[3] = (HKBackendDescriptor){ HK_LIB_NATIVE, [HKNativeBackend class], @"native", @"HookKit", native_available, NO, YES };
        table[4] = (HKBackendDescriptor){ HK_LIB_DOBBY, [HKDobbyBackend class], @"dobby", @"Dobby", dobby_available, YES, YES };
        // Never automatic: Frida is opt-in — Dobby is compiled in and lighter;
        // Frida is the premium arm64e-tested engine users request explicitly.
        table[5] = (HKBackendDescriptor){ HK_LIB_FRIDA, [HKFridaBackend class], @"frida", @"Frida", frida_available, NO, YES };
        table[6] = (HKBackendDescriptor){ HK_LIB_FISHHOOK, [HKFishhookBackend class], @"fishhook", @"fishhook", fishhook_available, YES, YES };
        // Never automatic: Swift vtable hooks are a separate API (no
        // message/function overlap) and only make sense when the caller has a
        // Swift class in hand, so this backend is opt-in.
        table[7] = (HKBackendDescriptor){ HK_LIB_SWIFT, [HKSwiftBackend class], @"swift", @"Swift vtables", swift_available, NO, NO };
        // Never automatic: litehook is opt-in — fishhook is the compiled-in
        // function-rebind floor; litehook adds memory patching on all archs,
        // plus inline and private-symbol techniques for its category entries.
        table[8] = (HKBackendDescriptor){ HK_LIB_LITEHOOK, [HKLitehookBackend class], @"litehook", @"litehook", litehook_available, NO, YES };
    });

    *outCount = sizeof(table) / sizeof(table[0]);
    return table;
}

#pragma mark - Category priorities

// Per-category priority order, as (backend, technique) pairs: each entry
// lists the pickers that satisfy the category, in the order they are tried
// (first available wins). The strategy is passed to the backend when it
// implements setStrategy:; backends without it use their vendor default
// technique. The order matches the main hk_backends table priority within
// each category.
// Single source of truth for category membership: getAvailableCategories
// derives availability from this table alone, and HKBackendDescriptor carries
// no category bits, so the two views cannot diverge.
const HKCategoryPriority hk_category_priorities[] = {
    { HK_CAT_MESSAGE,         { {HK_LIB_ELLEKIT, HKStrategyDefault}, {HK_LIB_SUBSTRATE, HKStrategyDefault}, {HK_LIB_SUBSTITUTE, HKStrategyDefault}, {HK_LIB_NATIVE, HKStrategyDefault} }, 4 },
    { HK_CAT_FUNCTION_REBIND, { {HK_LIB_FISHHOOK, HKStrategyRebind}, {HK_LIB_LITEHOOK, HKStrategyRebind} }, 2 },
    // Prologue inline trampolines are AArch64-only: litehook, Dobby and Frida
    // emit AArch64 instructions unconditionally, so litehook's picker is
    // arm64/arm64e-only. On 32-bit archs ElleKit, Dobby and Frida still cover
    // the category, and Dobby/Frida report unavailable at runtime, so no
    // resolution can select HKStrategyInline there.
    { HK_CAT_FUNCTION_INLINE, { {HK_LIB_ELLEKIT, HKStrategyInline}, {HK_LIB_DOBBY, HKStrategyInline}, {HK_LIB_FRIDA, HKStrategyInline},
#if defined(__arm64__) || defined(__arm64e__)
                                {HK_LIB_LITEHOOK, HKStrategyInline} },
                               4 },
#else
                                // litehook's inline trampoline emits AArch64
                                // opcodes only (see HKLitehookBackend), so its
                                // inline picker is arm64/arm64e-only; on 32-bit
                                // archs ElleKit, Dobby and Frida still cover
                                // the category. litehook rebind and memory use
                                // stay available on 32-bit.
                                },
                               3 },
#endif
#if defined(__arm64__) || defined(__arm64e__)
    { HK_CAT_PRIVATE_SYMBOL,  { {HK_LIB_ELLEKIT, HKStrategyPrivateSymbol}, {HK_LIB_SUBSTRATE, HKStrategyPrivateSymbol}, {HK_LIB_SUBSTITUTE, HKStrategyPrivateSymbol}, {HK_LIB_LITEHOOK, HKStrategyPrivateSymbol} }, 4 },
#else
    // litehook's DSC private-symbol lookup hardcodes 64-bit structures
    // (mach_header_64 / LC_SEGMENT_64 / section_64 / nlist_64), so on 32-bit
    // archs the private-symbol category drops the litehook picker — ElleKit,
    // Substrate and Substitute still cover it. Explicit litehook rebind and
    // memory use stays available on 32-bit; only this category picker is out.
    { HK_CAT_PRIVATE_SYMBOL,  { {HK_LIB_ELLEKIT, HKStrategyPrivateSymbol}, {HK_LIB_SUBSTRATE, HKStrategyPrivateSymbol}, {HK_LIB_SUBSTITUTE, HKStrategyPrivateSymbol} }, 3 },
#endif
};
const size_t hk_category_priority_count = sizeof(hk_category_priorities) / sizeof(hk_category_priorities[0]);