#import "hooks.h"

// %group shadowhook_objc
// %hook NSObject
// + (Class)class {
//     Class result = %orig;

//     if(!isCallerExternal() && [_shadow isAddrRestricted:(__bridge const void *)result]) {
//         return nil;
//     }

//     return result;
// }
// %end
// %end

static const char* (*original_class_getImageName)(Class cls);
static const char* replaced_class_getImageName(Class cls) {
    // C0-2: Shadow's own code sees truth; every other caller is filtered.
    if(!isCallerExternal()) {
        return original_class_getImageName(cls);
    }

    // Protected class (its data lives in a protected image): report "no
    // image" — NULL, never a fake executable path (plan Wave 1c).
    if([_shadow isAddrRestricted:(__bridge const void *)cls]) {
        return NULL;
    }

    const char* result = original_class_getImageName(cls);

    if(result && [_shadow isProtectedImagePath:@(result)]) {
        return NULL;
    }

    return result;
}

static const char * _Nonnull * (*original_objc_copyImageNames)(unsigned int *outCount);
static const char * _Nonnull * replaced_objc_copyImageNames(unsigned int *outCount) {
    if(!isCallerExternal()) {
        return original_objc_copyImageNames(outCount);
    }

    // Always resolve through a local count (the original rejects
    // outCount == NULL), then build a malloc'd NULL-terminated filtered copy
    // with strdup'd names (the originals are owned by the original array) and
    // free the original. outCount == NULL still gets the FILTERED array, and
    // *outCount is only written when non-NULL. The old truncate-at-exec
    // heuristic is gone (plan Wave 1c).
    unsigned int localCount = 0;
    const char **result = original_objc_copyImageNames(&localCount);

    if(!result) {
        if(outCount) {
            *outCount = 0;
        }

        return NULL;
    }

    const char **filtered = malloc(((size_t)localCount + 1) * sizeof(char *));

    if(!filtered) {
        // malloc failure: fail soft with the stock list (the process is OOM).
        if(outCount) {
            *outCount = localCount;
        }

        return result;
    }

    unsigned int n = 0;

    for(unsigned int i = 0; i < localCount; i++) {
        const char* name = result[i];

        if(!name || [_shadow isProtectedImagePath:@(name)]) {
            continue;
        }

        filtered[n] = strdup(name);
        n++;
    }

    filtered[n] = NULL;
    free(result);

    if(outCount) {
        *outCount = n;
    }

    return filtered;
}

static const char * _Nonnull * (*original_objc_copyClassNamesForImage)(const char* image, unsigned int *outCount);
static const char * _Nonnull * replaced_objc_copyClassNamesForImage(const char* image, unsigned int *outCount) {
    if(!isCallerExternal()) {
        return original_objc_copyClassNamesForImage(image, outCount);
    }

    if([_shadow isProtectedImagePath:@(image)]) {
        // Zero the count before returning NULL so callers can't misread a
        // stale count (plan Wave 1c).
        if(outCount) {
            *outCount = 0;
        }

        return NULL;
    }

    return original_objc_copyClassNamesForImage(image, outCount);
}

static Class (*original_NSClassFromString)(NSString* aClassName);
static Class replaced_NSClassFromString(NSString* aClassName) {
    // C0-2: Shadow's own code sees truth; every other caller is filtered.
    if(!isCallerExternal()) {
        return original_NSClassFromString(aClassName);
    }

    Class result = original_NSClassFromString(aClassName);

    if([_shadow isAddrRestricted:(__bridge const void *)result]) {
        return nil;
    }

    return result;
}

// --- Class lookup / enumeration (plan Wave 1c): the result's image is
// classified, so classes whose data lives in a protected image (Shadow,
// HookKit, RootBridge, libSandy, substrate/substitute/ellekit) never resolve
// for external callers. objc_getRequiredClass is deliberately NOT hooked: it
// aborts the process when the class is missing, so a suppressed class would
// turn a benign miss into a hard crash (its fatal contract) — and its abort
// semantics make it a useless probe for a detector that wants a clean
// yes/no signal.

static Class (*original_objc_getClass)(const char* name);
static Class replaced_objc_getClass(const char* name) {
    if(!isCallerExternal()) {
        return original_objc_getClass(name);
    }

    Class result = original_objc_getClass(name);

    if(result && [_shadow isAddrRestricted:(__bridge const void *)result]) {
        return Nil;
    }

    return result;
}

static Class (*original_objc_lookUpClass)(const char* name);
static Class replaced_objc_lookUpClass(const char* name) {
    if(!isCallerExternal()) {
        return original_objc_lookUpClass(name);
    }

    Class result = original_objc_lookUpClass(name);

    if(result && [_shadow isAddrRestricted:(__bridge const void *)result]) {
        return Nil;
    }

    return result;
}

static Class (*original_objc_getMetaClass)(const char* name);
static Class replaced_objc_getMetaClass(const char* name) {
    if(!isCallerExternal()) {
        return original_objc_getMetaClass(name);
    }

    Class result = original_objc_getMetaClass(name);

    if(result && [_shadow isAddrRestricted:(__bridge const void *)result]) {
        return Nil;
    }

    return result;
}

static int (*original_objc_getClassList)(Class* buffer, int bufferCount);
static int replaced_objc_getClassList(Class* buffer, int bufferCount) {
    if(!isCallerExternal()) {
        return original_objc_getClassList(buffer, bufferCount);
    }

    // Two-phase: pull the full list through a scratch buffer, drop protected
    // classes, fill at most bufferCount and return the FILTERED total.
    int total = original_objc_getClassList(NULL, 0);

    if(total <= 0) {
        return 0;
    }

    Class* all = (Class *)malloc((size_t)total * sizeof(Class));

    if(!all) {
        // malloc failure: fail soft with the stock behavior.
        return original_objc_getClassList(buffer, bufferCount);
    }

    int filled = original_objc_getClassList(all, total);
    int n = 0;

    for(int i = 0; i < filled; i++) {
        if([_shadow isAddrRestricted:(__bridge const void *)all[i]]) {
            continue;
        }

        all[n++] = all[i];
    }

    if(buffer && bufferCount > 0) {
        memcpy(buffer, all, (size_t)MIN(n, bufferCount) * sizeof(Class));
    }

    free(all);
    return n;
}

static Class* (*original_objc_copyClassList)(unsigned int* outCount);
static Class* replaced_objc_copyClassList(unsigned int* outCount) {
    if(!isCallerExternal()) {
        return original_objc_copyClassList(outCount);
    }

    int total = original_objc_getClassList(NULL, 0);

    if(total <= 0) {
        if(outCount) {
            *outCount = 0;
        }

        return NULL;
    }

    Class* all = (Class *)malloc((size_t)total * sizeof(Class));

    if(!all) {
        return original_objc_copyClassList(outCount);   // fail soft
    }

    int filled = original_objc_getClassList(all, total);
    Class* filtered = (Class *)malloc(((size_t)total + 1) * sizeof(Class));

    if(!filtered) {
        free(all);
        return original_objc_copyClassList(outCount);   // fail soft
    }

    unsigned int n = 0;

    for(int i = 0; i < filled; i++) {
        if([_shadow isAddrRestricted:(__bridge const void *)all[i]]) {
            continue;
        }

        filtered[n++] = all[i];
    }

    filtered[n] = NULL;
    free(all);

    if(outCount) {
        *outCount = n;
    }

    return filtered;
}

// iOS 16+ (resolved at install like imp_getBlock; older OSes skip it).
static void (*original_objc_enumerateClasses)(const void* image, const char* namePrefix, Protocol* conformingTo, Class subclassing, void (^block)(Class aClass, BOOL* stop));
static void replaced_objc_enumerateClasses(const void* image, const char* namePrefix, Protocol* conformingTo, Class subclassing, void (^block)(Class aClass, BOOL* stop)) {
    if(!isCallerExternal() || !block) {
        return original_objc_enumerateClasses(image, namePrefix, conformingTo, subclassing, block);
    }

    // Wrap the caller's block: suppress protected classes (without touching
    // *stop) and forward everything else with the SAME stop pointer so the
    // caller's stop=YES propagates to the runtime.
    original_objc_enumerateClasses(image, namePrefix, conformingTo, subclassing, ^(Class aClass, BOOL* stop) {
        if([_shadow isAddrRestricted:(__bridge const void *)aClass]) {
            return;
        }

        block(aClass, stop);
    });
}

// NXMapGet/NXHashGet hooks removed (plan Wave 1a): dead class-hiding path —
// internal runtime callers are exempt by C0-2 classification and the hooks
// had broad runtime interference for no reachable detector surface.

static IMP (*original_method_getImplementation)(Method m);
static IMP replaced_method_getImplementation(Method m) {
    // C0-2: Shadow's own code sees truth; every other caller is filtered.
    if(!isCallerExternal()) {
        return original_method_getImplementation(m);
    }

    IMP result = original_method_getImplementation(m);

    // Classify the Method (its storage lives in the owning image's data) AND
    // the returned IMP: a protected Method or IMP must never resolve. NULL,
    // not a fabricated "native-looking" IMP — the header cast was a fake that
    // detectors could still fingerprint (plan Wave 1b).
    if([_shadow isAddrRestricted:(void *)m] || [_shadow isAddrRestricted:(void *)result]) {
        return NULL;
    }

    return result;
}

static IMP (*original_class_getMethodImplementation)(Class cls, SEL name);
static IMP replaced_class_getMethodImplementation(Class cls, SEL name) {
    if(!isCallerExternal()) {
        return original_class_getMethodImplementation(cls, name);
    }

    IMP result = original_class_getMethodImplementation(cls, name);

    // Same policy as replaced_method_getImplementation: the class, and the
    // IMP it resolves to, must both be unprotected.
    if([_shadow isAddrRestricted:(__bridge const void *)cls] || [_shadow isAddrRestricted:(void *)result]) {
        return NULL;
    }

    return result;
}

// imp_getBlock is not a linkable symbol on all SDKs (added in iOS 16), so
// resolve it at runtime like dyld.x does for dlopen_internal, and guard NULL.
// Block ABI layout: isa, flags, reserved, invoke (offset 16).
typedef struct {
    void* isa;
    int flags;
    int reserved;
    void* invoke;
} shdw_block_layout_t;

static id (*original_imp_getBlock)(IMP anImp);
static id replaced_imp_getBlock(IMP anImp) {
    // C0-2: Shadow's own code sees truth; every other caller is filtered.
    if(!isCallerExternal()) {
        return original_imp_getBlock(anImp);
    }

    // Call the original with the correct id signature, then classify the
    // returned block's ABI invoke pointer (offset 16) — NOT the trampoline
    // IMP: an IMP created from a protected block must not be revealed, and
    // the trampoline's image says nothing about the block it dispatches to
    // (plan Wave 2).
    id block = original_imp_getBlock(anImp);

    if(!block) {
        return nil;
    }

    shdw_block_layout_t* layout = (__bridge shdw_block_layout_t *)block;

    if([_shadow isAddrRestricted:layout->invoke]) {
        return nil;
    }

    return block;
}

void shadowhook_objc(HKSubstitutor* hooks) {
    // %init(shadowhook_objc);
    MSHookFunction(class_getImageName, replaced_class_getImageName, (void **) &original_class_getImageName);
    MSHookFunction(objc_copyClassNamesForImage, replaced_objc_copyClassNamesForImage, (void **) &original_objc_copyClassNamesForImage);
    MSHookFunction(objc_copyImageNames, replaced_objc_copyImageNames, (void **) &original_objc_copyImageNames);
    MSHookFunction(method_getImplementation, replaced_method_getImplementation, (void **) &original_method_getImplementation);
    MSHookFunction(class_getMethodImplementation, replaced_class_getMethodImplementation, (void **) &original_class_getMethodImplementation);

    void* imp_getBlock_ptr = dlsym(RTLD_DEFAULT, "imp_getBlock");
    if(imp_getBlock_ptr) {
        MSHookFunction(imp_getBlock_ptr, replaced_imp_getBlock, (void **) &original_imp_getBlock);
    }
}

void shadowhook_objc_hidetweakclasses(HKSubstitutor* hooks) {
    MSHookFunction(NSClassFromString, replaced_NSClassFromString, (void **) &original_NSClassFromString);

    // Class lookup / enumeration (plan Wave 1c). objc_getRequiredClass is
    // skipped: its fatal contract (abort on missing class) makes a filtered
    // miss a crash, and it is not a usable probe.
    MSHookFunction(objc_getClass, replaced_objc_getClass, (void **) &original_objc_getClass);
    MSHookFunction(objc_lookUpClass, replaced_objc_lookUpClass, (void **) &original_objc_lookUpClass);
    MSHookFunction(objc_getMetaClass, replaced_objc_getMetaClass, (void **) &original_objc_getMetaClass);
    MSHookFunction(objc_getClassList, replaced_objc_getClassList, (void **) &original_objc_getClassList);
    MSHookFunction(objc_copyClassList, replaced_objc_copyClassList, (void **) &original_objc_copyClassList);

    void* enumerateClassesPtr = dlsym(RTLD_DEFAULT, "objc_enumerateClasses");

    if(enumerateClassesPtr) {
        MSHookFunction(enumerateClassesPtr, replaced_objc_enumerateClasses, (void **) &original_objc_enumerateClasses);
    }
}
