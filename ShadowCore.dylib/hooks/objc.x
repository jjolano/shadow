#import "hooks.h"

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
    // and free the original. The name strings are BORROWED, not strdup'd:
    // objc_copyImageNames copies only the pointer array — the strings live in
    // the runtime's per-image storage and outlive the array, the same
    // lifetime stock callers rely on (they free() only the array, so strdup'd
    // strings would leak on every call). outCount == NULL still gets the
    // FILTERED array, and *outCount is only written when non-NULL. The old
    // truncate-at-exec heuristic is gone (plan Wave 1c).
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

        filtered[n] = name;
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
// HookKit, libSandy, substrate/substitute/ellekit) never resolve
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

// --- Method metadata (plan Wave 3): class_copyMethodList,
// class_getInstanceMethod/class_getClassMethod,
// _method_getImplementationAndName, class_getMethodImplementation_stret and
// the two objc_copy*ForImage[Header] SPIs must not surface protected
// classes, Methods or IMPs.

// Defined with the item-3 method_getImplementation hook below.
static IMP (*original_method_getImplementation)(Method m);

static Method* (*original_class_copyMethodList)(Class cls, unsigned int* outCount);
static Method* replaced_class_copyMethodList(Class cls, unsigned int* outCount) {
    if(!isCallerExternal()) {
        return original_class_copyMethodList(cls, outCount);
    }

    if([_shadow isAddrRestricted:(__bridge const void *)cls]) {
        if(outCount) {
            *outCount = 0;
        }

        return NULL;
    }

    unsigned int localCount = 0;
    Method* result = original_class_copyMethodList(cls, &localCount);

    if(!result || localCount == 0) {
        if(outCount) {
            *outCount = localCount;
        }

        return result;
    }

    // Filter protected entries in place (the array is caller-freed): a benign
    // class can carry Methods whose IMPs live in protected images (e.g.
    // block-based methods backed by a protected library).
    unsigned int n = 0;

    for(unsigned int i = 0; i < localCount; i++) {
        IMP imp = original_method_getImplementation(result[i]);

        if([_shadow isAddrRestricted:(void *)result[i]] || [_shadow isAddrRestricted:(void *)imp]) {
            continue;
        }

        result[n++] = result[i];
    }

    result[n] = NULL;

    if(outCount) {
        *outCount = n;
    }

    return result;
}

static Method (*original_class_getInstanceMethod)(Class cls, SEL name);
static Method replaced_class_getInstanceMethod(Class cls, SEL name) {
    if(!isCallerExternal()) {
        return original_class_getInstanceMethod(cls, name);
    }

    Method result = original_class_getInstanceMethod(cls, name);

    if([_shadow isAddrRestricted:(__bridge const void *)cls]
    || [_shadow isAddrRestricted:(void *)result]
    || [_shadow isAddrRestricted:(void *)original_method_getImplementation(result)]) {
        return NULL;
    }

    return result;
}

static Method (*original_class_getClassMethod)(Class cls, SEL name);
static Method replaced_class_getClassMethod(Class cls, SEL name) {
    if(!isCallerExternal()) {
        return original_class_getClassMethod(cls, name);
    }

    Method result = original_class_getClassMethod(cls, name);

    if([_shadow isAddrRestricted:(__bridge const void *)cls]
    || [_shadow isAddrRestricted:(void *)result]
    || [_shadow isAddrRestricted:(void *)original_method_getImplementation(result)]) {
        return NULL;
    }

    return result;
}

// Private libobjc export (Swift runtime); resolved at install.
static IMP (*original_method_getImplementationAndName)(Method m, SEL* nameOut);
static IMP replaced_method_getImplementationAndName(Method m, SEL* nameOut) {
    if(!isCallerExternal()) {
        return original_method_getImplementationAndName(m, nameOut);
    }

    IMP result = original_method_getImplementationAndName(m, nameOut);

    if([_shadow isAddrRestricted:(void *)m] || [_shadow isAddrRestricted:(void *)result]) {
        if(nameOut) {
            *nameOut = NULL;
        }

        return NULL;
    }

    return result;
}

static IMP (*original_class_getMethodImplementation_stret)(Class cls, SEL name);
static IMP replaced_class_getMethodImplementation_stret(Class cls, SEL name) {
    if(!isCallerExternal()) {
        return original_class_getMethodImplementation_stret(cls, name);
    }

    IMP result = original_class_getMethodImplementation_stret(cls, name);

    if([_shadow isAddrRestricted:(__bridge const void *)cls] || [_shadow isAddrRestricted:(void *)result]) {
        return NULL;
    }

    return result;
}

static Class* (*original_objc_copyClassesForImage)(const char* image, unsigned int* outCount);
static Class* replaced_objc_copyClassesForImage(const char* image, unsigned int* outCount) {
    if(!isCallerExternal()) {
        return original_objc_copyClassesForImage(image, outCount);
    }

    if([_shadow isProtectedImagePath:@(image)]) {
        if(outCount) {
            *outCount = 0;
        }

        return NULL;
    }

    return original_objc_copyClassesForImage(image, outCount);
}

static const char** (*original_objc_copyClassNamesForImageHeader)(const struct mach_header* mh, unsigned int* outCount);
static const char** replaced_objc_copyClassNamesForImageHeader(const struct mach_header* mh, unsigned int* outCount) {
    if(!isCallerExternal()) {
        return original_objc_copyClassNamesForImageHeader(mh, outCount);
    }

    if(!mh || [_shadow isAddrRestricted:mh]) {
        if(outCount) {
            *outCount = 0;
        }

        return NULL;
    }

    return original_objc_copyClassNamesForImageHeader(mh, outCount);
}

// --- objc_setHook_getImageName / objc_setHook_getClass (plan Wave 3): the
// chained-hook SPIs hand out the PREVIOUS hook as outOldValue — a detector
// chaining through it would reach the native implementation and observe true
// image names/classes for protected images. Untrusted callers get a stable
// filtered proxy instead (never the native predecessor); trusted
// platform-runtime callers (libobjc/libSystem) pass through. The native
// predecessors are captured at install through the original setters, which
// are then restored as the current hooks so the class_getImageName /
// objc_getClass hot paths stay on the native implementations until a
// detector actually sets a hook.

static BOOL (*shdw_native_getImageName)(Class cls, const char** outImageName);
static BOOL (*shdw_native_getClass)(const char* name, Class* outClass);

// True when the caller of the current hook is the platform runtime itself
// (libobjc / libSystem) — those may chain their own hooks and must see the
// real predecessor.
static BOOL shdw_caller_is_platform_runtime(void) {
    const char* callerPath = dyld_image_path_containing_address(__builtin_extract_return_addr(__builtin_return_address(0)));

    if(!callerPath) {
        return NO;
    }

    NSString* lower = [[NSString stringWithUTF8String:callerPath] lowercaseString];
    return [lower containsString:@"libobjc"] || [lower containsString:@"libsystem"];
}

static BOOL shdw_getImageName_proxy(Class cls, const char** outImageName) {
    if([_shadow isAddrRestricted:(__bridge const void *)cls]) {
        return NO;
    }

    return shdw_native_getImageName ? shdw_native_getImageName(cls, outImageName) : NO;
}

static BOOL shdw_getClass_proxy(const char* name, Class* outClass) {
    Class result = Nil;

    if(!shdw_native_getClass || !shdw_native_getClass(name, &result)) {
        return NO;
    }

    if(result && [_shadow isAddrRestricted:(__bridge const void *)result]) {
        return NO;
    }

    if(outClass) {
        *outClass = result;
    }

    return YES;
}

static void (*original_objc_setHook_getImageName)(objc_hook_getImageName newValue, objc_hook_getImageName* outOldValue);
static void replaced_objc_setHook_getImageName(objc_hook_getImageName newValue, objc_hook_getImageName* outOldValue) {
    if(!isCallerExternal() || shdw_caller_is_platform_runtime()) {
        return original_objc_setHook_getImageName(newValue, outOldValue);
    }

    // Untrusted: install their hook (chain preserved), hand out the proxy.
    objc_hook_getImageName previous = NULL;
    original_objc_setHook_getImageName(newValue, &previous);

    if(outOldValue) {
        *outOldValue = shdw_getImageName_proxy;
    }
}

static void (*original_objc_setHook_getClass)(objc_hook_getClass newValue, objc_hook_getClass* outOldValue);
static void replaced_objc_setHook_getClass(objc_hook_getClass newValue, objc_hook_getClass* outOldValue) {
    if(!isCallerExternal() || shdw_caller_is_platform_runtime()) {
        return original_objc_setHook_getClass(newValue, outOldValue);
    }

    objc_hook_getClass previous = NULL;
    original_objc_setHook_getClass(newValue, &previous);

    if(outOldValue) {
        *outOldValue = shdw_getClass_proxy;
    }
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
    [hooks hookFunction:class_getImageName withReplacement:replaced_class_getImageName outOldPtr:(void **) &original_class_getImageName];
    [hooks hookFunction:objc_copyClassNamesForImage withReplacement:replaced_objc_copyClassNamesForImage outOldPtr:(void **) &original_objc_copyClassNamesForImage];
    [hooks hookFunction:objc_copyImageNames withReplacement:replaced_objc_copyImageNames outOldPtr:(void **) &original_objc_copyImageNames];
    [hooks hookFunction:method_getImplementation withReplacement:replaced_method_getImplementation outOldPtr:(void **) &original_method_getImplementation];
    [hooks hookFunction:class_getMethodImplementation withReplacement:replaced_class_getMethodImplementation outOldPtr:(void **) &original_class_getMethodImplementation];

    void* imp_getBlock_ptr = dlsym(RTLD_DEFAULT, "imp_getBlock");
    if(imp_getBlock_ptr) {
        [hooks hookFunction:imp_getBlock_ptr withReplacement:replaced_imp_getBlock outOldPtr:(void **) &original_imp_getBlock];
    }
}

void shadowhook_objc_hidetweakclasses(HKSubstitutor* hooks) {
    [hooks hookFunction:NSClassFromString withReplacement:replaced_NSClassFromString outOldPtr:(void **) &original_NSClassFromString];

    // Class lookup / enumeration (plan Wave 1c). objc_getRequiredClass is
    // skipped: its fatal contract (abort on missing class) makes a filtered
    // miss a crash, and it is not a usable probe.
    [hooks hookFunction:objc_getClass withReplacement:replaced_objc_getClass outOldPtr:(void **) &original_objc_getClass];
    [hooks hookFunction:objc_lookUpClass withReplacement:replaced_objc_lookUpClass outOldPtr:(void **) &original_objc_lookUpClass];
    [hooks hookFunction:objc_getMetaClass withReplacement:replaced_objc_getMetaClass outOldPtr:(void **) &original_objc_getMetaClass];
    [hooks hookFunction:objc_getClassList withReplacement:replaced_objc_getClassList outOldPtr:(void **) &original_objc_getClassList];
    [hooks hookFunction:objc_copyClassList withReplacement:replaced_objc_copyClassList outOldPtr:(void **) &original_objc_copyClassList];

    void* enumerateClassesPtr = dlsym(RTLD_DEFAULT, "objc_enumerateClasses");

    if(enumerateClassesPtr) {
        [hooks hookFunction:enumerateClassesPtr withReplacement:replaced_objc_enumerateClasses outOldPtr:(void **) &original_objc_enumerateClasses];
    }

    // Method metadata (plan Wave 3).
    [hooks hookFunction:class_copyMethodList withReplacement:replaced_class_copyMethodList outOldPtr:(void **) &original_class_copyMethodList];
    [hooks hookFunction:class_getInstanceMethod withReplacement:replaced_class_getInstanceMethod outOldPtr:(void **) &original_class_getInstanceMethod];
    [hooks hookFunction:class_getClassMethod withReplacement:replaced_class_getClassMethod outOldPtr:(void **) &original_class_getClassMethod];

    void* methodImplAndNamePtr = dlsym(RTLD_DEFAULT, "_method_getImplementationAndName");

    if(methodImplAndNamePtr) {
        [hooks hookFunction:methodImplAndNamePtr withReplacement:replaced_method_getImplementationAndName outOldPtr:(void **) &original_method_getImplementationAndName];
    }

    void* stretPtr = dlsym(RTLD_DEFAULT, "class_getMethodImplementation_stret");

    if(stretPtr) {
        [hooks hookFunction:stretPtr withReplacement:replaced_class_getMethodImplementation_stret outOldPtr:(void **) &original_class_getMethodImplementation_stret];
    }

    void* copyClassesForImagePtr = dlsym(RTLD_DEFAULT, "objc_copyClassesForImage");

    if(copyClassesForImagePtr) {
        [hooks hookFunction:copyClassesForImagePtr withReplacement:replaced_objc_copyClassesForImage outOldPtr:(void **) &original_objc_copyClassesForImage];
    }

    void* copyClassNamesForImageHeaderPtr = dlsym(RTLD_DEFAULT, "objc_copyClassNamesForImageHeader");

    if(copyClassNamesForImageHeaderPtr) {
        [hooks hookFunction:copyClassNamesForImageHeaderPtr withReplacement:replaced_objc_copyClassNamesForImageHeader outOldPtr:(void **) &original_objc_copyClassNamesForImageHeader];
    }

    // Chained-hook SPIs (plan Wave 3): capture the native predecessors and
    // restore them as the current hooks (hot paths stay native); untrusted
    // setters get the filtered proxies.
    void* setHookGetImageNamePtr = dlsym(RTLD_DEFAULT, "objc_setHook_getImageName");

    if(setHookGetImageNamePtr) {
        [hooks hookFunction:setHookGetImageNamePtr withReplacement:replaced_objc_setHook_getImageName outOldPtr:(void **) &original_objc_setHook_getImageName];

        objc_hook_getImageName native = NULL;
        objc_hook_getImageName restore = NULL;

        original_objc_setHook_getImageName(shdw_getImageName_proxy, &native);
        shdw_native_getImageName = native;
        original_objc_setHook_getImageName(native, &restore);
    }

    void* setHookGetClassPtr = dlsym(RTLD_DEFAULT, "objc_setHook_getClass");

    if(setHookGetClassPtr) {
        [hooks hookFunction:setHookGetClassPtr withReplacement:replaced_objc_setHook_getClass outOldPtr:(void **) &original_objc_setHook_getClass];

        objc_hook_getClass native = NULL;
        objc_hook_getClass restore = NULL;

        original_objc_setHook_getClass(shdw_getClass_proxy, &native);
        shdw_native_getClass = native;
        original_objc_setHook_getClass(native, &restore);
    }
}
