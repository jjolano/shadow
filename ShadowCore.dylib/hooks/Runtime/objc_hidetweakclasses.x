#import "hooks.h"

static Class (*original_NSClassFromString)(NSString* aClassName);
static Class replaced_NSClassFromString(NSString* aClassName) {
    // C0-2: Shadow's own code sees truth; every other caller is filtered.
    if(!isCallerExternal()) {
        return original_NSClassFromString(aClassName);
    }

    Class result = original_NSClassFromString(aClassName);

    if(shdw_objc_class_is_hidden(result)) {
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

    if(result && shdw_objc_class_is_hidden(result)) {
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

    if(result && shdw_objc_class_is_hidden(result)) {
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

    if(result && shdw_objc_class_is_hidden(result)) {
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
        if(shdw_objc_class_is_hidden(all[i])) {
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
        if(shdw_objc_class_is_hidden(all[i])) {
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
        if(shdw_objc_class_is_hidden(aClass)) {
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


static Method* (*original_class_copyMethodList)(Class cls, unsigned int* outCount);
static Method* replaced_class_copyMethodList(Class cls, unsigned int* outCount) {
    if(!isCallerExternal()) {
        return original_class_copyMethodList(cls, outCount);
    }

    if(shdw_objc_class_is_hidden(cls)) {
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
        // Fail soft if an alternate installer skipped the native capture.
        if(!original_method_getImplementation) {
            result[n++] = result[i];
            continue;
        }

        IMP imp = original_method_getImplementation(result[i]);

        // Classify the IMP, not the raw Method pointer: Method metadata lives
        // in the owning image's data (shared-cache regions for system
        // classes), where span-based address tests misclassify. The owning
        // class was already checked above.
        if(shdw_objc_addr_is_hidden((void *)imp)) {
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

    // Public classes may be swizzled by third-party SDKs. Hiding a method
    // because its current IMP belongs to Shadow makes the selector appear
    // absent and prevents those SDKs from chaining the replacement.
    if(shdw_objc_class_is_hidden(cls)) {
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

    // Match class_getInstanceMethod: hide protected classes, while preserving
    // method metadata needed to chain replacements on public classes.
    if(shdw_objc_class_is_hidden(cls)) {
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

    // Classify the IMP, not the raw Method pointer (shared-cache Method
    // metadata misclassifies under span tests).
    if(shdw_objc_addr_is_hidden((void *)result)) {
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

    if(shdw_objc_class_is_hidden(cls)) {
        return NULL;
    }

    return result;
}

static Class* (*original_objc_copyClassesForImage)(const char* image, unsigned int* outCount);
static Class* replaced_objc_copyClassesForImage(const char* image, unsigned int* outCount) {
    if(!isCallerExternal()) {
        return original_objc_copyClassesForImage(image, outCount);
    }

    if(shdw_objc_image_path_is_hidden(image)) {
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

    if(!mh || shdw_objc_addr_is_hidden(mh)) {
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
    if(shdw_objc_class_is_hidden(cls)) {
        return NO;
    }

    return shdw_native_getImageName ? shdw_native_getImageName(cls, outImageName) : NO;
}

static BOOL shdw_getClass_proxy(const char* name, Class* outClass) {
    Class result = Nil;

    if(!shdw_native_getClass || !shdw_native_getClass(name, &result)) {
        return NO;
    }

    if(result && shdw_objc_class_is_hidden(result)) {
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
    // Keep a raw predecessor for the metadata filters. The low-level
    // method_getImplementation hook is intentionally not installed: it has
    // no declaring-Class argument, so hiding a protected IMP breaks any
    // legitimate third-party swizzler that is chaining a public class.
    if(!original_method_getImplementation) {
        original_method_getImplementation = method_getImplementation;
    }

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
    // setters get the filtered proxies. The capture must use the RAW setter
    // — calling through the hooked setter here would re-enter
    // replaced_objc_setHook_* whose original_* is still NULL until the
    // batch drains (SIGSEGV at PC=0). Hook the setter only after the
    // predecessor is captured and restored.
    void* setHookGetImageNamePtr = dlsym(RTLD_DEFAULT, "objc_setHook_getImageName");

    if(setHookGetImageNamePtr) {
        // Capture the native predecessor via the raw setter — calling the
        // hooked setter here would re-enter replaced_objc_setHook_* whose
        // original_* is still NULL until the batch drains. outOldValue is
        // _Nonnull: pass real storage (the global directly — Apple publishes
        // *outOldValue before the new hook can run).
        ((void (*)(objc_hook_getImageName, objc_hook_getImageName *))setHookGetImageNamePtr)(shdw_getImageName_proxy, &shdw_native_getImageName);

        objc_hook_getImageName restore = NULL;
        ((void (*)(objc_hook_getImageName, objc_hook_getImageName *))setHookGetImageNamePtr)(shdw_native_getImageName, &restore);

        [hooks hookFunction:setHookGetImageNamePtr withReplacement:replaced_objc_setHook_getImageName outOldPtr:(void **) &original_objc_setHook_getImageName];
    }

    void* setHookGetClassPtr = dlsym(RTLD_DEFAULT, "objc_setHook_getClass");

    if(setHookGetClassPtr) {
        objc_hook_getClass native = NULL;
        ((void (*)(objc_hook_getClass, objc_hook_getClass *))setHookGetClassPtr)(shdw_getClass_proxy, &native);
        shdw_native_getClass = native;

        objc_hook_getClass restore = NULL;
        ((void (*)(objc_hook_getClass, objc_hook_getClass *))setHookGetClassPtr)(native, &restore);

        [hooks hookFunction:setHookGetClassPtr withReplacement:replaced_objc_setHook_getClass outOldPtr:(void **) &original_objc_setHook_getClass];
    }
}
