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
    Class result = original_NSClassFromString(aClassName);

    if(isCallerExternal() || ![_shadow isAddrRestricted:(__bridge const void *)result]) {
        return result;
    }

    return nil;
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
static void* (*original_imp_getBlock)(IMP anImp);
static void* replaced_imp_getBlock(IMP anImp) {
    if(isCallerExternal() || ![_shadow isAddrRestricted:(void *)anImp]) {
        return original_imp_getBlock(anImp);
    }

    return NULL;
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
}
