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
    const char* result = original_class_getImageName(cls);

    if(isCallerExternal() || ![_shadow isCPathRestricted:result]) {
        return result;
    }

    return [[Shadow getExecutablePath] fileSystemRepresentation];
}

static const char * _Nonnull * (*original_objc_copyImageNames)(unsigned int *outCount);
static const char * _Nonnull * replaced_objc_copyImageNames(unsigned int *outCount) {
    const char * _Nonnull * result = original_objc_copyImageNames(outCount);

    if(isCallerExternal() || !result || !outCount) {
        return result;
    }

    const char* exec_name = _dyld_get_image_name(0);
    unsigned int i;

    for(i = 0; i < *outCount; i++) {
        if(strcmp(result[i], exec_name) == 0) {
            // Stop after app executable.
            // todo: improve this to filter instead
            *outCount = (i + 1);
            break;
        }
    }

    return result;
}

static const char * _Nonnull * (*original_objc_copyClassNamesForImage)(const char* image, unsigned int *outCount);
static const char * _Nonnull * replaced_objc_copyClassNamesForImage(const char* image, unsigned int *outCount) {
    if(isCallerExternal() || ![_shadow isCPathRestricted:image]) {
        return original_objc_copyClassNamesForImage(image, outCount);
    }

    return NULL;
}

static Class (*original_NSClassFromString)(NSString* aClassName);
static Class replaced_NSClassFromString(NSString* aClassName) {
    Class result = original_NSClassFromString(aClassName);

    if(isCallerExternal() || ![_shadow isAddrRestricted:(__bridge const void *)result]) {
        return result;
    }

    return nil;
}

typedef struct _NXMapTable NXMapTable;
typedef struct _NXHashTable NXHashTable;

extern void* NXMapGet(NXMapTable *table, const char *name);
extern void* NXHashGet(NXHashTable *table, const void *data);

static void* (*original_NXMapGet)(NXMapTable *table, const char *name);
static void* replaced_NXMapGet(NXMapTable *table, const char *name) {
    void* result = original_NXMapGet(table, name);

    if(isCallerExternal() || ![_shadow isAddrRestricted:result]) {
        return result;
    }

    return nil;
}

static void* (*original_NXHashGet)(NXHashTable *table, const void *data);
static void* replaced_NXHashGet(NXHashTable *table, const void *data) {
    void* result = original_NXHashGet(table, data);

    if(isCallerExternal() || ![_shadow isAddrRestricted:result]) {
        return result;
    }

    return nil;
}

static IMP (*original_method_getImplementation)(Method m);
static IMP replaced_method_getImplementation(Method m) {
    IMP result = original_method_getImplementation(m);

    if(isCallerExternal() || ![_shadow isAddrRestricted:(void *)result]) {
        return result;
    }

    // The fake IMP is never called — detectors (IOSSecuritySuite amISwizzled)
    // only classify the IMP's image via dladdr/dyld_image_path_containing_address.
    // Pointing at the app's own mach_header (image index 0) makes a swizzled
    // method's IMP look native. _dyld_get_image_header is hooked by dyld.x, but
    // our call originates from the tweak, so it returns the true executable header.
    return (IMP)_dyld_get_image_header(0);
}

static IMP (*original_class_getMethodImplementation)(Class cls, SEL name);
static IMP replaced_class_getMethodImplementation(Class cls, SEL name) {
    IMP result = original_class_getMethodImplementation(cls, name);

    if(isCallerExternal() || ![_shadow isAddrRestricted:(void *)result]) {
        return result;
    }

    // Same rationale as replaced_method_getImplementation above.
    return (IMP)_dyld_get_image_header(0);
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
    MSHookFunction(NXMapGet, replaced_NXMapGet, (void **) &original_NXMapGet);
    MSHookFunction(NXHashGet, replaced_NXHashGet, (void **) &original_NXHashGet);
}
