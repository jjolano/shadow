#import "hooks.h"

// %group shadowhook_objc
// %hook NSObject
// + (Class)class {
//     Class result = %orig;

//     if(!isCallerTweak() && [_shadow isAddrRestricted:(__bridge const void *)result]) {
//         return nil;
//     }

//     return result;
// }
// %end
// %end

static const char* (*original_class_getImageName)(Class cls);
static const char* replaced_class_getImageName(Class cls) {
    const char* result = original_class_getImageName(cls);

    if(isCallerTweak() || ![_shadow isCPathRestricted:result]) {
        return result;
    }

    return [[Shadow getExecutablePath] fileSystemRepresentation];
}

static const char * _Nonnull * (*original_objc_copyImageNames)(unsigned int *outCount);
static const char * _Nonnull * replaced_objc_copyImageNames(unsigned int *outCount) {
    const char * _Nonnull * result = original_objc_copyImageNames(outCount);

    if(isCallerTweak() || !result || !outCount) {
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
    if(isCallerTweak() || ![_shadow isCPathRestricted:image]) {
        return original_objc_copyClassNamesForImage(image, outCount);
    }

    return NULL;
}

static Class (*original_NSClassFromString)(NSString* aClassName);
static Class replaced_NSClassFromString(NSString* aClassName) {
    Class result = original_NSClassFromString(aClassName);

    if(isCallerTweak() || ![_shadow isAddrRestricted:(__bridge const void *)result]) {
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

    if(isCallerTweak() || ![_shadow isAddrRestricted:result]) {
        return result;
    }

    return nil;
}

static void* (*original_NXHashGet)(NXHashTable *table, const void *data);
static void* replaced_NXHashGet(NXHashTable *table, const void *data) {
    void* result = original_NXHashGet(table, data);

    if(isCallerTweak() || ![_shadow isAddrRestricted:result]) {
        return result;
    }

    return nil;
}

void shadowhook_objc(HKSubstitutor* hooks) {
    // %init(shadowhook_objc);
    MSHookFunction(class_getImageName, replaced_class_getImageName, (void **) &original_class_getImageName);
    MSHookFunction(objc_copyClassNamesForImage, replaced_objc_copyClassNamesForImage, (void **) &original_objc_copyClassNamesForImage);
    MSHookFunction(objc_copyImageNames, replaced_objc_copyImageNames, (void **) &original_objc_copyImageNames);
}

void shadowhook_objc_hidetweakclasses(HKSubstitutor* hooks) {
    MSHookFunction(NSClassFromString, replaced_NSClassFromString, (void **) &original_NSClassFromString);
    MSHookFunction(NXMapGet, replaced_NXMapGet, (void **) &original_NXMapGet);
    MSHookFunction(NXHashGet, replaced_NXHashGet, (void **) &original_NXHashGet);
}
