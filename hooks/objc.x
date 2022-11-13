#import "hooks.h"

%group shadowhook_objc
%hookf(Class, objc_lookUpClass, const char* name) {
    Class result = %orig;

    if(result) {
        const char* image_name = class_getImageName(result);

        if([_shadow isCPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return nil;
        }
    }

    return result;
}

%hookf(Class, objc_getClass, const char* name) {
    Class result = %orig;

    if(result) {
        const char* image_name = class_getImageName(result);

        if([_shadow isCPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return nil;
        }
    }

    return result;
}

%hookf(Class, objc_getMetaClass, const char* name) {
    Class result = %orig;

    if(result) {
        const char* image_name = class_getImageName(result);

        if([_shadow isCPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return nil;
        }
    }

    return result;
}

%hookf(Class, NSClassFromString, NSString* aClassName) {
    Class result = %orig;

    if(result) {
        const char* image_name = class_getImageName(result);

        if([_shadow isCPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return nil;
        }
    }

    return result;
}

// %hookf(IMP, method_getImplementation, Method m) {
//     IMP result = %orig;

//     if(result) {
//         const char* image_name = dyld_image_path_containing_address(result);

//         if([_shadow isCPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
//             return nil;
//         }
//     }

//     return result;
// }

%hookf(const char * _Nonnull *, objc_copyImageNames, unsigned int *outCount) {
    const char * _Nonnull * result = %orig;

    if(result && *outCount && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        const char* exec_name = _dyld_get_image_name(0);
        unsigned int i;

        for(i = 0; i < *outCount; i++) {
            if(strcmp(result[i], exec_name) == 0) {
                // Stop after app executable.
                *outCount = (i + 1);
                break;
            }
        }
    }

    return result;
}

%hookf(const char * _Nonnull *, objc_copyClassNamesForImage, const char* image, unsigned int *outCount) {
    const char * _Nonnull * result = %orig;

    if(result) {
        if([_shadow isCPathRestricted:image] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            if(outCount) {
                *outCount = 0;
            }

            return NULL;
        }
    }

    return result;
}
%end

void shadowhook_objc(void) {
    %init(shadowhook_objc);
}
