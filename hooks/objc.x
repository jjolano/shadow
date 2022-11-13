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

%end

void shadowhook_objc(void) {
    %init(shadowhook_objc);
}
