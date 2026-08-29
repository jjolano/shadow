#import "hooks.h"

#import <mach-o/dyld.h>
#import <objc/runtime.h>

#include <stdlib.h>
#include <string.h>

static BOOL shdw_string_has_suffix(const char* value, const char* suffix) {
    if(!value || !suffix) return NO;
    size_t valueLength = strlen(value), suffixLength = strlen(suffix);
    return valueLength >= suffixLength && strcmp(value + valueLength - suffixLength, suffix) == 0;
}

static BOOL shdw_has_image_suffix(const char* suffix) {
    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        if(shdw_string_has_suffix(_dyld_get_image_name(i), suffix)) return YES;
    }
    return NO;
}

static BOOL shdw_has_bool_method(Class cls, const char* selector, BOOL classMethod) {
    if(!cls) return NO;
    Method method = classMethod
        ? class_getClassMethod(cls, sel_registerName(selector))
        : class_getInstanceMethod(cls, sel_registerName(selector));
    const char* encoding = method ? method_getTypeEncoding(method) : NULL;
    return encoding && (encoding[0] == 'B' || encoding[0] == 'c');
}

static __attribute__((unused)) BOOL shdw_has_iossecuritysuite_classes(void) {
    int count = objc_getClassList(NULL, 0);
    if(count <= 0) return NO;

    Class __unsafe_unretained *classes =
        (Class __unsafe_unretained *)calloc((size_t)count, sizeof(Class));
    if(!classes) return NO;

    int filled = objc_getClassList(classes, count);
    const char *suiteImage = NULL, *jailbreakImage = NULL, *runtimeImage = NULL;

    for(int i = 0; i < filled && i < count; i++) {
        const char* name = class_getName(classes[i]);
        const char* image = class_getImageName(classes[i]);

        if(shdw_string_has_suffix(name, "16IOSSecuritySuite") ||
           shdw_string_has_suffix(name, ".IOSSecuritySuite")) {
            suiteImage = image;
        } else if(shdw_string_has_suffix(name, "16JailbreakChecker") ||
                  shdw_string_has_suffix(name, ".JailbreakChecker")) {
            jailbreakImage = image;
        } else if(shdw_string_has_suffix(name, "18RuntimeHookChecker") ||
                  shdw_string_has_suffix(name, ".RuntimeHookChecker")) {
            runtimeImage = image;
        }
    }

    free(classes);
    return suiteImage && jailbreakImage && runtimeImage &&
        strcmp(suiteImage, jailbreakImage) == 0 && strcmp(suiteImage, runtimeImage) == 0;
}

static __attribute__((unused)) BOOL shdw_detect_iossecuritysuite(void) {
    return shdw_has_image_suffix("/IOSSecuritySuite.framework/IOSSecuritySuite") ||
        shdw_has_iossecuritysuite_classes();
}

static __attribute__((unused)) BOOL shdw_detect_freerasp(void) {
    return shdw_has_image_suffix("/TalsecRuntime.framework/TalsecRuntime");
}

static BOOL shdw_detect_dtt(void) {
    return shdw_has_bool_method(objc_getClass("DTTJailbreakDetection"), "isJailbroken", YES);
}

static BOOL shdw_detect_safedevice(void) {
    Class detector = objc_getClass("SafeDeviceJailbreakDetection");
    if(shdw_has_bool_method(detector, "isJailbroken", YES)) return YES;

    Class plugin = objc_getClass("SafeDevicePlugin");
    NSUInteger matches = 0;
    matches += shdw_has_bool_method(plugin, "isJailBroken", NO);
    matches += shdw_has_bool_method(plugin, "isJailBrokenCustom", NO);
    matches += shdw_has_bool_method(plugin, "hasObviousJailbreakSigns", NO);
    return matches >= 2;
}

static BOOL shdw_detect_jailmonkey(void) {
    return shdw_has_bool_method(objc_getClass("JailMonkey"), "isJailBroken", NO);
}

NSDictionary* shadowhook_DetectorAdapters_resolvePreferences(NSDictionary* prefs) {
    NSMutableDictionary* effective = [prefs mutableCopy];
    NSDictionary<NSString*, NSNumber*>* detected = @{
        SHDWDetectorPatchDTTID : @(shdw_detect_dtt()),
        SHDWDetectorPatchSafeDeviceID : @(shdw_detect_safedevice()),
        SHDWDetectorPatchJailMonkeyID : @(shdw_detect_jailmonkey()),
    };

    for(NSString* key in detected) {
        effective[key] = @([prefs[key] boolValue] && [detected[key] boolValue]);
    }

    return [effective copy];
}
