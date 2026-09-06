#import "AdapterHooks.h"

#import <mach-o/dyld.h>
#import <objc/runtime.h>

#include <dlfcn.h>
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

static BOOL shdw_has_image_substring(const char* substr) {
    if(!substr || !substr[0]) return NO;
    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* name = _dyld_get_image_name(i);
        if(name && strstr(name, substr)) return YES;
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

static BOOL shdw_detect_iossecuritysuite(void) {
    // ponytail: image check only at ctor. objc_getClassList realizes every
    // ObjC class (realizeAllClasses), which faults Swift singleton metadata
    // mid-dyld-init on Swift-heavy apps (Google Maps EXC_BAD_ACCESS at PC=0).
    // Class-name matching adds no detection the image check misses: SPM
    // static embeds have no separate image but also expose no ObjC entry
    // (pure Swift, no ObjC methods to hook), so there is nothing to prearm.
    return shdw_has_image_suffix("/IOSSecuritySuite.framework/IOSSecuritySuite");
}

static BOOL shdw_detect_freerasp(void) {
    return shdw_has_image_suffix("/TalsecRuntime.framework/TalsecRuntime");
}

static BOOL shdw_detect_devicesecuritykit(void) {
    // Real library exposes SwizzlingDetector/DSKBridge; the filtered runner
    // embeds the same probe in DeviceSecurityKitRunner. SPM static embeds
    // have no separate image, so check classes first, image second.
    if(objc_getClass("DeviceSecurityKit.SwizzlingDetector") || objc_getClass("DSKBridge")) return YES;
    return shdw_has_image_suffix("/DeviceSecurityKit.framework/DeviceSecurityKit") ||
        shdw_has_image_substring("DeviceSecurityKit");
}

static BOOL shdw_detect_bat(void) {
    // BAT ships as SPM embed or runner; anchor on the image name plus the
    // exported PreventedAPIs entry (same anchor the adapter hooks — dlsym is
    // a dyld hash lookup, and the ctor calls this before hooks install, so
    // internal-caller short-circuit keeps it a clean lookup afterwards).
    if(shdw_has_image_substring("BATJailbreakGuard")) return YES;
    if(dlsym(RTLD_DEFAULT, "$s17BATJailbreakGuard42JailbreakDetectionPreventedAPICheckServiceC02isD8DetectedSbyF")) return YES;
    if(dlsym(RTLD_DEFAULT, "$s23BATJailbreakGuardRunner42JailbreakDetectionPreventedAPICheckServiceC02isD8DetectedSbyF")) return YES;
    return NO;
}

// Ctor prearm predicate: YES when any known detector is linked at launch.
// Apple's DeviceCheck framework is deliberately NOT a signal (benign
// AppAttest use would de-stealth); the DeviceCheck adapter's detectors are
// the DTT/SafeDevice/JailMonkey trio below.
static BOOL shdw_detect_dtt(void);
static BOOL shdw_detect_safedevice(void);
static BOOL shdw_detect_jailmonkey(void);
BOOL shdw_adapter_has_known_detector(void) {
    return shdw_detect_dtt() || shdw_detect_safedevice() || shdw_detect_jailmonkey() ||
        shdw_detect_freerasp() || shdw_detect_iossecuritysuite() ||
        shdw_detect_devicesecuritykit() || shdw_detect_bat();
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

NSDictionary* shdw_adapter_resolve_preferences(NSDictionary* prefs) {
    NSMutableDictionary* effective = [prefs mutableCopy];
    NSDictionary<NSString*, NSNumber*>* detected = @{
        SHDWAdapterDTTJailbreakDetectionID : @(shdw_detect_dtt()),
        SHDWAdapterSafeDeviceID : @(shdw_detect_safedevice()),
        SHDWAdapterJailMonkeyID : @(shdw_detect_jailmonkey()),
    };

    for(NSString* key in detected) {
        effective[key] = @([prefs[key] boolValue] && [detected[key] boolValue]);
    }

    return [effective copy];
}
