#import "AdapterHooks.h"
#import <HookKit/HookKitSwift.h>
#import <HookKit/HookKitRuntime.h>
#import <HookKit/HookKitResolver.h>

// DeviceSecurityKit runner up to 0.40 filtered checks UIApplication.canOpenURL
// swizzling via dladdr on method_getImplementation. Shadow's %hook for
// UIApplication uses HookKit's ObjC engine, whose IMP lives in
// ShadowCore and is correctly hidden via dladdr for SHDWHookSession hooks
// but not for hookkit-generated hooks (SHDWOriginalImplementationForMethod
// has no record). Rather than widen the generic method_getImplementation
// hook to chase HookKit's slot, directly neutralise the detector's Swift
// predicate: isSwizzled(AnyClass, Selector) -> Bool always false for
// external callers. Two targets: the filtered runner's
// DeviceSecurityKitRunner.AppDelegate.isSwizzled and the real library's
// DeviceSecurityKit.SwizzlingDetector.isSwizzled (both demangled
// substring "isSwizzled").

// Swift calling convention note: HookKit Swift hook expects a Swift
// method pointer (self in x20). Clang's __attribute__((swiftcall))
// matches; a plain C Bool return in w0 is sufficient for a Bool.

__attribute__((swiftcall)) static bool hook_isSwizzled(void *self, void *cls, void *sel) {
    (void)self; (void)cls; (void)sel;
    return false;
}

static const void* shdw_adapter_devicesecuritykit_remap_dladdr(const void* address,
                                                                const void* caller) {
    const char* callerPath = caller ? dyld_image_path_containing_address(caller) : NULL;
    if(!callerPath || (!strstr(callerPath, "DeviceSecurityKitRunner") &&
                       !strstr(callerPath, "DeviceSecurityKit"))) {
        return NULL;
    }

    void* original = SHDWCanOpenURLOriginal();
    return original && address == SHDWCanOpenURLReplacement() ? original : NULL;
}

static const void* shdw_devicesecuritykit_image_header(void) {
    // DSK's swizzling probe lives in DeviceSecurityKit (SwizzlingDetector) or,
    // for the filtered runner, DeviceSecurityKitRunner. Prefer the library.
    Class probe = objc_getClass("DeviceSecurityKit.SwizzlingDetector")
        ?: objc_getClass("DSKBridge");
    return probe ? dyld_image_header_containing_address((__bridge void*)probe) : NULL;
}

void shdw_adapter_devicesecuritykit(SHDWHookSession* hooks) {
    SHDWSetDladdrRemapper(shdw_adapter_devicesecuritykit_remap_dladdr);

    // Route the late-loaded DSK framework's class_getMethodImplementation /
    // method_getImplementation imports through Shadow's swizzling-stealth
    // filter, so SwizzlingDetector.checkSystemMethodOrigins reads the original
    // (system) IMP for hooked methods (canOpenURL:, fileExistsAtPath:, ...).
    const void* imageHeader = shdw_devicesecuritykit_image_header();
    if(imageHeader) {
        SHDWRequestUniversalFeatures(SHDWUniversalFeatureImageRebinding, hooks, imageHeader);
    }

    // Everything below forces SwizzlingDetector.isSwizzled() to return false —
    // a disable-style neutralizer that overrides the check result rather than
    // presenting a stock-looking environment. Gate it on the user's aggressive
    // opt-in; without it the natural dladdr/IMP-origin stealth above stands
    // alone (which already clears the current DSK build's swizzling probe).
    if(!shdw_detector_aggressive) {
        return;
    }
    // Filtered runner: DeviceSecurityKitRunner.AppDelegate.isSwizzled
    hk_swift_target_t t1 = hk_swift_target_init();
    t1.class_name = "DeviceSecurityKitRunner.AppDelegate";
    t1.name_kind = HK_SWIFT_NAME_DEMANGLED_SUBSTRING;
    t1.method_name = "isSwizzled";
    t1.require_unique = false;
    t1.availability = HK_AVAILABILITY_REQUIRED_NOW;
    hk_status_t s1 = hk_swift_hook(&t1, (void*)hook_isSwizzled, NULL);

    // Real library: DeviceSecurityKit.SwizzlingDetector.isSwizzled
    hk_swift_target_t t2 = hk_swift_target_init();
    t2.class_name = "DeviceSecurityKit.SwizzlingDetector";
    t2.name_kind = HK_SWIFT_NAME_DEMANGLED_SUBSTRING;
    t2.method_name = "isSwizzled";
    t2.require_unique = false;
    hk_swift_hook(&t2, (void*)hook_isSwizzled, NULL);

    if (s1 != HK_STATUS_OK) {
        hk_swift_target_t t1b = hk_swift_target_init();
        t1b.class_name = "AppDelegate";
        t1b.name_kind = HK_SWIFT_NAME_DEMANGLED_SUBSTRING;
        t1b.method_name = "isSwizzled";
        t1b.require_unique = false;
        hk_swift_hook(&t1b, (void*)hook_isSwizzled, NULL);
    }

    void *sym = dlsym(RTLD_DEFAULT, "_$s23DeviceSecurityKitRunner11AppDelegateC10isSwizzledySbyXlXp_10ObjectiveC8SelectorVtF");
    if (sym) {
        [hooks hookFunction:sym withReplacement:(void*)hook_isSwizzled outOldPtr:NULL];
    }

}
