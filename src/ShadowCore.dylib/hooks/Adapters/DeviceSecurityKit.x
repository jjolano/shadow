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

void shdw_adapter_devicesecuritykit(SHDWHookSession* hooks) {
    SHDWSetDladdrRemapper(shdw_adapter_devicesecuritykit_remap_dladdr);
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
