#import "AdapterHooks.h"
#import <HookKit/HookKitRuntime.h>

// DeviceSecurityKit runner up to 0.40 filtered checks UIApplication.canOpenURL
// swizzling via dladdr on method_getImplementation. Shadow's %hook for
// UIApplication uses HookKit's ObjC engine, whose IMP lives in ShadowCore and
// is correctly hidden via dladdr for SHDWHookSession hooks but not for
// hookkit-generated hooks (SHDWOriginalImplementationForMethod has no record).
// The natural lane below answers that probe with the original system IMP
// instead of a forced verdict:
//   * the dladdr remapper, scoped to callers inside a DSK image, reports the
//     pre-hook canOpenURL: IMP;
//   * the late-loaded DSK image gets method_getImplementation /
//     class_getMethodImplementation rebound to Shadow's swizzling-stealth
//     filter (SHDWUniversalFeatureImageRebinding), so
//     SwizzlingDetector.checkSystemMethodOrigins reads system origins for
//     every hooked method.
//
// This file also carried an aggressive-only Swift hook that forced
// isSwizzled() to false (two demangled-substring targets plus a mangled-symbol
// fallback). Removed: the natural lane above already clears the check, so the
// force-false changed no observed result — on-device A/B (identical revision,
// Detector_Aggressive the only difference) reports dsk.swizzling clean either
// way. It was also anchored to names DSK controls, so a DSK rename would have
// made it a silent no-op rather than the backup it looked like.

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
}
