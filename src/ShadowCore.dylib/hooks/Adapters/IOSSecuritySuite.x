#import "AdapterHooks.h"

static const void* shdw_iossecuritysuite_image_header(void) {
    Class bridge = objc_getClass("IOSSBridge");
    return bridge ? dyld_image_header_containing_address((__bridge void*)bridge) : NULL;
}

void shdw_adapter_iossecuritysuite(SHDWHookSession* hooks) {
    // Scope repeated symbols to this late-loaded image; an any-image request
    // overlaps ctor-owned slots and HookKit correctly refuses the whole plan.
    const void* imageHeader = shdw_iossecuritysuite_image_header();
    SHDWRequestUniversalFeatures(SHDWUniversalFeatureImageRebinding |
                                 SHDWUniversalFeatureFilesystemMetadata |
                                 SHDWUniversalFeatureSymbolicLinks |
                                 SHDWUniversalFeatureLaunchServicesURLFiltering,
                                 hooks, imageHeader);
}
