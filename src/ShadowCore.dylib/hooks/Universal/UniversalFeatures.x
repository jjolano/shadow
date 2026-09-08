#import "UniversalHooks.h"

void SHDWRequestUniversalFeatures(SHDWUniversalFeatures features,
                                  SHDWHookSession* hooks,
                                  const void* imageHeader) {
    if(features & SHDWUniversalFeatureImageRebinding) {
        shdw_universal_rebind_image(hooks, imageHeader);
        shdw_universal_antidebugging_rebind_image(hooks, imageHeader);
        shdw_universal_objc_rebind_image(hooks, imageHeader);
        shdw_universal_objc_methodimpl_rebind_image(hooks, imageHeader);
    }
    if(features & SHDWUniversalFeatureFilesystemMetadata) {
        shdw_universal_feature_filesystem_metadata(hooks);
    }
    if(features & SHDWUniversalFeatureSymbolicLinks) {
        shdw_universal_feature_symbolic_links(hooks);
    }
    if(features & SHDWUniversalFeatureLaunchServicesURLFiltering) {
        shdw_universal_feature_launchservices_url_filtering(hooks);
    }
}
