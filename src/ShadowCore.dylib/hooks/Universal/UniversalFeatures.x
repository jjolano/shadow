#import "UniversalHooks.h"

static void shdw_universal_install_image_rebinding(SHDWHookSession* hooks, const void* imageHeader) {
    shdw_universal_rebind_image(hooks, imageHeader);
    shdw_universal_antidebugging_rebind_image(hooks, imageHeader);
}

static void shdw_universal_install_filesystem_metadata(SHDWHookSession* hooks, const void* imageHeader) {
    (void)imageHeader;
    shdw_universal_feature_filesystem_metadata(hooks);
}

static void shdw_universal_install_symbolic_links(SHDWHookSession* hooks, const void* imageHeader) {
    (void)imageHeader;
    shdw_universal_feature_symbolic_links(hooks);
}

static void shdw_universal_install_launchservices_url_filtering(SHDWHookSession* hooks, const void* imageHeader) {
    (void)imageHeader;
    shdw_universal_feature_launchservices_url_filtering(hooks);
}

void shdw_universal_register_features(void) {
    SHDWRegisterUniversalFeatureInstaller(SHDWUniversalFeatureImageRebinding,
                                          shdw_universal_install_image_rebinding);
    SHDWRegisterUniversalFeatureInstaller(SHDWUniversalFeatureFilesystemMetadata,
                                          shdw_universal_install_filesystem_metadata);
    SHDWRegisterUniversalFeatureInstaller(SHDWUniversalFeatureSymbolicLinks,
                                          shdw_universal_install_symbolic_links);
    SHDWRegisterUniversalFeatureInstaller(SHDWUniversalFeatureLaunchServicesURLFiltering,
                                          shdw_universal_install_launchservices_url_filtering);
}
