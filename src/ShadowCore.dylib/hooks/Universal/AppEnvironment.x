// App-visible environment spoofing (merged: UIApplication, NSUserDefaults, NSProcessInfo, LSApplicationWorkspace).
// Entry functions keep their per-group names — dylib.x's installer table calls them individually.
#import "UniversalHooks.h"

%group shadowhook_UIApplication
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        NSLog(@"canOpenURL restricted: %@", url);
        return NO;
    }

    return %orig;
}

- (BOOL)openURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        NSLog(@"openURL restricted: %@", url);
        return NO;
    }

    return %orig;
}

// NOTE: declared void on iOS 10+ (UIApplication.h) — never contact
// LaunchServices for a restricted URL; the completion is delivered
// asynchronously with NO, matching the async contract of the real API.
- (void)openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenExternalURLOptionsKey, id> *)options completionHandler:(void (^)(BOOL success))completion __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        NSLog(@"openURL:options: restricted: %@", url);

        if(completion) {
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                completion(NO);
            });
        }

        return;
    }

    %orig;
}
%end
%end

static void *gShadowCanOpenURLOrig = NULL;
static void *gShadowCanOpenURLHook = NULL;

void shdw_universal_url_scheme(SHDWHookSession* hooks) {
    Class cls = objc_getClass("UIApplication");
    SEL sel = sel_registerName("canOpenURL:");
    Method m = class_getInstanceMethod(cls, sel);
    if (m) gShadowCanOpenURLOrig = (void*)method_getImplementation(m);
    %init(shadowhook_UIApplication);
    if (m) gShadowCanOpenURLHook = (void*)method_getImplementation(m);
    if (!gShadowCanOpenURLOrig) {
        IMP orig = SHDWOriginalImplementationForMethod(m);
        if (orig) gShadowCanOpenURLOrig = (void*)orig;
    }
    SHDWPublishCanOpenURLArtifacts(gShadowCanOpenURLOrig, gShadowCanOpenURLHook);
}

// NSUserDefaults suite-name coverage. Detectors read other apps' preference
// domains via [[NSUserDefaults alloc] initWithSuiteName:] / persistentDomain
// to infer installed jailbreak apps (Cydia, Sileo, etc.). Cross-app suite
// reads mostly fail via sandbox anyway, but this is defense-in-depth: a
// JB-indicator suite name trips the behavioral detector and the read is
// answered with nil for external callers. Only VERIFIED jailbreak bundle IDs
// match — the same conservative stance as shdw_bootstrap_service_restricted.
static BOOL shdw_nsuserdefaults_suite_restricted(NSString* suitename) {
    if(!suitename || suitename.length == 0) {
        return NO;
    }

    static NSSet* restrictedSuites = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        restrictedSuites = [NSSet setWithObjects:
            @"com.saurik.Cydia",
            @"com.saurik.Cydia.Startup",
            @"org.coolstar.sileo",
            @"org.coolstar.coolstor",
            @"com.unc0ver",
            @"com.cydia",
            @"com.jailbreak",
            @"com.opa334.trollstore",
            @"com.opa334.sileo",
            nil];
    });

    return [restrictedSuites containsObject:suitename];
}

%group shadowhook_NSUserDefaults
%hook NSUserDefaults
- (instancetype)initWithSuiteName:(NSString *)suitename __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_nsuserdefaults_suite_restricted(suitename)) {
        shdw_detector_detected("nsuserdefaults");

        // Re-route to the global domain via the ORIGINAL implementation
        // (never [self initWithSuiteName:], which would recurse into this
        // hook): the caller gets a valid instance, and the
        // persistentDomainForName: hook below already hides the domain.
        return %orig(NSGlobalDomain);
    }

    return %orig;
}

- (NSDictionary *)persistentDomainForName:(NSString *)domainName __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_nsuserdefaults_suite_restricted(domainName)) {
        shdw_detector_detected("nsuserdefaults");
        return nil;
    }

    return %orig;
}
%end
%end

void shdw_universal_user_defaults(SHDWHookSession* hooks) {
    %init(shadowhook_NSUserDefaults);
}
#import "../../policy/EnvironmentPolicy.h"

%group shadowhook_NSProcessInfo
%hook NSProcessInfo
- (NSDictionary *)environment __attribute__((annotate("hookkit:allow_inherited"))) {
    NSDictionary* result = %orig;

    if(!isCallerExternal() || !result) {
        return result;
    }

    // Shared env sanitization policy (policy/EnvironmentPolicy.m): hidden
    // keys (DYLD_*/JAILBREAKD_*/safe-mode) removed, PATH jailbreak
    // components dropped — the same rules the getenv/_NSGetEnviron/PROCARGS2
    // surfaces apply, so every channel agrees.
    return shdw_env_sanitized_dictionary(result);
}

- (NSArray<NSString *> *)arguments __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray<NSString *>* result = %orig;

    if(!isCallerExternal() || !result || result.count == 0) {
        return result;
    }

    // Shared argv sanitization policy (policy/EnvironmentPolicy.m): argv[0]
    // and ordering preserved; injection flags (with their path value) and
    // restricted-path arguments removed.
    return shdw_env_sanitized_argv(result);
}
%end
%end

void shdw_universal_nsprocessinfo(SHDWHookSession* hooks) {
    Class cls = objc_getClass("NSProcessInfo");
    SEL sel = sel_registerName("environment");
    void* orig = SHDWSnapshotInstanceMethodIMP(cls, sel);
    %init(shadowhook_NSProcessInfo);
    SHDWRegisterHookedInstanceMethod(cls, sel, orig);
}

#import <MobileCoreServices/LSApplicationWorkspace.h>
#import <MobileCoreServices/LSApplicationProxy.h>
#import <MobileCoreServices/LSBundleProxy.h>

// use of LSApplicationWorkspace seems to be known for getting App Store rejected, but you never know...

// TODO: LaunchServices/MobileInstallation payload content filtering —
// restricted app IDs inside allowed install plists (LSApplicationProxy
// reads of /var/mobile/Library/MobileInstallation or LS install records)
// are not yet filtered; needs the NSFileManager/NSString read paths to
// post-filter plist payloads by bundle ID.

// C0-3: hidden-app predicate — restricted bundle URL OR case-insensitive
// restricted bundle ID. Applied to every proxy-returning surface so a proxy
// can't leak through a variant that only checks one of the two signals.
static NSArray* shdw_filter_application_proxies(NSArray* proxies) {
    NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:proxies.count];

    for(LSApplicationProxy* ap in proxies) {
        if(![_shadow isURLRestricted:[ap bundleURL]] && ![_shadow isBundleIDRestricted:[ap bundleIdentifier]]) {
            [result_filtered addObject:ap];
        }
    }

    return [result_filtered copy];
}

%group shadowhook_LSApplicationWorkspace
%hook LSApplicationWorkspace
- (NSArray<LSApplicationProxy *> *)allApplications __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray<LSApplicationProxy *>* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)allInstalledApplications __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray<LSApplicationProxy *>* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)directionsApplications __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray<LSApplicationProxy *>* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)unrestrictedApplications __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray<LSApplicationProxy *>* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)applicationsAvailableForHandlingURLScheme:(NSString *)urlScheme __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isSchemeRestricted:urlScheme]) {
        return @[];
    }

    NSArray<LSApplicationProxy *>* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)applicationsAvailableForOpeningURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        return @[];
    }

    NSArray<LSApplicationProxy *>* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)applicationsAvailableForOpeningURL:(NSURL *)url legacySPI:(BOOL)legacySPI __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        return @[];
    }

    NSArray<LSApplicationProxy *>* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<NSString *> *)publicURLSchemes __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray<NSString *>* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray<NSString *>* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* scheme in result) {
            if(![_shadow isSchemeRestricted:scheme]) {
                [result_filtered addObject:scheme];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSArray<NSString *> *)privateURLSchemes __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray<NSString *>* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray<NSString *>* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* scheme in result) {
            if(![_shadow isSchemeRestricted:scheme]) {
                [result_filtered addObject:scheme];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}
%end

// C0-3: direct proxy construction — closes the TODO above for the
// materialization path: a caller that read an allowed install plist can
// resolve individual proxies by identifier/URL, so nil-out the constructors
// for restricted apps instead of only filtering the workspace arrays.
// initWithCoder: is intentionally NOT hooked — the workspace arrays are
// already filtered, the identifier is stored under private coder keys (no
// reliable decode without breaking stock unarchiving), and returning nil
// mid-unarchive can abort LaunchServices internals.
%hook LSApplicationProxy
+ (instancetype)applicationProxyForIdentifier:(NSString *)identifier __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && identifier && [_shadow isBundleIDRestricted:identifier]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)applicationProxyForBundleURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}
%end
%end

%group shadowhook_LSApplicationWorkspaceCanOpenURL
%hook LSApplicationWorkspace
- (BOOL)isApplicationAvailableToOpenURL:(NSURL *)url error:(NSError **)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) *error = nil;
        return NO;
    }

    return %orig;
}

- (BOOL)isApplicationAvailableToOpenURL:(NSURL *)url includePrivateURLSchemes:(BOOL)includePrivateURLSchemes error:(NSError **)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) *error = nil;
        return NO;
    }

    return %orig;
}
%end
%end

static BOOL shdw_ls_can_open_url_installed = NO;

void shdw_universal_feature_launchservices_url_filtering(SHDWHookSession* hooks) {
    (void)hooks;

    if(shdw_ls_can_open_url_installed) {
        return;
    }

    Class workspace = objc_getClass("LSApplicationWorkspace");
    if(workspace && class_getInstanceMethod(workspace, sel_registerName("isApplicationAvailableToOpenURL:error:"))) {
        %init(shadowhook_LSApplicationWorkspaceCanOpenURL);
        shdw_ls_can_open_url_installed = YES;
    }
}

%group shadowhook_LSApplicationWorkspaceInstalledApplications
%hook LSApplicationWorkspace
- (NSArray<NSString *> *)installedApplications __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray<NSString *>* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray<NSString *>* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* app_bundleId in result) {
            if([_shadow isBundleIDRestricted:app_bundleId]) {
                continue;
            }

            LSBundleProxy* app_bundle = [LSBundleProxy bundleProxyForIdentifier:app_bundleId];
            BOOL restricted = app_bundle && [_shadow isURLRestricted:[app_bundle bundleURL]];

            if(!restricted) {
                [result_filtered addObject:app_bundleId];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}
%end
%end

void shdw_universal_hide_apps(SHDWHookSession* hooks) {
    %init(shadowhook_LSApplicationWorkspace);
    shdw_universal_feature_launchservices_url_filtering(hooks);

    Class workspace = objc_getClass("LSApplicationWorkspace");
    if(workspace && class_getInstanceMethod(workspace, @selector(installedApplications))) {
        %init(shadowhook_LSApplicationWorkspaceInstalledApplications);
    }
}
