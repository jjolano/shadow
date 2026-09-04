// App-visible environment spoofing (merged: UIApplication, NSUserDefaults, NSProcessInfo, LSApplicationWorkspace).
// Entry functions keep their per-group names — dylib.x's installer table calls them individually.
#import "UniversalHooks.h"
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>

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

    if([restrictedSuites containsObject:suitename]) {
        return YES;
    }

    // A cfprefsd-hook probe passes a jailbreak daemon/pref plist PATH as the
    // suite name (e.g. /basebin/LaunchDaemons/com.opa334.Dopamine.idownloadd or
    // /var/mobile/Library/Preferences/xyz.willy.Zebra) and treats any readable
    // value as evidence the jailbreak's cfprefsd is answering for it. A stock
    // cfprefsd returns nothing for these. Match the jailbreak plist namespaces
    // by path so the read is answered with nil for external callers. These are
    // never legitimate app suite names.
    if([suitename hasPrefix:@"/basebin/"] ||
       [suitename hasPrefix:@"/Library/LaunchDaemons/"] ||
       [suitename hasPrefix:@"/var/jb/"] ||
       [suitename containsString:@"/LaunchDaemons/com.opa334"] ||
       [suitename containsString:@"/LaunchDaemons/jailbreakd"]) {
        return YES;
    }

    // Known jailbreak-app preference domains a stock device never has.
    static NSArray<NSString*>* jbPrefIDs = nil;
    static dispatch_once_t prefOnce;
    dispatch_once(&prefOnce, ^{
        jbPrefIDs = @[
            @"com.opa334.choicyprefs", @"com.opa334.craneprefs",
            @"com.spark.snowboardprefs", @"com.tigisoftware.Filza",
            @"org.coolstar.SileoStore", @"ru.domo.cocoatop64",
            @"ws.hbang.Terminal", @"xyz.willy.Zebra",
            @"us.diatr.shshd", @"com.opa334.sandyd",
        ];
    });
    NSString* leaf = suitename.lastPathComponent;
    for(NSString* pref in jbPrefIDs) {
        if([leaf isEqualToString:pref]) {
            return YES;
        }
    }

    return NO;
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

// --- passcode-status probe (aggressive-gated) ---
//
// A probe infers "is a device passcode set?" three ways and treats FAILURE of
// each as evidence:
//   1. -[LAContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:]
//   2. SecItemAdd of a kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly item
//   3. SecKeyCreateRandomKey for a Secure-Enclave key gated on the passcode
// This is NOT a jailbreak signal: a stock device with NO passcode set — or an
// app lacking the keychain-access-group entitlement (errSecMissingEntitlement,
// -34018) — fails all three identically. So neutralising it is disable-style,
// gated on aggressive mode, and reports the "passcode is set" outcome for
// external callers only. Internal callers and natural mode are untouched.

extern BOOL shdw_detector_aggressive;

typedef int32_t shdw_os_status_t;
typedef const void* shdw_cf_dictionary_ref_t;
typedef const void* shdw_cf_type_ref_t;
typedef const void* shdw_sec_key_ref_t;
typedef const void** shdw_cf_type_ref_out_t;

#ifndef errSecSuccess
#define errSecSuccess 0
#endif

%group shadowhook_LAContext
%hook LAContext
- (BOOL)canEvaluatePolicy:(NSInteger)policy error:(NSError**)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_detector_aggressive && isCallerExternal()) {
        // LAPolicyDeviceOwnerAuthentication == 2. Report evaluable (passcode
        // set) and clear any error the caller passed in.
        if(policy == 2) {
            if(error) *error = nil;
            return YES;
        }
    }
    return %orig;
}
%end
%end

static shdw_os_status_t (*shdw_orig_SecItemAdd)(shdw_cf_dictionary_ref_t attributes, shdw_cf_type_ref_out_t result);
static shdw_os_status_t shdw_replaced_SecItemAdd(shdw_cf_dictionary_ref_t attributes, shdw_cf_type_ref_out_t result) {
    shdw_os_status_t status = shdw_orig_SecItemAdd(attributes, result);
    // Only rewrite a FAILED add for an external caller under aggressive mode:
    // the probe reads any non-errSecSuccess as "no passcode". A stock device
    // with a passcode returns errSecSuccess, so this matches that shape without
    // fabricating on the success path.
    if(shdw_detector_aggressive && isCallerExternal() && status != errSecSuccess) {
        return errSecSuccess;
    }
    return status;
}

static shdw_sec_key_ref_t (*shdw_orig_SecKeyCreateRandomKey)(shdw_cf_dictionary_ref_t params, shdw_cf_type_ref_out_t error);
static shdw_sec_key_ref_t shdw_replaced_SecKeyCreateRandomKey(shdw_cf_dictionary_ref_t params, shdw_cf_type_ref_out_t error) {
    shdw_sec_key_ref_t key = shdw_orig_SecKeyCreateRandomKey(params, error);
    // The probe only checks the result is non-null. When a Secure-Enclave key
    // creation fails for want of a passcode, fall back to an ordinary in-memory
    // key so the caller sees a valid SecKeyRef — but only external + aggressive.
    if(!key && shdw_detector_aggressive && isCallerExternal()) {
        // Build a minimal 256-bit EC key request with no access control /
        // Secure-Enclave requirement, which does not depend on a passcode.
        NSDictionary* fallback = @{
            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrKeySizeInBits: @256,
            (__bridge id)kSecPrivateKeyAttrs: @{ (__bridge id)kSecAttrIsPermanent: @NO },
        };
        shdw_cf_type_ref_t innerErr = NULL;
        key = shdw_orig_SecKeyCreateRandomKey((__bridge shdw_cf_dictionary_ref_t)fallback,
                                              (shdw_cf_type_ref_out_t)&innerErr);
        if(key && error) *error = NULL;   // hide the original failure
    }
    return key;
}

void shdw_universal_passcode_status(SHDWHookSession* hooks) {
    // ObjC: LAContext. Snapshot+register so a detector reading the current IMP
    // still resolves to the original (consistent with other ObjC hooks).
    Class cls = objc_getClass("LAContext");
    if(cls) {
        SEL sel = sel_registerName("canEvaluatePolicy:error:");
        void* orig = SHDWSnapshotInstanceMethodIMP(cls, sel);
        %init(shadowhook_LAContext);
        SHDWRegisterHookedInstanceMethod(cls, sel, orig);
    }

    // C: Security.framework. Rebind lane (cold detection-facing calls), skipped
    // cleanly when the symbols are absent.
    void* sym = shdw_resolve_libsystem("SecItemAdd");
    if(sym) {
        [hooks hookRebindSymbol:@"SecItemAdd" withReplacement:(void*)shdw_replaced_SecItemAdd outOldPtr:(void**)&shdw_orig_SecItemAdd];
    }
    sym = shdw_resolve_libsystem("SecKeyCreateRandomKey");
    if(sym) {
        [hooks hookRebindSymbol:@"SecKeyCreateRandomKey" withReplacement:(void*)shdw_replaced_SecKeyCreateRandomKey outOldPtr:(void**)&shdw_orig_SecKeyCreateRandomKey];
    }
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
