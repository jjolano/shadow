#import "DeviceCheckHooks.h"

#import <stdio.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>

// Fail-closed forgery: async DeviceCheck/AppAttest entry points answer with
// the stock-shaped error a real unsupported device produces, instead of ever
// minting a fake token (the server validates the Apple signature + nonce, so
// a local forgery reads as fraud — worse than an error). DCErrorDomain is
// resolved from the framework at runtime so no link dependency is added and
// the domain string can never drift; the code cites DCError.h order
// (UnknownSystemFailure=0, FeatureUnsupported=1, ...).
static NSError* shdw_dch_unsupportedError(BOOL isAppAttestKey) {
    static NSString* __strong resolvedDomain = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        void* slot = dlsym(RTLD_DEFAULT, "DCErrorDomain");
        NSString* __unsafe_unretained* ptr = (NSString* __unsafe_unretained*)slot;
        NSString* live = (slot && ptr) ? ptr[0] : nil;
        resolvedDomain = live ?: @"com.apple.DeviceCheck.error";
    });
    NSString* desc = isAppAttestKey
        ? @"The operation is not supported on this device."
        : @"DeviceCheck is not available on this device.";
    return [NSError errorWithDomain:resolvedDomain code:1
                           userInfo:@{ NSLocalizedDescriptionKey : desc }];
}

// Forge IMPs: (NSData*/NSString*, NSError*) blocks, matching both
// single-arg (generateToken/Key) and trailing-arg (attest/assert) shapes.
static void shdw_dch_imp1_forge_unsupported(id self, SEL _cmd, id completion) {
    (void)self;
    if(!completion) return;
    BOOL keyFlow = sel_isEqual(_cmd, sel_registerName("generateKeyWithCompletionHandler:"));
    NSError* err = shdw_dch_unsupportedError(keyFlow);
    void (^block)(id, id) = completion;
    // Async contract: never invoke the completion inline (NSFileManager.x).
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        block(nil, err);
    });
}

static void shdw_dch_imp3_forge_unsupported(id self, SEL _cmd, id a0, id a1, id completion) {
    (void)self; (void)_cmd; (void)a0; (void)a1;
    if(!completion) return;
    NSError* err = shdw_dch_unsupportedError(YES);  // attest/assert are AppAttest key flows.
    void (^block)(id, id) = completion;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        block(nil, err);
    });
}

// Descriptor table install.
static char s_loggedUnknown[256] = { 0 };

// Descriptor table.
const DCHDescriptor shdw_devicecheck_descriptors[] = {
    { "UBReportMetadataDevice", "is_rooted",  DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "UBReportMetadataDevice", "is_rooted",  DCHMethodInstance, '@', 0, DCHPolicyFalse },
    { "UBReportMetadataDevice", "is_rooted",  DCHMethodInstance, '^', 0, DCHPolicyFalse },
    { "EnrollParameters",       "jailbroken", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "EnrollParameters",       "jailbroken", DCHMethodInstance, '@', 0, DCHPolicyFalse },
    { "EnrollParameters",       "jailbroken", DCHMethodInstance, '^', 0, DCHPolicyFalse },

    // Step 2, batch 1.
    { "DCDevice",                 "isSupported",          DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "DCAppAttestService",       "isSupported",          DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    // Step 2b, fail-closed forgery: crypto forgery is impossible client-side
    // (Apple-signed statements), so async entry points answer with the same
    // stock-shaped DCErrorFeatureUnsupported a real unsupported device
    // produces. Untargeted rows (DCHTargetNone) like the isSupported pair —
    // no detector prearm needed.
    { "DCDevice",                 "generateTokenWithCompletionHandler:", DCHMethodInstance, 'v', 1, DCHPolicyForgeUnsupported },
    { "DCAppAttestService",       "generateKeyWithCompletionHandler:",   DCHMethodInstance, 'v', 1, DCHPolicyForgeUnsupported },
    { "DCAppAttestService",       "attestKey:clientDataHash:completionHandler:",      DCHMethodInstance, 'v', 3, DCHPolicyForgeUnsupported },
    { "DCAppAttestService",       "generateAssertion:clientDataHash:completionHandler:", DCHMethodInstance, 'v', 3, DCHPolicyForgeUnsupported },
    { "UIDevice",                 "isJailbroken",         DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "UIDevice",                 "isJailBreak",          DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "UIDevice",                 "isJailBroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "JailbreakDetectionVC",     "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "DTTJailbreakDetection",    "isJailbroken",         DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "SafeDeviceJailbreakDetection", "isJailbroken",     DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "SafeDevicePlugin",         "isJailBroken",          DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "SafeDevicePlugin",         "isJailBrokenCustom",    DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "SafeDevicePlugin",         "hasObviousJailbreakSigns", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "JailMonkey",               "isJailBroken",          DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "ANSMetadata",              "computeIsJailbroken",  DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "ANSMetadata",              "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },

    // Batch 2.
    { "AppsFlyerUtils",           "isJailBreakon",        DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "AppsFlyerUtils",           "isJailbrokenWithSkipAdvancedJailbreakValidation:", DCHMethodClass, 'B', 1, DCHPolicyFalse },
    { "jailBreak",                "isJailBreak",          DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "GBDeviceInfo",             "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "CMARAppRestrictionsDelegate", "isDeviceNonCompliant", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "ADYSecurityChecks",        "isDeviceJailbroken",   DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "UtilitySystem",            "isJailbreak",          DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "GemaltoConfiguration",     "isJailbreak",          DCHMethodClass,    'B', 0, DCHPolicyFalse },

    // Batch 3.
    { "CPWRDeviceInfo",           "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "CPWRSessionInfo",          "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "KSSystemInfo",             "isJailbroken",         DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "EMDSKPPConfiguration",     "jailBroken",           DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "EMDskppConfigurationBuilder", "jailbreakStatus",   DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "FCRSystemMetadata",        "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },

    // Batch 4.
    { "v_VDMap",                  "isJailbrokenDetected",        DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "v_VDMap",                  "isJailBrokenDetectedByVOS",   DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "v_VDMap",                  "isDFPHookedDetecedByVOS",     DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "v_VDMap",                  "isCodeInjectionDetectedByVOS", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "v_VDMap",                  "isDebuggerCheckDetectedByVOS", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "v_VDMap",                  "isAppSignerCheckDetectedByVOS", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "v_VDMap",                  "v_checkAModified",            DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "v_VDMap",                  "isRuntimeTamperingDetected",  DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "SDMUtils",                 "isJailBroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "OneSignalJailbreakDetection", "isJailbroken",      DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "DigiPassHandler",          "rootedDeviceTestResult", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "AWMyDeviceGeneralInfo",    "isCompliant",          DCHMethodInstance, 'B', 0, DCHPolicyTrue },

    // Batch 5.
    { "DTXSessionInfo",           "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "DTXDeviceInfo",            "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "JailbreakDetection",       "jailbroken",           DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "jailBrokenJudge",          "isJailBreak",          DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "jailBrokenJudge",          "isCydiaJailBreak",     DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "jailBrokenJudge",          "isApplicationsJailBreak", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "jailBrokenJudge",          "ischeckCydiaJailBreak", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "jailBrokenJudge",          "isPathJailBreak",      DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "jailBrokenJudge",          "boolIsjailbreak",      DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "FBAdBotDetector",          "isJailBrokenDevice",   DCHMethodInstance, 'B', 0, DCHPolicyFalse },

    // Batch 6.
    { "TNGDeviceTool",            "isJailBreak",          DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "TNGDeviceTool",            "isJailBreak_file",     DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "TNGDeviceTool",            "isJailBreak_cydia",    DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "TNGDeviceTool",            "isJailBreak_appList",  DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "TNGDeviceTool",            "isJailBreak_env",      DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "DTDeviceInfo",             "isJailbreak",          DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "SecVIDeviceUtil",          "isJailbreak",          DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "RVPBridgeExtension4Jailbroken", "isJailbroken",    DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "ZDetection",               "isRootedOrJailbroken", DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { NULL, NULL, 0, 0, 0, 0 }
};

static BOOL shdw_dch_encoding_is_unknown(char encoding) {
    return encoding != 'B' && encoding != 'c' && encoding != '@' && encoding != '^' && encoding != 'v';
}

static DCHTarget shdw_dch_target(const DCHDescriptor* desc) {
    if(strcmp(desc->className, "DTTJailbreakDetection") == 0) {
        return DCHTargetDTT;
    }

    if(strcmp(desc->className, "SafeDeviceJailbreakDetection") == 0 ||
       strcmp(desc->className, "SafeDevicePlugin") == 0) {
        return DCHTargetSafeDevice;
    }

    if(strcmp(desc->className, "JailMonkey") == 0) {
        return DCHTargetJailMonkey;
    }

    return DCHTargetNone;
}

static IMP shdw_dch_replacement_imp(const DCHDescriptor* desc) {
    if(desc->encoding == '@') {
        // Zero-arg object rows only; a one-arg '@' row has no IMP.
        return (IMP) &shdw_dch_imp0_obj_nil;
    }

    if(desc->encoding == '^') {
        return (IMP) &shdw_dch_imp0_ptr_null;
    }

    // Forge rows ('v' + completion block): policy selects the stock error.
    if(desc->encoding == 'v' && desc->policy == DCHPolicyForgeUnsupported) {
        if(desc->argCount == 1) {
            return (IMP) &shdw_dch_imp1_forge_unsupported;
        }
        return (IMP) &shdw_dch_imp3_forge_unsupported;
    }

    // Scalar family ('B'/'c' rows): policy picks false vs true.
    BOOL truePolicy = (desc->policy == DCHPolicyTrue);

    if(desc->argCount == 0) {
        return truePolicy ? (IMP) &shdw_dch_imp0_bool_true : (IMP) &shdw_dch_imp0_bool_false;
    }

    return truePolicy ? (IMP) &shdw_dch_imp1_bool_true : (IMP) &shdw_dch_imp1_bool_false;
}

NSUInteger shdw_devicecheck_install_hooks(SHDWHookSession* hooks, DCHTarget enabledTargets) {
    if(!hooks) {
        return 0;
    }

    NSUInteger installed = 0;

    for(const DCHDescriptor* desc = shdw_devicecheck_descriptors; desc->className; desc++) {
        DCHTarget target = shdw_dch_target(desc);

        if(target != DCHTargetNone && !(enabledTargets & target)) {
            continue;
        }

        Class cls = objc_getClass(desc->className);

        if(!cls) {
            continue;   // Late-loaded classes are skipped until a later install.
        }

        SEL sel = sel_registerName(desc->selector);
        Method method = desc->kind == DCHMethodClass
            ? class_getClassMethod(cls, sel)
            : class_getInstanceMethod(cls, sel);

        if(!method) {
            continue;
        }

        const char* encoding = method_getTypeEncoding(method);

        if(!encoding) {
            NSLog(@"[Shadow] DeviceCheck: skipping %s%s%s",
                desc->kind == DCHMethodClass ? "+" : "-",
                desc->className, desc->selector);
            continue;
        }

        char e0 = encoding[0];
        BOOL rowMatches = (e0 == 'B' || e0 == 'c')
            ? (desc->encoding == 'B' || desc->encoding == 'c')
            : (e0 == '@' && desc->encoding == '@') ||
              (e0 == '^' && desc->encoding == '^') ||
              // Forge rows: void-returning methods whose LAST arg is the
              // (result, NSError*) completion block (1 or 3 args). Stock
              // signatures verified against the SDK headers:
              // generateToken/Key take (block); attest/assert take
              // (keyId, clientDataHash, block).
              (e0 == 'v' && desc->encoding == 'v' &&
               desc->policy == DCHPolicyForgeUnsupported &&
               (desc->argCount == 1 || desc->argCount == 3));

        if(!rowMatches) {
            if(shdw_dch_encoding_is_unknown(e0)) {
                char key[256];
                snprintf(key, sizeof(key), "%s%s%s",
                    desc->kind == DCHMethodClass ? "+" : "-",
                    desc->className, desc->selector);

                if(strcmp(s_loggedUnknown, key) != 0) {
                    NSLog(@"[Shadow] DeviceCheck: skipping %s",
                        key);
                    snprintf(s_loggedUnknown, sizeof(s_loggedUnknown), "%s", key);
                }
            }

            continue;
        }

        [hooks hookMessageInClass:cls withSelector:sel withReplacement:shdw_dch_replacement_imp(desc) outOldPtr:NULL];
        installed++;
    }

    return installed;
}
