#import "DeviceCheckHooks.h"

#import <stdio.h>

// Descriptor-driven install for the DeviceCheck group's ABI-sensitive
// third-party rooted/jailbroken property hooks (see the header).
//
// Install behavior:
//   - class absent at install  -> skip silently
//   - method absent            -> skip silently
//   - encoding 'B' or 'c'      -> BOOL-returning hook (row policy false/true)
//   - encoding '@'             -> object-returning hook (nil)
//   - anything else            -> fail open: leave the real method untouched,
//                                 log once
//
// The two probes each get TWO descriptor rows (scalar-family + object) so a
// single row carries exactly one accepted return encoding; at install only
// the row matching the method's runtime encoding fires — the other row
// skips.
//
// Install route: the passed message-capable hook session (shadowhook_DeviceCheck
// receives it from the coordinator), NOT the global HKHookMessage default.

// One logged-unknown guard shared by every row: once a class+selector with an
// unrecognized return encoding is seen, note it and move on.
static char s_loggedUnknown[256] = { 0 };

// Descriptor table. Step 1: the two ABI-sensitive probes. Each probe gets
// TWO rows — a scalar-family row (accepted 'B'/'c', policy false) and an
// object row (accepted '@', policy nil). Exactly one row matches any given
// runtime encoding. Both probes are zero-argument instance methods.
const DCHDescriptor shdw_devicecheck_descriptors[] = {
    { "UBReportMetadataDevice", "is_rooted",  DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "UBReportMetadataDevice", "is_rooted",  DCHMethodInstance, '@', 0, DCHPolicyFalse },
    { "EnrollParameters",       "jailbroken", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "EnrollParameters",       "jailbroken", DCHMethodInstance, '@', 0, DCHPolicyFalse },

    // Step 2, batch 1: Apple/device classes.
    { "DCDevice",                 "isSupported",          DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "DCAppAttestService",       "isSupported",          DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "UIDevice",                 "isJailbroken",         DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "UIDevice",                 "isJailBreak",          DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "UIDevice",                 "isJailBroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "JailbreakDetectionVC",     "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "DTTJailbreakDetection",    "isJailbroken",         DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "ANSMetadata",              "computeIsJailbroken",  DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "ANSMetadata",              "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },

    // Step 2, batch 2: SDK/detection-helper classes.
    { "AppsFlyerUtils",           "isJailBreakon",        DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "AppsFlyerUtils",           "isJailbrokenWithSkipAdvancedJailbreakValidation:", DCHMethodClass, 'B', 1, DCHPolicyFalse },
    { "jailBreak",                "isJailBreak",          DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "GBDeviceInfo",             "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "CMARAppRestrictionsDelegate", "isDeviceNonCompliant", DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "ADYSecurityChecks",        "isDeviceJailbroken",   DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "UtilitySystem",            "isJailbreak",          DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "GemaltoConfiguration",     "isJailbreak",          DCHMethodClass,    'B', 0, DCHPolicyFalse },

    // Step 2, batch 3: configuration/device-info classes.
    { "CPWRDeviceInfo",           "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "CPWRSessionInfo",          "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "KSSystemInfo",             "isJailbroken",         DCHMethodClass,    'B', 0, DCHPolicyFalse },
    { "EMDSKPPConfiguration",     "jailBroken",           DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "EMDskppConfigurationBuilder", "jailbreakStatus",   DCHMethodInstance, 'B', 0, DCHPolicyFalse },
    { "FCRSystemMetadata",        "isJailbroken",         DCHMethodInstance, 'B', 0, DCHPolicyFalse },

    // Step 2, batch 4: VOS detector + misc classes. AWMyDeviceGeneralInfo
    // is the one TRUE policy row.
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

    // Step 2, batch 5: DTX/JailbreakDetection classes.
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

    // Step 2, batch 6: final classes.
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
    return encoding != 'B' && encoding != 'c' && encoding != '@';
}

static IMP shdw_dch_replacement_imp(const DCHDescriptor* desc) {
    if(desc->encoding == '@') {
        // Step-1 table carries zero-arg object rows only (the two probes);
        // a one-arg '@' row has no IMP and must not reach the resolver
        // (argCount guard in the install loop).
        return (IMP) &shdw_dch_imp0_obj_nil;
    }

    // Scalar family ('B'/'c' rows): policy picks false vs true.
    BOOL truePolicy = (desc->policy == DCHPolicyTrue);

    if(desc->argCount == 0) {
        return truePolicy ? (IMP) &shdw_dch_imp0_bool_true : (IMP) &shdw_dch_imp0_bool_false;
    }

    return truePolicy ? (IMP) &shdw_dch_imp1_bool_true : (IMP) &shdw_dch_imp1_bool_false;
}

NSUInteger shdw_devicecheck_install_hooks(SHDWHookSession* hooks) {
    if(!hooks) {
        return 0;
    }

    NSUInteger installed = 0;

    for(const DCHDescriptor* desc = shdw_devicecheck_descriptors; desc->className; desc++) {
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
            NSLog(@"[Shadow] DeviceCheck: skipping %s%s%s: missing type encoding",
                desc->kind == DCHMethodClass ? "+" : "-",
                desc->className, desc->selector);
            continue;
        }

        char e0 = encoding[0];
        BOOL rowMatches = (e0 == 'B' || e0 == 'c')
            ? (desc->encoding == 'B' || desc->encoding == 'c')
            : (e0 == '@' && desc->encoding == '@');

        if(!rowMatches) {
            if(shdw_dch_encoding_is_unknown(e0)) {
                // Fail open: leave the real method untouched. Log once per
                // class+selector (both rows of a probe share the key, so a
                // dual-row probe logs exactly once).
                char key[256];
                snprintf(key, sizeof(key), "%s%s%s",
                    desc->kind == DCHMethodClass ? "+" : "-",
                    desc->className, desc->selector);

                if(strcmp(s_loggedUnknown, key) != 0) {
                    NSLog(@"[Shadow] DeviceCheck: skipping %s: unsupported return encoding %s",
                        key, encoding);
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
