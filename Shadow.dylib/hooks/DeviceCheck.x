#import "hooks.h"

%group shadowhook_DeviceCheck
// Opt-in (Hook_DeviceCheck): attestation fails closed — apps that require
// DeviceCheck attestation see "unsupported" and must fall back to their
// degraded path instead of minting real attestation artifacts.
// TODO: DCDevice generateToken/generateKey and DCAppAttestService
// generateKey/attestKey/generateAssertion are deliberately NOT hooked — the
// artifacts are server-verifiable, so a forged value would fail attestation
// on the server side; returning "unsupported" here is the only honest answer.
%hook DCDevice
- (BOOL)isSupported {
	return NO;
}
%end

%hook DCAppAttestService
- (BOOL)isSupported {
	return NO;
}
%end

%hook UIDevice
+ (BOOL)isJailbroken {
    return NO;
}

- (BOOL)isJailBreak {
    return NO;
}

- (BOOL)isJailBroken {
    return NO;
}
%end

// %hook SFAntiPiracy
// + (int)isJailbroken {
// 	// Probably should not hook with a hard coded value.
// 	// This value may be changed by developers using this library.
// 	// Best to defeat the checks rather than skip them.
// 	return 4783242;
// }
// %end

%hook JailbreakDetectionVC
- (BOOL)isJailbroken {
    return NO;
}
%end

%hook DTTJailbreakDetection
+ (BOOL)isJailbroken {
    return NO;
}
%end

%hook ANSMetadata
- (BOOL)computeIsJailbroken {
    return NO;
}

- (BOOL)isJailbroken {
    return NO;
}
%end

%hook AppsFlyerUtils
+ (BOOL)isJailBreakon {
    return NO;
}

+ (bool)isJailbrokenWithSkipAdvancedJailbreakValidation:(bool)a {
    return false;
}
%end

%hook jailBreak
+ (bool)isJailBreak {
    return false;
}
%end

%hook GBDeviceInfo
- (BOOL)isJailbroken {
    return NO;
}
%end

%hook CMARAppRestrictionsDelegate
- (bool)isDeviceNonCompliant {
    return false;
}
%end

%hook ADYSecurityChecks
+ (bool)isDeviceJailbroken {
    return false;
}
%end

// UBReportMetadataDevice -is_rooted and EnrollParameters -jailbroken are
// installed manually (shdw_install_probe_abi below): their return ABI varies
// between SDK versions (BOOL on some, object on others), and a fixed
// signature against the wrong ABI returns garbage.

%hook UtilitySystem
+ (bool)isJailbreak {
    return false;
}
%end

%hook GemaltoConfiguration
+ (bool)isJailbreak {
    return false;
}
%end

%hook CPWRDeviceInfo
- (bool)isJailbroken {
    return false;
}
%end

%hook CPWRSessionInfo
- (bool)isJailbroken {
    return false;
}
%end

%hook KSSystemInfo
+ (bool)isJailbroken {
    return false;
}
%end

%hook EMDSKPPConfiguration
- (bool)jailBroken {
    return false;
}
%end

// EnrollParameters -jailbroken: see the note at UBReportMetadataDevice.

%hook EMDskppConfigurationBuilder
- (bool)jailbreakStatus {
    return false;
}
%end

%hook FCRSystemMetadata
- (bool)isJailbroken {
    return false;
}
%end

%hook v_VDMap
- (bool)isJailbrokenDetected {
    return false;
}

- (bool)isJailBrokenDetectedByVOS {
    return false;
}

- (bool)isDFPHookedDetecedByVOS {
    return false;
}

- (bool)isCodeInjectionDetectedByVOS {
    return false;
}

- (bool)isDebuggerCheckDetectedByVOS {
    return false;
}

- (bool)isAppSignerCheckDetectedByVOS {
    return false;
}

- (bool)v_checkAModified {
    return false;
}

- (bool)isRuntimeTamperingDetected {
    return false;
}
%end

%hook SDMUtils
- (BOOL)isJailBroken {
    return NO;
}
%end

%hook OneSignalJailbreakDetection
+ (BOOL)isJailbroken {
    return NO;
}
%end

%hook DigiPassHandler
- (BOOL)rootedDeviceTestResult {
    return NO;
}
%end

%hook AWMyDeviceGeneralInfo
- (bool)isCompliant {
    return true;
}
%end

%hook DTXSessionInfo
- (bool)isJailbroken {
    return false;
}
%end

%hook DTXDeviceInfo
- (bool)isJailbroken {
    return false;
}
%end

%hook JailbreakDetection
- (bool)jailbroken {
    return false;
}
%end

%hook jailBrokenJudge
- (bool)isJailBreak {
    return false;
}

- (bool)isCydiaJailBreak {
    return false;
}

- (bool)isApplicationsJailBreak {
    return false;
}

- (bool)ischeckCydiaJailBreak {
    return false;
}

- (bool)isPathJailBreak {
    return false;
}

- (bool)boolIsjailbreak {
    return false;
}
%end

%hook FBAdBotDetector
- (bool)isJailBrokenDevice {
    return false;
}
%end

%hook TNGDeviceTool
+ (bool)isJailBreak {
    return false;
}

+ (bool)isJailBreak_file {
    return false;
}

+ (bool)isJailBreak_cydia {
    return false;
}

+ (bool)isJailBreak_appList {
    return false;
}

+ (bool)isJailBreak_env {
    return false;
}
%end

%hook DTDeviceInfo
+ (bool)isJailbreak {
    return false;
}
%end

%hook SecVIDeviceUtil
+ (bool)isJailbreak {
    return false;
}   
%end

%hook RVPBridgeExtension4Jailbroken
- (bool)isJailbroken {
    return false;
}
%end

%hook ZDetection
+ (bool)isRootedOrJailbroken {
    return false;
}
%end
%end

// Encoding-aware install for third-party rooted/jailbroken properties whose
// return ABI varies between SDK versions. The runtime method encoding is
// inspected at install: B@:/c@: → BOOL-returning hook (NO), @@: →
// object-returning hook (nil), anything else → skip and leave the real
// method untouched.
static BOOL shdw_replaced_probe_BOOL(id self, SEL _cmd) {
    return NO;
}

static id shdw_replaced_probe_obj(id self, SEL _cmd) {
    return nil;
}

static void shdw_install_probe_abi(const char* className, const char* selName, void** origBool, void** origObj) {
    Class cls = objc_getClass(className);

    if(!cls) {
        return;
    }

    SEL sel = sel_registerName(selName);
    Method method = class_getInstanceMethod(cls, sel);

    if(!method) {
        return;
    }

    const char* encoding = method_getTypeEncoding(method);

    if(!encoding) {
        return;
    }

    if(encoding[0] == 'B' || encoding[0] == 'c') {
        MSHookMessageEx(cls, sel, (IMP) &shdw_replaced_probe_BOOL, origBool);
    } else if(encoding[0] == '@') {
        MSHookMessageEx(cls, sel, (IMP) &shdw_replaced_probe_obj, origObj);
    }
    // Unknown encoding: skip.
}

static BOOL (*shdw_orig_ub_is_rooted_BOOL)(id, SEL) = NULL;
static id (*shdw_orig_ub_is_rooted_obj)(id, SEL) = NULL;
static BOOL (*shdw_orig_enroll_jailbroken_BOOL)(id, SEL) = NULL;
static id (*shdw_orig_enroll_jailbroken_obj)(id, SEL) = NULL;

void shadowhook_DeviceCheck(HKSubstitutor* hooks) {
    %init(shadowhook_DeviceCheck);

    shdw_install_probe_abi("UBReportMetadataDevice", "is_rooted",
        (void **) &shdw_orig_ub_is_rooted_BOOL, (void **) &shdw_orig_ub_is_rooted_obj);
    shdw_install_probe_abi("EnrollParameters", "jailbroken",
        (void **) &shdw_orig_enroll_jailbroken_BOOL, (void **) &shdw_orig_enroll_jailbroken_obj);
}
