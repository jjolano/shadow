#import "hooks.h"
#import "DeviceCheckHooks.h"

%group shadowhook_DeviceCheck
// TODO: late-loaded detector-class hook retry — detector classes that load
// after this group installs are never hooked; retrying on image-add needs
// the dylib.x watcher wiring (not implemented here).
// Opt-in (Hook_DeviceCheck): attestation fails closed — apps that require
// DeviceCheck attestation see "unsupported" and must fall back to their
// degraded path instead of minting real attestation artifacts.
// TODO: DCDevice generateToken/generateKey and DCAppAttestService
// generateKey/attestKey/generateAssertion are deliberately NOT hooked — the
// artifacts are server-verifiable, so a forged value would fail attestation
// on the server side; returning "unsupported" here is the only honest answer.
// Step 2, batch 1: DCDevice, DCAppAttestService, UIDevice,
// JailbreakDetectionVC, DTTJailbreakDetection, ANSMetadata blocks migrated
// to DeviceCheckHooks.m descriptor rows.
// Step 2, batch 2: AppsFlyerUtils, jailBreak, GBDeviceInfo,
// CMARAppRestrictionsDelegate, ADYSecurityChecks, UtilitySystem,
// GemaltoConfiguration blocks migrated to DeviceCheckHooks.m descriptor rows.

// UBReportMetadataDevice -is_rooted and EnrollParameters -jailbroken are
// installed manually (shdw_install_probe_abi below): their return ABI varies
// between SDK versions (BOOL on some, object on others), and a fixed
// signature against the wrong ABI returns garbage.

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
// return ABI varies between SDK versions: moved to DeviceCheckHooks.{h,m}
// (descriptor-driven). The runtime method encoding is inspected at install:
// B@:/c@: → BOOL-returning hook (NO), @@: → object-returning hook (nil),
// anything else → skip and leave the real method untouched.

void shadowhook_DeviceCheck(HKSubstitutor* hooks) {
    %init(shadowhook_DeviceCheck);

    shdw_devicecheck_install_hooks(hooks);
}
