#import "hooks.h"

%group shadowhook_DeviceCheck
// %hook DCDevice
// - (BOOL)isSupported {
//     // maybe returning unsupported can skip some app attest token generations
// 	return NO;
// }
// %end

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

%hook UBReportMetadataDevice
- (void *)is_rooted {
    return NULL;
}
%end

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

%hook EnrollParameters
- (void *)jailbroken {
    return NULL;
}
%end

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

void shadowhook_DeviceCheck(HKSubstitutor* hooks) {
    %init(shadowhook_DeviceCheck);
}
