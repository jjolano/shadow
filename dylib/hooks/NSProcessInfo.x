#import "hooks.h"

%group shadowhook_NSProcessInfo
%hook NSProcessInfo
- (BOOL)isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion)version {
    // Override version checks that use this method.
    return YES;
}

- (NSDictionary *)environment {
	NSDictionary* result = %orig;

    if(result) {
        NSMutableDictionary* filtered_result = [result mutableCopy];

        [filtered_result removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
        [filtered_result removeObjectForKey:@"_MSSafeMode"];
        [filtered_result removeObjectForKey:@"_SafeMode"];
        [filtered_result removeObjectForKey:@"_SubstituteSafeMode"];
        [filtered_result removeObjectForKey:@"SHELL"];

        // struct utsname systemInfo;
        // uname(&systemInfo);
        // [filtered_result setObject:@(systemInfo.machine) forKey:@"SIMULATOR_DEVICE_NAME"];

        result = [filtered_result copy];
    }

    return result;
}
%end
%end

%group shadowhook_NSProcessInfo_fakemac
%hook NSProcessInfo
- (BOOL)isiOSAppOnMac {
    // actually would be funny if this bypasses a lot of checks
    return YES;
}
%end
%end

void shadowhook_NSProcessInfo(HKSubstitutor* hooks) {
    %init(shadowhook_NSProcessInfo);
}

void shadowhook_NSProcessInfo_fakemac(HKSubstitutor* hooks) {
    %init(shadowhook_NSProcessInfo_fakemac);
}
