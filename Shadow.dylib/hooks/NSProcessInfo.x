#import "hooks.h"

%group shadowhook_NSProcessInfo
%hook NSProcessInfo
- (NSDictionary *)environment {
    NSDictionary* result = %orig;

    if(isCallerExternal() || !result) {
        return result;
    }

    NSMutableDictionary* filtered_result = [result mutableCopy];

    // Stock iOS never has these set; their presence is the jailbreak signal
    // a detector reads back from the cached environment. DYLD_* covers
    // INSERT_LIBRARIES and every search-path knob; the safe-mode and
    // JAILBREAKD_* variables come from jailbreakd/loader launch contexts.
    for(NSString* key in [filtered_result allKeys]) {
        if([key hasPrefix:@"DYLD_"]
        || [key hasPrefix:@"JAILBREAKD_"]
        || [key isEqualToString:@"_MSSafeMode"]
        || [key isEqualToString:@"_SafeMode"]
        || [key isEqualToString:@"_SubstituteSafeMode"]) {
            [filtered_result removeObjectForKey:key];
        }
    }

    // PATH: drop jailbreak components (/var/jb bootstrap and preboot roots —
    // stock iOS PATH has neither), preserving everything else.
    NSString* pathValue = filtered_result[@"PATH"];

    if(pathValue && pathValue.length > 0) {
        NSArray* parts = [pathValue componentsSeparatedByString:@":"];
        NSMutableArray* kept = [NSMutableArray arrayWithCapacity:parts.count];

        for(NSString* part in parts) {
            if([part hasPrefix:@"/var/jb"]
            || [part hasPrefix:@"/private/preboot"]
            || [part hasPrefix:@"/preboot"]) {
                continue;
            }

            [kept addObject:part];
        }

        if(kept.count != parts.count) {
            filtered_result[@"PATH"] = [kept componentsJoinedByString:@":"];
        }
    }

    return filtered_result;
}

- (NSArray<NSString *> *)arguments {
    NSArray<NSString *>* result = %orig;

    if(isCallerExternal() || !result || result.count == 0) {
        return result;
    }

    NSMutableArray<NSString *>* filtered_result = [NSMutableArray arrayWithCapacity:result.count];

    // argv[0] and ordering are preserved; only injection flags (with their
    // path value) and restricted-path arguments are removed.
    [filtered_result addObject:result[0]];

    for(NSUInteger i = 1; i < result.count; i++) {
        NSString* arg = result[i];

        if([_shadow isPathRestricted:arg]) {
            continue;
        }

        if([arg isEqualToString:@"-dylib"]
        || [arg isEqualToString:@"-insert"]
        || [arg isEqualToString:@"-load"]
        || [arg isEqualToString:@"-bundle"]
        || [arg isEqualToString:@"-init"]) {
            // Injection flag: drop the flag and its following path value.
            if(i + 1 < result.count) {
                i++;
            }

            continue;
        }

        [filtered_result addObject:arg];
    }

    return filtered_result;
}
%end
%end

%group shadowhook_NSProcessInfo_fakemac
%hook NSProcessInfo
- (BOOL)isMacCatalystApp {
    if(isCallerExternal()) {
        return %orig;
    }

    // actually would be funny if this bypasses a lot of checks
    return YES;
}

- (BOOL)isiOSAppOnMac {
    if(isCallerExternal()) {
        return %orig;
    }

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
