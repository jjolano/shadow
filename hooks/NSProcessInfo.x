#import "hooks.h"

%group shadowhook_NSProcessInfo
%hook NSProcessInfo
- (NSDictionary *)environment {
	NSDictionary* result = %orig;

    if(result) {
        NSMutableDictionary* filtered_result = [result mutableCopy];

        [filtered_result removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
        [filtered_result removeObjectForKey:@"_MSSafeMode"];
        [filtered_result removeObjectForKey:@"_SafeMode"];
        [filtered_result removeObjectForKey:@"SHELL"];

        /*
        struct utsname systemInfo;
        uname(&systemInfo);

        [filtered_result setObject:@(systemInfo.machine) forKey:@"SIMULATOR_MODEL_IDENTIFIER"];
        */

        result = [filtered_result copy];
    }

    return result;
}
%end
%end

void shadowhook_NSProcessInfo(void) {
    %init(shadowhook_NSProcessInfo);
}
