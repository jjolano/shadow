#import "hooks.h"

%group shadowhook_mach
%hookf(kern_return_t, bootstrap_check_in, mach_port_t bp, const char* service_name, mach_port_t* sp) {
    HBLogDebug(@"%@: %s", @"bootstrap_check_in", service_name);
    
    if(![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSString* name = @(service_name);

        if([name hasPrefix:@"cy:"]
        || [name hasPrefix:@"lh:"]
        || [name hasPrefix:@"rbs:"]
        || [name hasPrefix:@"org.coolstar"]
        || [name hasPrefix:@"com.saurik"]){
            return BOOTSTRAP_UNKNOWN_SERVICE;
        }
    }

    return %orig;
}

%hookf(kern_return_t, bootstrap_look_up, mach_port_t bp, const char* service_name, mach_port_t* sp) {
    HBLogDebug(@"%@: %s", @"bootstrap_look_up", service_name);

    if(![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSString* name = @(service_name);
        
        if([name hasPrefix:@"cy:"]
        || [name hasPrefix:@"lh:"]
        || [name hasPrefix:@"rbs:"]
        || [name hasPrefix:@"org.coolstar"]
        || [name hasPrefix:@"com.saurik"]){
            return BOOTSTRAP_UNKNOWN_SERVICE;
        }
    }

    return %orig;
}
%end

void shadowhook_mach(void) {
    %init(shadowhook_mach);
}
