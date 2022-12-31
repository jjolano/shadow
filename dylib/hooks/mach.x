#import "hooks.h"

static kern_return_t (*original_bootstrap_check_in)(mach_port_t bp, const char* service_name, mach_port_t* sp);
static kern_return_t replaced_bootstrap_check_in(mach_port_t bp, const char* service_name, mach_port_t* sp) {
    if(service_name && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSString* name = @(service_name);
        NSLog(@"%@: %@", @"bootstrap_check_in", name);

        if(![name hasPrefix:@"com.apple"]) {
            if([name hasPrefix:@"cy:"]
            || [name hasPrefix:@"lh:"]
            || [name hasPrefix:@"rbs:"]
            || [name hasPrefix:@"org.coolstar"]
            || [name hasPrefix:@"com.ex"]
            || [name hasPrefix:@"com.saurik"]
            || [name hasPrefix:@"me.jjolano"]){
                return BOOTSTRAP_UNKNOWN_SERVICE;
            }
        }
    }

    return original_bootstrap_check_in(bp, service_name, sp);
}

static kern_return_t (*original_bootstrap_look_up)(mach_port_t bp, const char* service_name, mach_port_t* sp);
static kern_return_t replaced_bootstrap_look_up(mach_port_t bp, const char* service_name, mach_port_t* sp) {
    if(service_name && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSString* name = @(service_name);
        NSLog(@"%@: %@", @"bootstrap_look_up", name);

        if(![name hasPrefix:@"com.apple"]) {
            if([name hasPrefix:@"cy:"]
            || [name hasPrefix:@"lh:"]
            || [name hasPrefix:@"rbs:"]
            || [name hasPrefix:@"org.coolstar"]
            || [name hasPrefix:@"com.ex"]
            || [name hasPrefix:@"com.saurik"]
            || [name hasPrefix:@"me.jjolano"]){
                return BOOTSTRAP_UNKNOWN_SERVICE;
            }
        }
    }

    return original_bootstrap_look_up(bp, service_name, sp);
}

void shadowhook_mach(HKBatchHook* hooks) {
    [hooks addFunctionHook:bootstrap_check_in withReplacement:replaced_bootstrap_check_in outOldPtr:(void **) &original_bootstrap_check_in];
    [hooks addFunctionHook:bootstrap_look_up withReplacement:replaced_bootstrap_look_up outOldPtr:(void **) &original_bootstrap_look_up];
}
