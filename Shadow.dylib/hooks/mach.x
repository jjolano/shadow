#import "hooks.h"

static kern_return_t (*original_bootstrap_check_in)(mach_port_t bp, const char* service_name, mach_port_t* sp);
static kern_return_t replaced_bootstrap_check_in(mach_port_t bp, const char* service_name, mach_port_t* sp) {
    if(!isCallerTweak() && service_name) {
        NSLog(@"%@: %s", @"bootstrap_check_in", service_name);

        if(strstr(service_name, "cy:") == service_name
        || strstr(service_name, "lh:") == service_name
        || strstr(service_name, "rbs:") == service_name
        || strstr(service_name, "org.coolstar") == service_name
        || strstr(service_name, "com.ex") == service_name
        || strstr(service_name, "com.saurik") == service_name
        || strstr(service_name, "com.opa334") == service_name
        || strstr(service_name, "me.jjolano") == service_name
        || strstr(service_name, "jailbreakd") != NULL){
            return BOOTSTRAP_UNKNOWN_SERVICE;
        }
    }

    return original_bootstrap_check_in(bp, service_name, sp);
}

static kern_return_t (*original_bootstrap_look_up)(mach_port_t bp, const char* service_name, mach_port_t* sp);
static kern_return_t replaced_bootstrap_look_up(mach_port_t bp, const char* service_name, mach_port_t* sp) {
    if(!isCallerTweak() && service_name) {
        NSLog(@"%@: %s", @"bootstrap_look_up", service_name);

        if(strstr(service_name, "cy:") == service_name
        || strstr(service_name, "lh:") == service_name
        || strstr(service_name, "rbs:") == service_name
        || strstr(service_name, "org.coolstar") == service_name
        || strstr(service_name, "com.ex") == service_name
        || strstr(service_name, "com.saurik") == service_name
        || strstr(service_name, "com.opa334") == service_name
        || strstr(service_name, "me.jjolano") == service_name
        || strstr(service_name, "jailbreakd") != NULL){
            return BOOTSTRAP_UNKNOWN_SERVICE;
        }
    }

    return original_bootstrap_look_up(bp, service_name, sp);
}

void shadowhook_mach(HKSubstitutor* hooks) {
    MSHookFunction(bootstrap_check_in, replaced_bootstrap_check_in, (void **) &original_bootstrap_check_in);
    MSHookFunction(bootstrap_look_up, replaced_bootstrap_look_up, (void **) &original_bootstrap_look_up);
}
