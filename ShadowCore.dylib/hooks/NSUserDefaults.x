#import "hooks.h"

// NSUserDefaults suite-name coverage. Detectors read other apps' preference
// domains via [[NSUserDefaults alloc] initWithSuiteName:] / persistentDomain
// to infer installed jailbreak apps (Cydia, Sileo, etc.). Cross-app suite
// reads mostly fail via sandbox anyway, but this is defense-in-depth: a
// JB-indicator suite name trips the behavioral detector and the read is
// answered with nil for external callers. Only VERIFIED jailbreak bundle IDs
// match — the same conservative stance as shdw_bootstrap_service_restricted.
static BOOL shdw_nsuserdefaults_suite_restricted(NSString* suitename) {
    if(!suitename || suitename.length == 0) {
        return NO;
    }

    static NSSet* restrictedSuites = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        restrictedSuites = [NSSet setWithObjects:
            @"com.saurik.Cydia",
            @"com.saurik.Cydia.Startup",
            @"org.coolstar.sileo",
            @"org.coolstar.coolstor",
            @"com.unc0ver",
            @"com.cydia",
            @"com.jailbreak",
            @"com.opa334.trollstore",
            @"com.opa334.sileo",
            nil];
    });

    return [restrictedSuites containsObject:suitename];
}

%group shadowhook_NSUserDefaults
%hook NSUserDefaults
- (instancetype)initWithSuiteName:(NSString *)suitename {
    if(isCallerExternal() && shdw_nsuserdefaults_suite_restricted(suitename)) {
        shdw_detector_detected("nsuserdefaults");

        // Re-route to the global domain via the ORIGINAL implementation
        // (never [self initWithSuiteName:], which would recurse into this
        // hook): the caller gets a valid instance, and the
        // persistentDomainForName: hook below already hides the domain.
        return %orig(NSGlobalDomain);
    }

    return %orig;
}

- (NSDictionary *)persistentDomainForName:(NSString *)domainName {
    if(isCallerExternal() && shdw_nsuserdefaults_suite_restricted(domainName)) {
        shdw_detector_detected("nsuserdefaults");
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSUserDefaults(HKSubstitutor* hooks) {
    %init(shadowhook_NSUserDefaults);
}
