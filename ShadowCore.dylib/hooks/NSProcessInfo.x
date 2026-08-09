#import "hooks.h"
#import "../policy/EnvironmentPolicy.h"

%group shadowhook_NSProcessInfo
%hook NSProcessInfo
- (NSDictionary *)environment {
    NSDictionary* result = %orig;

    if(!isCallerExternal() || !result) {
        return result;
    }

    // Shared env sanitization policy (policy/EnvironmentPolicy.m): hidden
    // keys (DYLD_*/JAILBREAKD_*/safe-mode) removed, PATH jailbreak
    // components dropped — the same rules the getenv/_NSGetEnviron/PROCARGS2
    // surfaces apply, so every channel agrees.
    return shdw_env_sanitized_dictionary(result);
}

- (NSArray<NSString *> *)arguments {
    NSArray<NSString *>* result = %orig;

    if(!isCallerExternal() || !result || result.count == 0) {
        return result;
    }

    // Shared argv sanitization policy (policy/EnvironmentPolicy.m): argv[0]
    // and ordering preserved; injection flags (with their path value) and
    // restricted-path arguments removed.
    return shdw_env_sanitized_argv(result);
}
%end
%end

// --- FakeMac group REMOVED (hook-output audit) ---
//
// The old group answered isMacCatalystApp/isiOSAppOnMac = YES to every
// external caller. That was a universal fingerprint: stock iOS never answers
// either with YES, so a detector could prove the hook from the value alone
// without any jailbreak probe, and any app legitimately branching on
// Mac-ness would misbehave. There is no truthful way to fake these reliably,
// so the group installs nothing. The installer stays as a linkable no-op so
// dylib.x's pref-gated call (Hook_FakeMac) keeps building; the toggle is
// inert.

void shadowhook_NSProcessInfo(HKSubstitutor* hooks) {
    %init(shadowhook_NSProcessInfo);
}

void shadowhook_NSProcessInfo_fakemac(HKSubstitutor* hooks) {
    (void) hooks;  // FakeMac removed: nothing to install.
}
