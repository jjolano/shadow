#import "hooks.h"

%group shadowhook_UIApplication
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        NSLog(@"%@: %@", @"canOpenURL restricted", url);
        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_UIApplication(HKSubstitutor* hooks) {
    %init(shadowhook_UIApplication);
}
