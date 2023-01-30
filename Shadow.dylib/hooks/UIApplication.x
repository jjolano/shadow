#import "hooks.h"

%group shadowhook_UIApplication
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    NSLog(@"%@: %@", @"canOpenURL", url);
    
    if([_shadow isURLRestricted:url] && !isCallerTweak()) {
        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_UIApplication(HKSubstitutor* hooks) {
    %init(shadowhook_UIApplication);
}
