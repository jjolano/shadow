#import "hooks.h"

%group shadowhook_UIApplication
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    BOOL result = %orig;

    HBLogDebug(@"%@: %@", @"canOpenURL", url);
    
    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return result;
}
%end
%end

void shadowhook_UIApplication(void) {
    %init(shadowhook_UIApplication);
}
