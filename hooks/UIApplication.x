#import "hooks.h"

%group shadowhook_UIApplication
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    NSArray* backtrace = [NSThread callStackSymbols];
    BOOL result = %orig;

    HBLogDebug(@"%@: %@", @"canOpenURL", url);
    
    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return result;
}
%end
%end

void shadowhook_UIApplication(void) {
    %init(shadowhook_UIApplication);
}
