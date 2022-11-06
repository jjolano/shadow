#import "hooks.h"

%group shadowhook_NSURL
%hook NSURL
- (BOOL)checkResourceIsReachableAndReturnError:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];
    BOOL result = %orig;
    
    if(result && [_shadow isURLRestricted:self] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return result;
}

- (NSURL *)fileReferenceURL {
    NSArray* backtrace = [NSThread callStackSymbols];
    NSURL* result = %orig;
    
    if(result && [_shadow isURLRestricted:self] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return result;
}
%end
%end

void shadowhook_NSURL(void) {
    %init(shadowhook_NSURL);
}
