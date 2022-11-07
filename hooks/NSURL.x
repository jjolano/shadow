#import "hooks.h"

%group shadowhook_NSURL
%hook NSURL
- (BOOL)checkResourceIsReachableAndReturnError:(NSError * _Nullable *)error {
    BOOL result = %orig;
    
    if(result && [_shadow isURLRestricted:self] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return result;
}

- (BOOL)checkPromisedItemIsReachableAndReturnError:(NSError * _Nullable *)error {
    BOOL result = %orig;
    
    if(result && [_shadow isURLRestricted:self] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return result;
}

- (NSURL *)fileReferenceURL {
    NSURL* result = %orig;
    
    if(result && [_shadow isURLRestricted:self] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (NSData *)bookmarkDataWithContentsOfURL:(NSURL *)bookmarkFileURL error:(NSError * _Nullable *)error {
    NSData* result = %orig;
    
    if(result && [_shadow isURLRestricted:bookmarkFileURL] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}
%end
%end

void shadowhook_NSURL(void) {
    %init(shadowhook_NSURL);
}
