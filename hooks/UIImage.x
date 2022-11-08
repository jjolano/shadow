#import "hooks.h"

%group shadowhook_UIImage
%hook UIImage
- (instancetype)initWithContentsOfFile:(NSString *)path {
    UIImage* result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (UIImage *)imageWithContentsOfFile:(NSString *)path {
    UIImage* result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}
%end
%end

void shadowhook_UIImage(void) {
    %init(shadowhook_UIImage);
}
