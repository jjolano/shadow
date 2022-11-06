#import "hooks.h"

%group shadowhook_UIImage
%hook UIImage
- (instancetype)initWithContentsOfFile:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageWithContentsOfFile:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_UIImage(void) {
    %init(shadowhook_UIImage);
}
