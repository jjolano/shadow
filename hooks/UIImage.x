#import "hooks.h"

%group shadowhook_UIImage
%hook UIImage
- (instancetype)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_UIImage(void) {
    %init(shadowhook_UIImage);
}
