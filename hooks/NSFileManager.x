#import "hooks.h"

%group shadowhook_NSFileManager
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return NO;
    }

    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if([_shadow isPathRestricted:path]) {
        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSFileManager(void) {
    %init(shadowhook_NSFileManager);
}
