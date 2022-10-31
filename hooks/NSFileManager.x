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

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isDeletableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return NO;
    }

    return %orig;
}

- (NSData *)contentsAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

- (BOOL)contentsEqualAtPath:(NSString *)path1 andPath:(NSString *)path2 {
    if([_shadow isPathRestricted:path1] || [_shadow isPathRestricted:path2]) {
        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSFileManager(void) {
    %init(shadowhook_NSFileManager);
}
