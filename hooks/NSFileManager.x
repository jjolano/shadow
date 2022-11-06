#import "hooks.h"

%group shadowhook_NSFileManager
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    BOOL result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return result;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    NSArray* backtrace = [NSThread callStackSymbols];
    BOOL result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return result;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    BOOL result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return result;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    BOOL result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return result;
}

- (BOOL)isDeletableFileAtPath:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    BOOL result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return result;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    BOOL result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return result;
}

- (NSData *)contentsAtPath:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    NSData* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return result;
}

- (BOOL)contentsEqualAtPath:(NSString *)path1 andPath:(NSString *)path2 {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if(([_shadow isPathRestricted:path1] || [_shadow isPathRestricted:path2]) && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSFileManager(void) {
    %init(shadowhook_NSFileManager);
}
