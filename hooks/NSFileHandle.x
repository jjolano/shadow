#import "hooks.h"

%group shadowhook_NSFileHandle
%hook NSFileHandle
+ (instancetype)fileHandleForReadingAtPath:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];

    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForReadingFromURL:(NSURL *)url error:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];

    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForWritingAtPath:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];

    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForWritingToURL:(NSURL *)url error:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];

    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForUpdatingAtPath:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];

    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForUpdatingURL:(NSURL *)url error:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSFileHandle(void) {
    %init(shadowhook_NSFileHandle);
}
