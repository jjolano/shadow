#import "hooks.h"

%group shadowhook_NSDictionary
%hook NSDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSMutableDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSDictionary(void) {
    %init(shadowhook_NSDictionary);
}
