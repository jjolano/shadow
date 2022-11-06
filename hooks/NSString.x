#import "hooks.h"

%group shadowhook_NSString
%hook NSString
- (instancetype)initWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

- (NSUInteger)completePathIntoString:(NSString * _Nullable *)outputName caseSensitive:(BOOL)flag matchesIntoArray:(NSArray<NSString *> * _Nullable *)outputArray filterTypes:(NSArray<NSString *> *)filterTypes {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isPathRestricted:self] && ![_shadow isCallerTweak:backtrace]) {
        return 0;
    }

    return %orig;
}
%end
%end

void shadowhook_NSString(void) {
    %init(shadowhook_NSString);
}
