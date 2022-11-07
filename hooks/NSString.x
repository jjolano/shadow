#import "hooks.h"

%group shadowhook_NSString
%hook NSString
- (instancetype)initWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

- (NSUInteger)completePathIntoString:(NSString * _Nullable *)outputName caseSensitive:(BOOL)flag matchesIntoArray:(NSArray<NSString *> * _Nullable *)outputArray filterTypes:(NSArray<NSString *> *)filterTypes {
    if([_shadow isPathRestricted:self] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return 0;
    }

    return %orig;
}
%end
%end

void shadowhook_NSString(void) {
    %init(shadowhook_NSString);
}
