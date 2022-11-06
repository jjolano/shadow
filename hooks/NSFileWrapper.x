#import "hooks.h"

%group shadowhook_NSFileWrapper
%hook NSFileWrapper
- (instancetype)initWithURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return 0;
    }

    return %orig;
}

- (instancetype)initSymbolicLinkWithDestinationURL:(NSURL *)url {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return 0;
    }

    return %orig;
}

- (BOOL)matchesContentsOfURL:(NSURL *)url {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return %orig;
}

- (BOOL)readFromURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSFileWrapperWritingOptions)options originalContentsURL:(NSURL *)originalContentsURL error:(NSError * _Nullable *)outError {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSFileWrapper(void) {
    %init(shadowhook_NSFileWrapper);
}
