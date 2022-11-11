#import "hooks.h"

%group shadowhook_NSFileWrapper
%hook NSFileWrapper
- (instancetype)initWithURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(outError) {
            *outError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return 0;
    }

    return %orig;
}

- (instancetype)initSymbolicLinkWithDestinationURL:(NSURL *)url {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return 0;
    }

    return %orig;
}

- (BOOL)matchesContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)readFromURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(outError) {
            *outError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSFileWrapperWritingOptions)options originalContentsURL:(NSURL *)originalContentsURL error:(NSError * _Nullable *)outError {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(outError) {
            *outError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSFileWrapper(void) {
    %init(shadowhook_NSFileWrapper);
}
