#import "hooks.h"

%group shadowhook_NSFileWrapper
%hook NSFileWrapper
- (instancetype)initWithURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return 0;
    }

    return %orig;
}

- (instancetype)initSymbolicLinkWithDestinationURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return 0;
    }

    return %orig;
}

- (BOOL)matchesContentsOfURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}

- (BOOL)readFromURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSFileWrapperWritingOptions)options originalContentsURL:(NSURL *)originalContentsURL error:(NSError * _Nullable *)outError {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSFileWrapper(HKSubstitutor* hooks) {
    %init(shadowhook_NSFileWrapper);
}
