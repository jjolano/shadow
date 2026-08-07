#import "hooks.h"

%group shadowhook_NSFileWrapper
%hook NSFileWrapper
// TODO(plan-wave-C): NSFileWrapper containment — fileWrappers,
// regularFileContents, symbolicLinkDestinationURL, serializedRepresentation
// and writeToURL:originalContentsURL: tree containment need an associated
// source URL, out of scope for this wave.
- (instancetype)initWithURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return 0;
    }

    return %orig;
}

- (instancetype)initSymbolicLinkWithDestinationURL:(NSURL *)url {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        return 0;
    }

    return %orig;
}

- (BOOL)matchesContentsOfURL:(NSURL *)url {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}

- (BOOL)readFromURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSFileWrapperWritingOptions)options originalContentsURL:(NSURL *)originalContentsURL error:(NSError * _Nullable *)outError {
    NSDictionary* writeOptions = @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};

    if(isCallerExternal() && [_shadow isURLRestricted:url options:writeOptions]) {
        if(outError) {
            *outError = [Shadow fileNoSuchFileErrorForURL:url];
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
