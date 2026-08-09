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

// initSymbolicLinkWithDestinationURL: intentionally NOT hooked — it only
// records the destination (no I/O at construction, so nothing can leak) and
// stock never returns nil from it, so a filtered nil would be a
// stock-impossible answer for the exact value the caller supplied.

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
