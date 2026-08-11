#import "hooks.h"

// Source-URL association: initWithURL:/readFromURL: record the wrapper's
// source URL so the tree accessors (fileWrappers, regularFileContents,
// symbolicLinkDestinationURL, serializedRepresentation) and
// writeToURL:originalContentsURL: can enforce containment on wrappers
// descended from a restricted source.
static const void* _NSFileWrapper_shdw_source_url_key = &_NSFileWrapper_shdw_source_url_key;

static NSURL* shdw_wrapper_source_url(NSFileWrapper* w) {
    return objc_getAssociatedObject(w, _NSFileWrapper_shdw_source_url_key);
}

static BOOL shdw_wrapper_source_restricted(NSFileWrapper* w) {
    NSURL* url = shdw_wrapper_source_url(w);

    return url && [_shadow isURLRestricted:url];
}

%group shadowhook_NSFileWrapper
%hook NSFileWrapper
- (instancetype)initWithURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return 0;
    }

    self = %orig;

    if(self) {
        objc_setAssociatedObject(self, _NSFileWrapper_shdw_source_url_key, url, OBJC_ASSOCIATION_COPY_NONATOMIC);
    }

    return self;
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

    BOOL result = %orig;

    if(result) {
        objc_setAssociatedObject(self, _NSFileWrapper_shdw_source_url_key, url, OBJC_ASSOCIATION_COPY_NONATOMIC);
    }

    return result;
}

- (NSDictionary<NSString *,NSFileWrapper *> *)fileWrappers {
    NSDictionary<NSString *,NSFileWrapper *> *result = %orig;

    if(result && isCallerExternal()) {
        NSMutableDictionary<NSString *,NSFileWrapper *> *filtered = [NSMutableDictionary dictionaryWithCapacity:[result count]];

        for(NSString* name in result) {
            NSFileWrapper* child = result[name];

            if(!shdw_wrapper_source_restricted(child)) {
                filtered[name] = child;
            }
        }

        result = filtered;
    }

    return result;
}

- (NSData *)regularFileContents {
    if(isCallerExternal() && shdw_wrapper_source_restricted(self)) {
        return nil;
    }

    return %orig;
}

- (NSURL *)symbolicLinkDestinationURL {
    if(isCallerExternal() && shdw_wrapper_source_restricted(self)) {
        return nil;
    }

    return %orig;
}

- (NSData *)serializedRepresentation {
    if(isCallerExternal() && shdw_wrapper_source_restricted(self)) {
        return nil;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSFileWrapperWritingOptions)options originalContentsURL:(NSURL *)originalContentsURL error:(NSError * _Nullable *)outError {
    NSDictionary* writeOptions = shdw_restriction_write_options();

    if(isCallerExternal() && ([_shadow isURLRestricted:url options:writeOptions] || [_shadow isURLRestricted:originalContentsURL])) {
        if(outError) {
            *outError = [Shadow fileNoSuchFileErrorForURL:originalContentsURL];
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
