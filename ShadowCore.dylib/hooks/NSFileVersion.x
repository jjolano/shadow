#import "hooks.h"

// Drop versions whose real URL is hidden: the -URL hook already returns nil
// for restricted versions, so nil is a denial signal in either direction
// (filtered answer for external callers, truthful answer for Shadow's own).
static NSArray* _shdw_filterVersionArray(NSArray* versions) {
    NSMutableArray* filtered = [NSMutableArray arrayWithCapacity:[versions count]];

    for(NSFileVersion* version in versions) {
        NSURL* url = [version URL];

        if(url && ![_shadow isURLRestricted:url]) {
            [filtered addObject:version];
        }
    }

    return filtered;
}

%group shadowhook_NSFileVersion
%hook NSFileVersion
+ (NSFileVersion *)currentVersionOfItemAtURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (NSArray<NSFileVersion *> *)otherVersionsOfItemAtURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    NSArray* result = %orig;

    if(result && isCallerExternal()) {
        result = _shdw_filterVersionArray(result);
    }

    return result;
}

+ (NSFileVersion *)versionOfItemAtURL:(NSURL *)url forPersistentIdentifier:(id)persistentIdentifier {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (NSURL *)temporaryDirectoryURLForNewVersionOfItemAtURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (NSFileVersion *)addVersionOfItemAtURL:(NSURL *)url withContentsOfURL:(NSURL *)contentsURL options:(NSFileVersionAddingOptions)options error:(NSError * _Nullable *)outError {
    if(isCallerExternal()) {
        // The versioned item is written; the contents source is read.
        NSDictionary* writeOptions = @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};

        if([_shadow isURLRestricted:url options:writeOptions] || [_shadow isURLRestricted:contentsURL]) {
            if(outError) {
                *outError = [Shadow fileNoSuchFileErrorForURL:url];
            }

            return nil;
        }
    }

    return %orig;
}

+ (NSArray<NSFileVersion *> *)unresolvedConflictVersionsOfItemAtURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    NSArray* result = %orig;

    if(result && isCallerExternal()) {
        result = _shdw_filterVersionArray(result);
    }

    return result;
}

// The receiver's real location: hidden versions report nil so a version
// object obtained before a ruleset change (or via an unfiltered path)
// cannot disclose its file.
- (NSURL *)URL {
    NSURL* result = %orig;

    if(isCallerExternal() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSURL *)replaceItemAtURL:(NSURL *)url options:(NSFileVersionReplacingOptions)options error:(NSError * _Nullable *)error {
    if(isCallerExternal()) {
        NSDictionary* writeOptions = @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};

        NSURL* selfURL = [self URL];

        if(!selfURL || [_shadow isURLRestricted:selfURL options:writeOptions] || [_shadow isURLRestricted:url options:writeOptions]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForURL:url];
            }

            return nil;
        }
    }

    NSURL* result = %orig;

    if(result && isCallerExternal() && [_shadow isURLRestricted:result]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:result];
        }

        return nil;
    }

    return result;
}

- (BOOL)removeAndReturnError:(NSError * _Nullable *)error {
    if(isCallerExternal()) {
        NSURL* selfURL = [self URL];

        if(!selfURL || [_shadow isURLRestricted:selfURL options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForURL:selfURL];
            }

            return NO;
        }
    }

    return %orig;
}

+ (BOOL)removeOtherVersionsOfItemAtURL:(NSURL *)url error:(NSError * _Nullable *)outError {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(outError) {
            *outError = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    return %orig;
}

+ (void)getNonlocalVersionsOfItemAtURL:(NSURL *)url completionHandler:(void (^)(NSArray<NSFileVersion *> *nonlocalFileVersions, NSError *error))completionHandler {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(completionHandler) {
            // Async-contract: never invoke a blocked-path completion inline.
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                completionHandler(nil, [Shadow fileNoSuchFileErrorForURL:url]);
            });
        }

        return;
    }

    %orig;
}
%end
%end

void shadowhook_NSFileVersion(HKSubstitutor* hooks) {
    %init(shadowhook_NSFileVersion);
}
