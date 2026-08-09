#import "hooks.h"

%group shadowhook_NSDictionary
%hook NSDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(error) {
            *error = [Shadow fileErrorWithCode:NSFileWriteUnknownError path:[url path] url:url];
        }

        return NO;
    }

    return %orig;
}
%end

%hook NSMutableDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (NSMutableDictionary *)dictionaryWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (NSMutableDictionary *)dictionaryWithContentsOfURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}
%end
%end

void shadowhook_NSDictionary(HKSubstitutor* hooks) {
    %init(shadowhook_NSDictionary);
}
