#import "hooks.h"

%group shadowhook_NSArray
%hook NSArray
- (id)initWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

- (NSArray *)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

+ (NSArray *)arrayWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

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

%hook NSMutableArray
- (id)initWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}
%end
%end

void shadowhook_NSArray(HKSubstitutor* hooks) {
    %init(shadowhook_NSArray);
}
