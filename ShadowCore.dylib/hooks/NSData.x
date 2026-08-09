#import "hooks.h"

%group shadowhook_NSData
%hook NSData
+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if(isCallerExternal() && [_shadow isPathRestricted:path]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if(isCallerExternal() && [_shadow isPathRestricted:path]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfMappedFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (id)dataWithContentsOfMappedFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToFile:(NSString *)path options:(NSDataWritingOptions)writeOptionsMask error:(NSError * _Nullable *)errorPtr {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileErrorWithCode:NSFileWriteUnknownError path:path url:nil];
        }

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

- (BOOL)writeToURL:(NSURL *)url options:(NSDataWritingOptions)writeOptionsMask error:(NSError * _Nullable *)errorPtr {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileErrorWithCode:NSFileWriteUnknownError path:[url path] url:url];
        }

        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSData(HKSubstitutor* hooks) {
    %init(shadowhook_NSData);
}
