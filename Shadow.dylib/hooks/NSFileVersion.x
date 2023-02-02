#import "hooks.h"

%group shadowhook_NSFileVersion
%hook NSFileVersion
+ (NSFileVersion *)currentVersionOfItemAtURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSArray<NSFileVersion *> *)otherVersionsOfItemAtURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSFileVersion *)versionOfItemAtURL:(NSURL *)url forPersistentIdentifier:(id)persistentIdentifier {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSURL *)temporaryDirectoryURLForNewVersionOfItemAtURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSFileVersion *)addVersionOfItemAtURL:(NSURL *)url withContentsOfURL:(NSURL *)contentsURL options:(NSFileVersionAddingOptions)options error:(NSError * _Nullable *)outError {
    if(!isCallerTweak() && ([_shadow isURLRestricted:url] || [_shadow isURLRestricted:contentsURL])) {
        if(outError) {
            *outError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (NSArray<NSFileVersion *> *)unresolvedConflictVersionsOfItemAtURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURL *)replaceItemAtURL:(NSURL *)url options:(NSFileVersionReplacingOptions)options error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (BOOL)removeOtherVersionsOfItemAtURL:(NSURL *)url error:(NSError * _Nullable *)outError {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}

+ (void)getNonlocalVersionsOfItemAtURL:(NSURL *)url completionHandler:(void (^)(NSArray<NSFileVersion *> *nonlocalFileVersions, NSError *error))completionHandler {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(completionHandler) {
            completionHandler(nil, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil]);
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
