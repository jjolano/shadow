#import "hooks.h"

%group shadowhook_NSFileVersion
%hook NSFileVersion
+ (NSFileVersion *)currentVersionOfItemAtURL:(NSURL *)url {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (NSArray<NSFileVersion *> *)otherVersionsOfItemAtURL:(NSURL *)url {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (NSFileVersion *)versionOfItemAtURL:(NSURL *)url forPersistentIdentifier:(id)persistentIdentifier {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (NSURL *)temporaryDirectoryURLForNewVersionOfItemAtURL:(NSURL *)url {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (NSFileVersion *)addVersionOfItemAtURL:(NSURL *)url withContentsOfURL:(NSURL *)contentsURL options:(NSFileVersionAddingOptions)options error:(NSError * _Nullable *)outError {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if(([_shadow isURLRestricted:url] || [_shadow isURLRestricted:contentsURL]) && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (NSArray<NSFileVersion *> *)unresolvedConflictVersionsOfItemAtURL:(NSURL *)url {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

- (NSURL *)replaceItemAtURL:(NSURL *)url options:(NSFileVersionReplacingOptions)options error:(NSError * _Nullable *)error {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return nil;
    }

    return %orig;
}

+ (BOOL)removeOtherVersionsOfItemAtURL:(NSURL *)url error:(NSError * _Nullable *)outError {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        return NO;
    }

    return %orig;
}

+ (void)getNonlocalVersionsOfItemAtURL:(NSURL *)url completionHandler:(void (^)(NSArray<NSFileVersion *> *nonlocalFileVersions, NSError *error))completionHandler {
    NSArray* backtrace = [NSThread callStackSymbols];
    
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:backtrace]) {
        if(completionHandler) {
            completionHandler(nil, nil);
        }

        return;
    }

    %orig;
}
%end
%end

void shadowhook_NSFileVersion(void) {
    %init(shadowhook_NSFileVersion);
}
