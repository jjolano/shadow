#import "hooks.h"

static char* _NSDirectoryEnumerator_shdw_key = "shdw";

%group shadowhook_NSFileManager
%hook NSDirectoryEnumerator
- (NSArray *)allObjects {
    BOOL isTweak = isCallerTweak();

    if(isTweak) {
        return %orig;
    }

    NSString* base = objc_getAssociatedObject(self, _NSDirectoryEnumerator_shdw_key);

    if(!base) {
        NSLog(@"NSDirectoryEnumerator base not found");
        base = @"";
    }

    if([_shadow isPathRestricted:base]) {
        return @[];
    }

    NSArray* result = %orig; 

    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : base}];
    }

    return result;
}

- (id)nextObject {
    BOOL isTweak = isCallerTweak();

    if(isTweak) {
        return %orig;
    }

    NSString* base = objc_getAssociatedObject(self, _NSDirectoryEnumerator_shdw_key);

    if(!base) {
        NSLog(@"NSDirectoryEnumerator base not found");
        base = @"";
    }

    if([_shadow isPathRestricted:base]) {
        return nil;
    }

    id result = %orig;

    // keep looping until we get something unrestricted or nil
    while(result) {
        NSString* path = nil;

        if([result isKindOfClass:[NSURL class]]) {
            path = [result path];
        } else if([result isKindOfClass:[NSString class]]) {
            path = result;
        }

        if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : base}]) {
            result = %orig;
        } else {
            break;
        }
    }

    return result;
}
%end

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    BOOL result = %orig;

    if(result && !isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return result;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    BOOL result = %orig;

    if(result && !isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return result;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    BOOL result = %orig;

    if(result && !isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return result;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    BOOL result = %orig;

    if(result && !isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return result;
}

- (BOOL)isDeletableFileAtPath:(NSString *)path {
    BOOL result = %orig;

    if(result && !isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return result;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
    BOOL result = %orig;

    if(result && !isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return result;
}

- (NSData *)contentsAtPath:(NSString *)path {
    NSData* result = %orig;

    if(result && !isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return nil;
    }

    return result;
}

- (BOOL)contentsEqualAtPath:(NSString *)path1 andPath:(NSString *)path2 {
    if(!isCallerTweak() && ([_shadow isPathRestricted:path1 options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isPathRestricted:path2 options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        return NO;
    }

    return %orig;
}

- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError * _Nullable *)error {
    BOOL isTweak = isCallerTweak();

    if(isTweak) {
        return %orig;
    }

    if([_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}];
    }

    return result;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    BOOL isTweak = isCallerTweak();

    if(isTweak) {
        return %orig;
    }

    if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : path}];
    }

    return result;
}

- (NSDirectoryEnumerator<NSURL *> *)enumeratorAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask errorHandler:(BOOL (^)(NSURL *url, NSError *error))handler {
    NSDirectoryEnumerator* result = %orig;
    
    if(result) {
        objc_setAssociatedObject(result, _NSDirectoryEnumerator_shdw_key, [url path], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        NSLog(@"%@: %@", @"enumeratorAtURL", url);
    }

    return result;
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path {
    NSDirectoryEnumerator* result = %orig;

    if(result) {
        objc_setAssociatedObject(result, _NSDirectoryEnumerator_shdw_key, path, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        NSLog(@"%@: %@", @"enumeratorAtPath", path);
    }
    
    return result;
}

- (NSArray<NSString *> *)subpathsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    BOOL isTweak = isCallerTweak();

    if(isTweak) {
        return %orig;
    }

    if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : path}];
    }

    return result;
}

- (NSArray<NSString *> *)subpathsAtPath:(NSString *)path {
    BOOL isTweak = isCallerTweak();

    if(isTweak) {
        return %orig;
    }

    if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : path}];
    }

    return result;
}

- (void)getFileProviderServicesForItemAtURL:(NSURL *)url completionHandler:(void (^)(NSDictionary *services, NSError *error))completionHandler {
    if(!isCallerTweak() && [_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(completionHandler) {
            completionHandler(nil, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil]);
        }

        return;
    }

    %orig;
}

- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }
        
        return nil;
    }

    return %orig;
}

- (NSArray<NSString *> *)componentsToDisplayForPath:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return nil;
    }

    return %orig;
}

- (NSString *)displayNameAtPath:(NSString *)path {
    NSString* result = %orig;

    if(result && !isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return nil;
    }

    return result;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    // Make sure rootfs is marked read-only
    NSDictionary<NSFileAttributeKey, id>* result = %orig;

    if(result && (
        [path hasPrefix:@"/private/preboot"]
        || [path hasPrefix:@"/private/var"]
        || [path hasPrefix:@"/var"]
    )) {
        NSMutableDictionary<NSFileAttributeKey, id>* result_filtered = [result mutableCopy];
        [result_filtered setObject:@(YES) forKey:NSFileAppendOnly];
        result = [result_filtered copy];
    }

    return result;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfFileSystemForPath:(NSString *)path error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    // Make sure rootfs is marked read-only
    NSDictionary<NSFileAttributeKey, id>* result = %orig;

    if(result && (
        [path hasPrefix:@"/private/preboot"]
        || [path hasPrefix:@"/private/var"]
        || [path hasPrefix:@"/var"]
    )) {
        NSMutableDictionary<NSFileAttributeKey, id>* result_filtered = [result mutableCopy];
        [result_filtered setObject:@(YES) forKey:NSFileAppendOnly];
        result = [result_filtered copy];
    }

    return result;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectoryAtURL:(NSURL *)directoryURL toItemAtURL:(NSURL *)otherURL error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && ([_shadow isURLRestricted:directoryURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isURLRestricted:otherURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }
        
        return NO;
    }

    return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domainMask toItemAtURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)changeCurrentDirectoryPath:(NSString *)path {
    NSLog(@"%@: %@", @"changeCurrentDirectoryPath", path);

    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return %orig;
}

- (NSDictionary *)fileAttributesAtPath:(NSString *)path traverseLink:(BOOL)yorn {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return nil;
    }

    return %orig;
}

- (NSDictionary *)fileSystemAttributesAtPath:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return nil;
    }

    // Make sure rootfs is marked read-only
    NSDictionary<NSFileAttributeKey, id>* result = %orig;

    if(result && (
        [path hasPrefix:@"/private/preboot"]
        || [path hasPrefix:@"/private/var"]
        || [path hasPrefix:@"/var"]
    )) {
        NSMutableDictionary<NSFileAttributeKey, id>* result_filtered = [result mutableCopy];
        [result_filtered setObject:@(YES) forKey:NSFileAppendOnly];
        result = [result_filtered copy];
    }

    return result;
}

- (NSArray *)directoryContentsAtPath:(NSString *)path {
    BOOL isTweak = isCallerTweak();

    if(isTweak) {
        return %orig;
    }

    if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : path}];
    }

    return result;
}

- (NSString *)pathContentOfSymbolicLinkAtPath:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return nil;
    }

    return %orig;
}

- (BOOL)replaceItemAtURL:(NSURL *)originalItemURL withItemAtURL:(NSURL *)newItemURL backupItemName:(NSString *)backupItemName options:(NSFileManagerItemReplacementOptions)options resultingItemURL:(NSURL * _Nullable *)resultingURL error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && ([_shadow isURLRestricted:originalItemURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isURLRestricted:newItemURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && ([_shadow isURLRestricted:srcURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isURLRestricted:dstURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && ([_shadow isPathRestricted:srcPath options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isPathRestricted:dstPath options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)moveItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && ([_shadow isURLRestricted:srcURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isURLRestricted:dstURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && ([_shadow isPathRestricted:srcPath options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isPathRestricted:dstPath options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)isUbiquitousItemAtURL:(NSURL *)url {
    BOOL result = %orig;

    if(!isCallerTweak() && result && [_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return result;
}

- (BOOL)setUbiquitous:(BOOL)flag itemAtURL:(NSURL *)url destinationURL:(NSURL *)destinationURL error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && ([_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isURLRestricted:destinationURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)startDownloadingUbiquitousItemAtURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)evictUbiquitousItemAtURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (NSURL *)URLForPublishingUbiquitousItemAtURL:(NSURL *)url expirationDate:(NSDate * _Nullable *)outDate error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (BOOL)createSymbolicLinkAtURL:(NSURL *)url withDestinationURL:(NSURL *)destURL error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createSymbolicLinkAtPath:(NSString *)path withDestinationPath:(NSString *)destPath error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)linkItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && ([_shadow isURLRestricted:srcURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isURLRestricted:dstURL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)linkItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && ([_shadow isPathRestricted:srcPath options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isPathRestricted:dstPath options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyPath:(NSString *)src toPath:(NSString *)dest handler:(id)handler {
    if(!isCallerTweak() && ([_shadow isPathRestricted:src options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isPathRestricted:dest options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        return NO;
    }

    return %orig;
}

- (BOOL)movePath:(NSString *)src toPath:(NSString *)dest handler:(id)handler {
    if(!isCallerTweak() && ([_shadow isPathRestricted:src options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isPathRestricted:dest options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        return NO;
    }

    return %orig;
}

- (BOOL)removeFileAtPath:(NSString *)path handler:(id)handler {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)changeFileAttributes:(NSDictionary *)attributes atPath:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)linkPath:(NSString *)src toPath:(NSString *)dest handler:(id)handler {
    if(!isCallerTweak() && ([_shadow isPathRestricted:src options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}] || [_shadow isPathRestricted:dest options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}])) {
        return NO;
    }

    return %orig;
}

- (BOOL)createDirectoryAtURL:(NSURL *)url withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary<NSFileAttributeKey, id> *)attr {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtURL:(NSURL *)URL error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:URL options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)trashItemAtURL:(NSURL *)url resultingItemURL:(NSURL * _Nullable *)outResultingURL error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url options:@{kShadowRestrictionWorkingDir : [self currentDirectoryPath]}]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSFileManager(HKSubstitutor* hooks) {
    %init(shadowhook_NSFileManager);
}
