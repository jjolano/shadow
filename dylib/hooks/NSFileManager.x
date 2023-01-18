#import "hooks.h"

static char* _NSDirectoryEnumerator_shdw_key = "shdw";

%group shadowhook_NSFileManager
%hook NSDirectoryEnumerator
- (NSArray *)allObjects {
    BOOL isTweak = [_shadow isCallerTweak:[NSThread callStackReturnAddresses]];
    NSString* base = objc_getAssociatedObject(self, _NSDirectoryEnumerator_shdw_key);

    if(!isTweak && [_shadow isPathRestricted:base]) {
        return @[];
    }

    NSArray* result = %orig; 

    if(result && !isTweak) {
        NSMutableArray* result_filtered = [NSMutableArray new];
        
        for(id entry in result) {
            NSString* path = nil;

            if([entry isKindOfClass:[NSURL class]]) {
                path = [entry path];
            } else if([entry isKindOfClass:[NSString class]] && base) {
                path = [base stringByAppendingPathComponent:entry];
            }

            if(![_shadow isPathRestricted:path]) {
                [result_filtered addObject:entry];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (id)nextObject {
    BOOL isTweak = [_shadow isCallerTweak:[NSThread callStackReturnAddresses]];
    NSString* base = objc_getAssociatedObject(self, _NSDirectoryEnumerator_shdw_key);

    if(!isTweak && [_shadow isPathRestricted:base]) {
        return nil;
    }

    id result = %orig;

    if(result && !isTweak) {
        // keep looping until we get something unrestricted or nil
        do {
            NSString* path = nil;

            if([result isKindOfClass:[NSURL class]]) {
                path = [result path];
            } else if([result isKindOfClass:[NSString class]] && base) {
                path = [base stringByAppendingPathComponent:result];
            }

            if(path && [_shadow isPathRestricted:path]) {
                result = %orig;
            } else {
                break;
            }
        } while(result);
    }

    return result;
}
%end

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isDeletableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (NSData *)contentsAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

- (BOOL)contentsEqualAtPath:(NSString *)path1 andPath:(NSString *)path2 {
    if(([_shadow isPathRestricted:path1] || [_shadow isPathRestricted:path2]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError * _Nullable *)error {
    BOOL isTweak = [_shadow isCallerTweak:[NSThread callStackReturnAddresses]];

    if([_shadow isURLRestricted:url] && !isTweak) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result && !isTweak) {
        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSURL* result_url in result) {
            if(![_shadow isURLRestricted:result_url]) {
                [result_filtered addObject:result_url];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    BOOL isTweak = [_shadow isCallerTweak:[NSThread callStackReturnAddresses]];

    if([_shadow isPathRestricted:path] && !isTweak) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result && !isTweak) {
        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSString* result_path in result) {
            NSString* abspath = result_path;

            if(![abspath isAbsolutePath]) {
                abspath = [path stringByAppendingPathComponent:result_path];
            }

            if(![_shadow isPathRestricted:abspath]) {
                [result_filtered addObject:result_path];
            }
        }

        result = [result_filtered copy];
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
    BOOL isTweak = [_shadow isCallerTweak:[NSThread callStackReturnAddresses]];

    if([_shadow isPathRestricted:path] && !isTweak) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result && !isTweak) {
        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSString* result_path in result) {
            NSString* abspath = result_path;

            if(![abspath isAbsolutePath]) {
                abspath = [path stringByAppendingPathComponent:result_path];
            }

            if(![_shadow isPathRestricted:abspath]) {
                [result_filtered addObject:result_path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSArray<NSString *> *)subpathsAtPath:(NSString *)path {
    BOOL isTweak = [_shadow isCallerTweak:[NSThread callStackReturnAddresses]];

    if([_shadow isPathRestricted:path] && !isTweak) {
        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result && !isTweak) {
        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSString* result_path in result) {
            NSString* abspath = result_path;

            if(![abspath isAbsolutePath]) {
                abspath = [path stringByAppendingPathComponent:result_path];
            }

            if(![_shadow isPathRestricted:abspath]) {
                [result_filtered addObject:result_path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (void)getFileProviderServicesForItemAtURL:(NSURL *)url completionHandler:(void (^)(NSDictionary *services, NSError *error))completionHandler {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(completionHandler) {
            completionHandler(nil, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil]);
        }

        return;
    }

    %orig;
}

- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }
        
        return nil;
    }

    return %orig;
}

- (NSArray<NSString *> *)componentsToDisplayForPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

- (NSString *)displayNameAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
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
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
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
    if(([_shadow isURLRestricted:directoryURL] || [_shadow isURLRestricted:otherURL]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }
        
        return NO;
    }

    return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domainMask toItemAtURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)changeCurrentDirectoryPath:(NSString *)path {
    NSLog(@"%@: %@", @"changeCurrentDirectoryPath", path);

    NSString* cwd = [self currentDirectoryPath];

    if(![path isAbsolutePath]) {
        // reconstruct path
        path = [cwd stringByAppendingPathComponent:path];
    }

    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (NSDictionary *)fileAttributesAtPath:(NSString *)path traverseLink:(BOOL)yorn {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

- (NSDictionary *)fileSystemAttributesAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
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
    BOOL isTweak = [_shadow isCallerTweak:[NSThread callStackReturnAddresses]];

    if([_shadow isPathRestricted:path] && !isTweak) {
        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result && !isTweak) {
        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSString* result_path in result) {
            NSString* abspath = result_path;

            if(![abspath isAbsolutePath]) {
                abspath = [path stringByAppendingPathComponent:result_path];
            }

            if(![_shadow isPathRestricted:abspath]) {
                [result_filtered addObject:result_path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSString *)pathContentOfSymbolicLinkAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

- (BOOL)replaceItemAtURL:(NSURL *)originalItemURL withItemAtURL:(NSURL *)newItemURL backupItemName:(NSString *)backupItemName options:(NSFileManagerItemReplacementOptions)options resultingItemURL:(NSURL * _Nullable *)resultingURL error:(NSError * _Nullable *)error {
    if(([_shadow isURLRestricted:originalItemURL] || [_shadow isURLRestricted:newItemURL]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if(([_shadow isURLRestricted:srcURL] || [_shadow isURLRestricted:dstURL]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if(([_shadow isPathRestricted:srcPath] || [_shadow isPathRestricted:dstPath]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)moveItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if(([_shadow isURLRestricted:srcURL] || [_shadow isURLRestricted:dstURL]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if(([_shadow isPathRestricted:srcPath] || [_shadow isPathRestricted:dstPath]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)isUbiquitousItemAtURL:(NSURL *)url {
    BOOL result = %orig;

    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return result;
}

- (BOOL)setUbiquitous:(BOOL)flag itemAtURL:(NSURL *)url destinationURL:(NSURL *)destinationURL error:(NSError * _Nullable *)error {
    if(([_shadow isURLRestricted:url] || [_shadow isURLRestricted:destinationURL]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)startDownloadingUbiquitousItemAtURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)evictUbiquitousItemAtURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (NSURL *)URLForPublishingUbiquitousItemAtURL:(NSURL *)url expirationDate:(NSDate * _Nullable *)outDate error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (BOOL)createSymbolicLinkAtURL:(NSURL *)url withDestinationURL:(NSURL *)destURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createSymbolicLinkAtPath:(NSString *)path withDestinationPath:(NSString *)destPath error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)linkItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if(([_shadow isURLRestricted:srcURL] || [_shadow isURLRestricted:dstURL]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)linkItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if(([_shadow isPathRestricted:srcPath] || [_shadow isPathRestricted:dstPath]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyPath:(NSString *)src toPath:(NSString *)dest handler:(id)handler {
    if(([_shadow isPathRestricted:src] || [_shadow isPathRestricted:dest]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)movePath:(NSString *)src toPath:(NSString *)dest handler:(id)handler {
    if(([_shadow isPathRestricted:src] || [_shadow isPathRestricted:dest]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)removeFileAtPath:(NSString *)path handler:(id)handler {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)changeFileAttributes:(NSDictionary *)attributes atPath:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)linkPath:(NSString *)src toPath:(NSString *)dest handler:(id)handler {
    if(([_shadow isPathRestricted:src] || [_shadow isPathRestricted:dest]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)createDirectoryAtURL:(NSURL *)url withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary<NSFileAttributeKey, id> *)attr {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtURL:(NSURL *)URL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:URL] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)trashItemAtURL:(NSURL *)url resultingItemURL:(NSURL * _Nullable *)outResultingURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
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
