#import "hooks.h"

%group shadowhook_NSFileManager

%hook NSDirectoryEnumerator
%property (nonatomic, strong) NSString* shdwDir;

- (NSArray *)allObjects {
    NSArray* result = %orig;

    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSString* base = [self valueForKey:@"shdwDir"];
        NSMutableArray* result_filtered = [NSMutableArray new];
        
        for(id entry in result) {
            if([entry isKindOfClass:[NSURL class]]) {
                if(![_shadow isURLRestricted:entry]) {
                    [result_filtered addObject:entry];
                }
            } else if([entry isKindOfClass:[NSString class]] && base) {
                NSString* path = [base stringByAppendingPathComponent:entry];

                if(![_shadow isPathRestricted:path]) {
                    [result_filtered addObject:path];
                }
            } else {
                [result_filtered addObject:entry];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (id)nextObject {
    id result = %orig;

    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if([result isKindOfClass:[NSURL class]]) {
            do {
                if([_shadow isURLRestricted:result]) {
                    result = %orig;
                } else {
                    break;
                }
            } while(result);
        } else if([result isKindOfClass:[NSString class]]) {
            NSString* base = [self valueForUndefinedKey:@"shdwDir"];

            if(base) {
                do {
                    NSString* path = [base stringByAppendingPathComponent:result];

                    if([_shadow isPathRestricted:path]) {
                        result = %orig;
                    } else {
                        break;
                    }
                } while(result);
            }
        }
    }

    return result;
}
%end

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    BOOL result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return result;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    BOOL result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return result;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    BOOL result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return result;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    BOOL result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return result;
}

- (BOOL)isDeletableFileAtPath:(NSString *)path {
    BOOL result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return result;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
    BOOL result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return result;
}

- (NSData *)contentsAtPath:(NSString *)path {
    NSData* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (BOOL)contentsEqualAtPath:(NSString *)path1 andPath:(NSString *)path2 {
    if(([_shadow isPathRestricted:path1] || [_shadow isPathRestricted:path2]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError * _Nullable *)error {
    NSArray<NSURL *> * result = %orig;
    
    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if([_shadow isURLRestricted:url]) {
            if(error) {
                *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
            }

            return nil;
        }

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
    NSArray<NSString *> * result = %orig;
    
    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if([_shadow isPathRestricted:path]) {
            if(error) {
                *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            }

            return nil;
        }

        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSString* result_path in result) {
            if(![_shadow isPathRestricted:result_path]) {
                [result_filtered addObject:result_path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSDirectoryEnumerator<NSURL *> *)enumeratorAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask errorHandler:(BOOL (^)(NSURL *url, NSError *error))handler {
    NSDirectoryEnumerator<NSURL *> * result = %orig;
    
    if(result) {
        [result setValue:[url path] forKey:@"shdwDir"];
        HBLogDebug(@"%@: %@", @"enumeratorAtURL", url);
    }

    return result;
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path {
    NSDirectoryEnumerator<NSString *> * result = %orig;

    if(result) {
        [result setValue:path forKey:@"shdwDir"];
        HBLogDebug(@"%@: %@", @"enumeratorAtPath", path);
    }
    
    return result;
}

- (NSArray<NSString *> *)subpathsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    NSArray<NSString *> * result = %orig;
    
    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if([_shadow isPathRestricted:path]) {
            if(error) {
                *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            }

            return nil;
        }

        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSString* result_path in result) {
            NSString* abspath = result_path;

            if(![abspath isAbsolutePath]) {
                // reconstruct path
                abspath = [path stringByAppendingPathComponent:abspath];
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
    NSArray<NSString *> * result = %orig;
    
    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if([_shadow isPathRestricted:path]) {
            return nil;
        }

        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSString* result_path in result) {
            NSString* abspath = result_path;

            if(![abspath isAbsolutePath]) {
                // reconstruct path
                abspath = [path stringByAppendingPathComponent:abspath];
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
    NSString* result = %orig;
    
    if(result && [_shadow isPathRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }
        
        return nil;
    }

    return result;
}

- (NSArray<NSString *> *)componentsToDisplayForPath:(NSString *)path {
    NSArray<NSString *> * result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (NSString *)displayNameAtPath:(NSString *)path {
    NSString* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return path;
    }

    return result;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    NSDictionary<NSFileAttributeKey, id> * result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    // Make sure rootfs is marked read-only

    return result;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfFileSystemForPath:(NSString *)path error:(NSError * _Nullable *)error {
    NSDictionary<NSFileAttributeKey, id> * result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }
        
        return nil;
    }

    // Make sure rootfs is marked read-only

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
    HBLogDebug(@"%@: %@", @"changeCurrentDirectoryPath", path);

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
    NSDictionary* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (NSDictionary *)fileSystemAttributesAtPath:(NSString *)path {
    NSDictionary* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    // Make sure rootfs is marked read-only

    return result;
}

- (NSArray *)directoryContentsAtPath:(NSString *)path {
    NSArray* result = %orig;
    
    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if([_shadow isPathRestricted:path]) {
            return nil;
        }

        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSString* result_path in result) {
            NSString* abspath = result_path;

            if(![abspath isAbsolutePath]) {
                // reconstruct path
                abspath = [path stringByAppendingPathComponent:abspath];
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
    NSString* result = %orig;
    
    if(result && [_shadow isPathRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
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

void shadowhook_NSFileManager(void) {
    %init(shadowhook_NSFileManager);
}
