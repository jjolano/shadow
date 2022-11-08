#import "hooks.h"

%group shadowhook_NSFileManager
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
    // todo
    return %orig;
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path {
    // todo
    return %orig;
}

- (NSArray<NSString *> *)subpathsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
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
                NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
                [pathComponents addObjectsFromArray:[abspath pathComponents]];
                abspath = [NSString pathWithComponents:pathComponents];
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
                NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
                [pathComponents addObjectsFromArray:[abspath pathComponents]];
                abspath = [NSString pathWithComponents:pathComponents];
            }

            if(![_shadow isPathRestricted:abspath]) {
                [result_filtered addObject:result_path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

// - (void)getFileProviderServicesForItemAtURL:(NSURL *)url completionHandler:(void (^)(NSDictionary<NSFileProviderServiceName,NSFileProviderService *> *services, NSError *error))completionHandler {
//     if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
//         if(completionHandler) {
//             completionHandler(nil, nil);
//         }

//         return;
//     }

//     %orig;
// }

- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    NSString* result = %orig;
    
    if(result && [_shadow isPathRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
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
        return nil;
    }

    // Make sure rootfs is marked read-only

    return result;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfFileSystemForPath:(NSString *)path error:(NSError * _Nullable *)error {
    NSDictionary<NSFileAttributeKey, id> * result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    // Make sure rootfs is marked read-only

    return result;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectoryAtURL:(NSURL *)directoryURL toItemAtURL:(NSURL *)otherURL error:(NSError * _Nullable *)error {
    if(([_shadow isURLRestricted:directoryURL] || [_shadow isURLRestricted:otherURL]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domainMask toItemAtURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)changeCurrentDirectoryPath:(NSString *)path {
    NSString* cwd = [self currentDirectoryPath];

    if(![path isAbsolutePath]) {
        // reconstruct path
        NSMutableArray* pathComponents = [[cwd pathComponents] mutableCopy];
        [pathComponents addObjectsFromArray:[path pathComponents]];
        path = [NSString pathWithComponents:pathComponents];
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
                NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
                [pathComponents addObjectsFromArray:[abspath pathComponents]];
                abspath = [NSString pathWithComponents:pathComponents];
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
%end
%end

void shadowhook_NSFileManager(void) {
    %init(shadowhook_NSFileManager);
}
