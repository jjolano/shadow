%hook NSFileManager
- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path manager:self]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (NSDirectoryEnumerator<NSURL *> *)enumeratorAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask errorHandler:(BOOL (^)(NSURL *url, NSError *error))handler {
    if([_shadow isURLRestricted:url]) {
        return %orig([NSURL fileURLWithPath:@"file:///.file"], keys, mask, handler);
    }

    return %orig;
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return %orig(@"/.file");
    }

    return %orig;
}

- (NSArray<NSString *> *)subpathsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path manager:self]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (NSArray<NSString *> *)subpathsAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return nil;
    }

    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:srcURL]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:srcPath manager:self]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (NSArray<NSString *> *)componentsToDisplayForPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return nil;
    }

    return %orig;
}

- (NSString *)displayNameAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return path;
    }

    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path manager:self]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (NSData *)contentsAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return nil;
    }

    return %orig;
}

- (BOOL)contentsEqualAtPath:(NSString *)path1 andPath:(NSString *)path2 {
    if([_shadow isPathRestricted:path1] || [_shadow isPathRestricted:path2]) {
        return NO;
    }

    return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectoryAtURL:(NSURL *)directoryURL toItemAtURL:(NSURL *)otherURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:directoryURL] || [_shadow isURLRestricted:otherURL]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domainMask toItemAtURL:(NSURL *)otherURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:otherURL]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)changeCurrentDirectoryPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)createSymbolicLinkAtURL:(NSURL *)url withDestinationURL:(NSURL *)destURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:destURL]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    BOOL ret = %orig;

    if(ret) {
        // Track this symlink in Shadow
        [_shadow addLinkFromPath:[url path] toPath:[destURL path]];
    }

    return ret;
}

- (BOOL)createSymbolicLinkAtPath:(NSString *)path withDestinationPath:(NSString *)destPath error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:destPath]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    BOOL ret = %orig;

    if(ret) {
        // Track this symlink in Shadow
        [_shadow addLinkFromPath:path toPath:destPath];
    }

    return ret;
}

- (BOOL)linkItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:dstURL]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    BOOL ret = %orig;

    if(ret) {
        // Track this symlink in Shadow
        [_shadow addLinkFromPath:[srcURL path] toPath:[dstURL path]];
    }

    return ret;
}

- (BOOL)linkItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:dstPath]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    BOOL ret = %orig;

    if(ret) {
        // Track this symlink in Shadow
        [_shadow addLinkFromPath:srcPath toPath:dstPath];
    }

    return ret;
}

- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path manager:self]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}
%end
