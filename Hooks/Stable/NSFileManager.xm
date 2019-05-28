%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if([_shadow isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isDeletableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}
%end
