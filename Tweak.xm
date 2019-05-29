// Shadow by jjolano

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "Includes/Shadow.h"

Shadow *_shadow = nil;

NSMutableArray *dyld_array = nil;
uint32_t dyld_array_count = 0;

struct mach_header *dyld_array_headers = NULL;
intptr_t *dyld_array_slides = NULL;

// Stable Hooks
%group hook_libc
// #include "Hooks/Stable/libc.xm"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <spawn.h>
#include <fcntl.h>
#include <errno.h>

%hookf(int, access, const char *pathname, int mode) {
    if(!pathname) {
        return %orig;
    }

    NSString *path = [NSString stringWithUTF8String:pathname];

    // workaround for tweaks not loading properly in Substrate
    if([_shadow useInjectCompatibilityMode] && [[path pathExtension] isEqualToString:@"plist"] && [path containsString:@"DynamicLibraries/"]) {
        return %orig;
    }

    if([_shadow isPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(char *, getenv, const char *name) {
    if(!name) {
        return %orig;
    }

    NSString *env = [NSString stringWithUTF8String:name];

    if([env isEqualToString:@"DYLD_INSERT_LIBRARIES"]
    || [env isEqualToString:@"_MSSafeMode"]
    || [env isEqualToString:@"_SafeMode"]) {
        return NULL;
    }

    return %orig;
}

%hookf(FILE *, fopen, const char *pathname, const char *mode) {
    if(!pathname) {
        return %orig;
    }
    
    if([_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]]) {
        errno = ENOENT;
        return NULL;
    }

    return %orig;
}

/*
%hookf(int, open, const char *pathname, int flags) {
    if(!pathname) {
        return %orig;
    }
    
    if([_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, openat, int dirfd, const char *pathname, int flags) {
    if(!pathname) {
        return %orig;
    }

    NSString *path = [NSString stringWithUTF8String:pathname];

    if(![path isAbsolutePath]) {
        // Get path of dirfd.
        char dirfdpath[PATH_MAX];
    
        if(fcntl(dirfd, F_GETPATH, dirfdpath) != -1) {
            NSString *dirfd_path = [NSString stringWithUTF8String:dirfdpath];
            path = [dirfd_path stringByAppendingPathComponent:path];
        }
    }
    
    if([_shadow isPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}
*/

%hookf(int, stat, const char *pathname, struct stat *statbuf) {
    if(!pathname) {
        return %orig;
    }

    if([_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, lstat, const char *pathname, struct stat *statbuf) {
    if(!pathname) {
        return %orig;
    }

    if([_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, statfs, const char *path, struct statfs *buf) {
    if(!path) {
        return %orig;
    }

    int ret = %orig;

    if(ret == 0) {
        NSString *pathname = [NSString stringWithUTF8String:path];

        if([_shadow isPathRestricted:pathname]) {
            errno = ENOENT;
            return -1;
        }

        pathname = [_shadow resolveLinkInPath:pathname];
        
        if(![pathname hasPrefix:@"/var"]
        && ![pathname hasPrefix:@"/private/var"]) {
            if(buf) {
                // Ensure root is marked read-only.
                buf->f_flags |= MNT_RDONLY;
                return ret;
            }
        }
    }

    return ret;
}

%hookf(int, posix_spawn, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if(!pathname) {
        return %orig;
    }

    NSString *path = [NSString stringWithUTF8String:pathname];

    if([_shadow isPathRestricted:path]) {
        return ENOSYS;
    }

    return %orig;
}

%hookf(int, posix_spawnp, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if(!pathname) {
        return %orig;
    }

    NSString *path = [NSString stringWithUTF8String:pathname];

    if([_shadow isPathRestricted:path]) {
        return ENOSYS;
    }

    return %orig;
}

%hookf(char *, realpath, const char *pathname, char *resolved_path) {
    if(!pathname) {
        return %orig;
    }

    if([_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]]) {
        errno = ENOENT;
        return NULL;
    }

    return %orig;
}

%hookf(int, symlink, const char *path1, const char *path2) {
    if(!path1 || !path2) {
        return %orig;
    }

    if([_shadow isPathRestricted:[NSString stringWithUTF8String:path2]]) {
        errno = ENOENT;
        return -1;
    }

    int ret = %orig;

    if(ret == 0) {
        // Track this symlink in Shadow
        [_shadow addLinkFromPath:[NSString stringWithUTF8String:path1] toPath:[NSString stringWithUTF8String:path2]];
    }

    return ret;
}

%hookf(int, link, const char *path1, const char *path2) {
    if(!path1 || !path2) {
        return %orig;
    }

    if([_shadow isPathRestricted:[NSString stringWithUTF8String:path2]]) {
        errno = ENOENT;
        return -1;
    }

    int ret = %orig;

    if(ret == 0) {
        // Track this symlink in Shadow
        [_shadow addLinkFromPath:[NSString stringWithUTF8String:path1] toPath:[NSString stringWithUTF8String:path2]];
    }

    return ret;
}

%hookf(int, fstatat, int dirfd, const char *pathname, struct stat *buf, int flags) {
    if(!pathname) {
        return %orig;
    }

    NSString *path = [NSString stringWithUTF8String:pathname];

    if(![path isAbsolutePath]) {
        // Get path of dirfd.
        char dirfdpath[PATH_MAX];
    
        if(fcntl(dirfd, F_GETPATH, dirfdpath) != -1) {
            NSString *dirfd_path = [NSString stringWithUTF8String:dirfdpath];
            path = [dirfd_path stringByAppendingPathComponent:path];
        }
    }
    
    if([_shadow isPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}
%end

%group hook_NSFileHandle
// #include "Hooks/Stable/NSFileHandle.xm"
%hook NSFileHandle
+ (instancetype)fileHandleForReadingAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForReadingFromURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForWritingAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForWritingToURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForUpdatingAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForUpdatingURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}
%end
%end

%group hook_NSFileManager
// #include "Hooks/Stable/NSFileManager.xm"
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
%end

%group hook_NSURL
// #include "Hooks/Stable/NSURL.xm"
%hook NSURL
- (BOOL)checkResourceIsReachableAndReturnError:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:self]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}
%end
%end

%group hook_UIApplication
// #include "Hooks/Stable/UIApplication.xm"
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}
%end
%end

%group hook_NSBundle
// #include "Hooks/Testing/NSBundle.xm"
%hook NSBundle
- (id)objectForInfoDictionaryKey:(NSString *)key {
    if([key isEqualToString:@"SignerIdentity"]) {
        return nil;
    }

    return %orig;
}
%end
%end

/*
%group hook_CoreFoundation
%hookf(CFReadStreamRef, CFReadStreamCreateWithFile, CFAllocatorRef alloc, CFURLRef fileURL) {
    NSURL *nsurl = (__bridge NSURL *)fileURL;

    if([nsurl isFileURL] && [_shadow isPathRestricted:[nsurl path] partial:NO]) {
        return NULL;
    }

    return %orig;
}

%hookf(CFWriteStreamRef, CFWriteStreamCreateWithFile, CFAllocatorRef alloc, CFURLRef fileURL) {
    NSURL *nsurl = (__bridge NSURL *)fileURL;

    if([nsurl isFileURL] && [_shadow isPathRestricted:[nsurl path] partial:NO]) {
        return NULL;
    }

    return %orig;
}

%hookf(CFURLRef, CFURLCreateFilePathURL, CFAllocatorRef allocator, CFURLRef url, CFErrorRef *error) {
    NSURL *nsurl = (__bridge NSURL *)url;

    if([nsurl isFileURL] && [_shadow isPathRestricted:[nsurl path] partial:NO]) {
        if(error) {
            *error = (__bridge CFErrorRef) [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }
        
        return NULL;
    }

    return %orig;
}

%hookf(CFURLRef, CFURLCreateFileReferenceURL, CFAllocatorRef allocator, CFURLRef url, CFErrorRef *error) {
    NSURL *nsurl = (__bridge NSURL *)url;

    if([nsurl isFileURL] && [_shadow isPathRestricted:[nsurl path] partial:NO]) {
        if(error) {
            *error = (__bridge CFErrorRef) [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }
        
        return NULL;
    }

    return %orig;
}
%end
*/

%group hook_NSUtilities
%hook UIImage
- (instancetype)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

/*
%hook NSData
- (id)initWithContentsOfMappedFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)dataWithContentsOfMappedFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }
        
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}
%end
*/

%hook NSMutableArray
- (id)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSArray
- (id)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSMutableDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSString
- (instancetype)initWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}
%end
%end

// Other Hooks
%group hook_private
// #include "Hooks/ApplePrivate.xm"
#include <unistd.h>
#include "Includes/codesign.h"

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int ret = %orig;

    if(ops == CS_OPS_STATUS && (ret & CS_PLATFORM_BINARY) && pid == getpid()) {
        // Ensure that the platform binary flag is not set.
        ret &= ~CS_PLATFORM_BINARY;
    }

    return ret;
}
%end

%group hook_debugging
// #include "Hooks/Debugging.xm"
#include <sys/sysctl.h>
#include <unistd.h>
#include <fcntl.h>

%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = %orig;

    if(ret == 0
    && name[0] == CTL_KERN
    && name[1] == KERN_PROC
    && name[2] == KERN_PROC_PID
    && name[3] == getpid()) {
        // Remove trace flag.
        if(oldp) {
            struct kinfo_proc *p = ((struct kinfo_proc *) oldp);

            if(p->kp_proc.p_flag & P_TRACED) {
                p->kp_proc.p_flag &= ~P_TRACED;
            }
        }
    }

    return ret;
}

%hookf(pid_t, getppid) {
    return 1;
}

%hookf(int, "_ptrace", int request, pid_t pid, caddr_t addr, int data) {
    if(request == 31 /* PTRACE_DENY_ATTACH */) {
        // "Success"
        return 0;
    }

    return %orig;
}
%end

%group hook_dyld_image
// #include "Hooks/dyld.xm"
#include <mach-o/dyld.h>

%hookf(uint32_t, _dyld_image_count) {
    if(dyld_array && dyld_array_count > 0) {
        return dyld_array_count;
    }

    return %orig;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    if(dyld_array && dyld_array_count > 0) {
        if(image_index >= dyld_array_count) {
            return NULL;
        }

        // return %orig((uint32_t) [dyld_array[image_index] unsignedIntValue]);
        return [dyld_array[image_index] UTF8String];
    }

    // Basic filter.
    const char *ret = %orig;

    if(ret && [_shadow isImageRestricted:[NSString stringWithUTF8String:ret]]) {
        return %orig(0);
    }

    return ret;
}

/*
%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
    if(dyld_array_headers && dyld_array_count > 0) {
        if(image_index >= dyld_array_count) {
            return NULL;
        }

        return &(dyld_array_headers[image_index]);
    }

    return %orig;
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
    if(dyld_array_slides && dyld_array_count > 0) {
        if(image_index >= dyld_array_count) {
            return 0;
        }

        return dyld_array_slides[image_index];
    }

    return %orig;
}

%hookf(void *, dlopen, const char *path, int mode) {
    void *ret = %orig;

    if(ret && path) {
        NSString *image_name = [NSString stringWithUTF8String:path];

        if((mode & RTLD_NOLOAD) == RTLD_NOLOAD) {
            if([_shadow isImageRestricted:image_name]) {
                NSLog(@"blocked dlopen: %@", image_name);
                return NULL;
            }
        } else {
            if(dyld_array && ![dyld_array containsObject:image_name] && ![_shadow isImageRestricted:image_name]) {
                [dyld_array addObject:image_name];
                dyld_array_count++;

                NSLog(@"added to dyld array: %@", image_name);
            }
        }
    }

    return ret;
}

%hookf(int, dlclose, void *handle) {
    int ret = %orig;

    if(ret == 0 && dyld_array) {
        // Regenerate dyld array.
        dyld_array = nil;
        dyld_array_count = 0;
        uint32_t orig_count = _dyld_image_count();
        dyld_array = [_shadow generateDyldNameArray];
        dyld_array_count = (uint32_t) [dyld_array count];

        NSLog(@"dlclose regenerated dyld array (%d/%d)", dyld_array_count, orig_count);
    }

    return ret;
}

%hookf(bool, dlopen_preflight, const char *path) {
    bool ret = %orig;

    if(ret) {
        NSString *image_name = [NSString stringWithUTF8String:path];

        if([_shadow isImageRestricted:image_name]) {
            NSLog(@"blocked dlopen_preflight: %@", image_name);
            return false;
        }
    }

    return ret;
}
*/
%end

%group hook_dyld_dlsym
// #include "Hooks/dlsym.xm"
#include <dlfcn.h>

%hookf(void *, dlsym, void *handle, const char *symbol) {
    if(!symbol) {
        return %orig;
    }

    NSString *sym = [NSString stringWithUTF8String:symbol];

    if([sym hasPrefix:@"MS"] /* Substrate */
    || [sym hasPrefix:@"Sub"] /* Substitute */
    || [sym hasPrefix:@"PS"] /* Substitrate */) {
        NSLog(@"blocked dlsym lookup: %@", sym);
        return NULL;
    }

    return %orig;
}
%end

%group hook_sandbox
// #include "Hooks/Sandbox.xm"
#include <stdio.h>
#include <unistd.h>

%hook NSArray
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if([_shadow isPathRestricted:path partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return NO;
    }

    return %orig;
}
%end

%hook NSDictionary
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if([_shadow isPathRestricted:path partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return NO;
    }

    return %orig;
}
%end

%hook NSData
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if([_shadow isPathRestricted:path partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToFile:(NSString *)path options:(NSDataWritingOptions)writeOptionsMask error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)useAuxiliaryFile {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSDataWritingOptions)writeOptionsMask error:(NSError * _Nullable *)error {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}
%end

%hook NSString
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)useAuxiliaryFile encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([url isFileURL] && [_shadow isPathRestricted:[url path] partial:NO]) {
        if(error) {
            *error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
        }

        return NO;
    }

    return %orig;
}
%end

%hookf(int, creat, const char *pathname, mode_t mode) {
    if(!pathname) {
        return %orig;
    }
    
    if([_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]]) {
        errno = EACCES;
        return -1;
    }

    return %orig;
}

%hookf(pid_t, fork) {
    errno = ENOSYS;
    return -1;
}

%hookf(FILE *, popen, const char *command, const char *type) {
    errno = ENOSYS;
    return NULL;
}

%hookf(int, setgid, gid_t gid) {
    // Block setgid for root.
    if(gid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}

%hookf(int, setuid, uid_t uid) {
    // Block setuid for root.
    if(uid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}

%hookf(int, setegid, gid_t gid) {
    // Block setegid for root.
    if(gid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}

%hookf(int, seteuid, uid_t uid) {
    // Block seteuid for root.
    if(uid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}

%hookf(uid_t, getuid) {
    // Return uid for mobile.
    return 501;
}

%hookf(gid_t, getgid) {
    // Return gid for mobile.
    return 501;
}

%hookf(uid_t, geteuid) {
    // Return uid for mobile.
    return 501;
}

%hookf(uid_t, getegid) {
    // Return gid for mobile.
    return 501;
}

%hookf(int, setreuid, uid_t ruid, uid_t euid) {
    // Block for root.
    if(ruid == 0 || euid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}

%hookf(int, setregid, gid_t rgid, gid_t egid) {
    // Block for root.
    if(rgid == 0 || egid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}
%end

%group hook_libraries
%hook UIDevice
+ (BOOL)isJailbroken {
    return NO;
}

- (BOOL)isJailBreak {
    return NO;
}

- (BOOL)isJailBroken {
    return NO;
}
%end

// %hook SFAntiPiracy
// + (int)isJailbroken {
// 	// Probably should not hook with a hard coded value.
// 	// This value may be changed by developers using this library.
// 	// Best to defeat the checks rather than skip them.
// 	return 4783242;
// }
// %end

%hook JailbreakDetectionVC
- (BOOL)isJailbroken {
    return NO;
}
%end

%hook DTTJailbreakDetection
+ (BOOL)isJailbroken {
    return NO;
}
%end

%hook ANSMetadata
- (BOOL)computeIsJailbroken {
    return NO;
}

- (BOOL)isJailbroken {
    return NO;
}
%end

%hook AppsFlyerUtils
+ (BOOL)isJailBreakon {
    return NO;
}
%end

%hook GBDeviceInfo
- (BOOL)isJailbroken {
    return NO;
}
%end

%hook CMARAppRestrictionsDelegate
- (bool)isDeviceNonCompliant {
    return false;
}
%end

%hook ADYSecurityChecks
+ (bool)isDeviceJailbroken {
    return false;
}
%end

%hook UBReportMetadataDevice
- (void *)is_rooted {
    return NULL;
}
%end

%hook UtilitySystem
+ (bool)isJailbreak {
    return false;
}
%end

%hook GemaltoConfiguration
+ (bool)isJailbreak {
    return false;
}
%end

%hook CPWRDeviceInfo
- (bool)isJailbroken {
    return false;
}
%end

%hook CPWRSessionInfo
- (bool)isJailbroken {
    return false;
}
%end

%hook KSSystemInfo
+ (bool)isJailbroken {
    return false;
}
%end

%hook EMDSKPPConfiguration
- (bool)jailBroken {
    return false;
}
%end

%hook EnrollParameters
- (void *)jailbroken {
    return NULL;
}
%end

%hook EMDskppConfigurationBuilder
- (bool)jailbreakStatus {
    return false;
}
%end

%hook FCRSystemMetadata
- (bool)isJailbroken {
    return false;
}
%end

%hook v_VDMap
- (bool)isJailBrokenDetectedByVOS {
    return false;
}
%end
%end

void init_path_map(Shadow *shadow) {
    // Restrict / by whitelisting
    [shadow addPath:@"/" restricted:YES hidden:NO];
    [shadow addPath:@"/.file" restricted:NO];
    [shadow addPath:@"/.ba" restricted:NO];
    [shadow addPath:@"/.mb" restricted:NO];
    [shadow addPath:@"/.HFS" restricted:NO];
    [shadow addPath:@"/.Trashes" restricted:NO];
    [shadow addPath:@"/AppleInternal" restricted:NO];
    [shadow addPath:@"/bin" restricted:YES hidden:NO];
    [shadow addPath:@"/boot" restricted:NO];
    [shadow addPath:@"/cores" restricted:NO];
    [shadow addPath:@"/Developer" restricted:NO];
    [shadow addPath:@"/lib" restricted:NO];
    [shadow addPath:@"/mnt" restricted:NO];
    [shadow addPath:@"/sbin" restricted:YES hidden:NO];

    // Restrict /Applications
    [shadow addPath:@"/Applications" restricted:NO];
    [shadow addPath:@"/Applications/Cydia.app" restricted:YES];
    [shadow addPath:@"/Applications/Sileo.app" restricted:YES];
    [shadow addPath:@"/Applications/Zebra.app" restricted:YES];

    // Restrict /dev
    [shadow addPath:@"/dev" restricted:NO];
    [shadow addPath:@"/dev/dlci." restricted:YES];
    [shadow addPath:@"/dev/vn0" restricted:YES];
    [shadow addPath:@"/dev/vn1" restricted:YES];
    [shadow addPath:@"/dev/ptmx" restricted:YES];
    [shadow addPath:@"/dev/kmem" restricted:YES];
    [shadow addPath:@"/dev/mem" restricted:YES];

    // Restrict /private
    [shadow addPath:@"/private" restricted:YES hidden:NO];
    [shadow addPath:@"/private/etc" restricted:NO];
    [shadow addPath:@"/private/system_data" restricted:NO];
    [shadow addPath:@"/private/var" restricted:NO];
    [shadow addPath:@"/private/xarts" restricted:NO];

    // Restrict /etc by whitelisting
    [shadow addPath:@"/etc" restricted:YES hidden:NO];
    [shadow addPath:@"/etc/asl" restricted:NO];
    [shadow addPath:@"/etc/asl.conf" restricted:NO];
    [shadow addPath:@"/etc/fstab" restricted:NO];
    [shadow addPath:@"/etc/group" restricted:NO];
    [shadow addPath:@"/etc/hosts" restricted:NO];
    [shadow addPath:@"/etc/hosts.equiv" restricted:NO];
    [shadow addPath:@"/etc/master.passwd" restricted:NO];
    [shadow addPath:@"/etc/networks" restricted:NO];
    [shadow addPath:@"/etc/notify.conf" restricted:NO];
    [shadow addPath:@"/etc/passwd" restricted:NO];
    [shadow addPath:@"/etc/ppp" restricted:NO];
    [shadow addPath:@"/etc/profile" restricted:NO];
    [shadow addPath:@"/etc/profile.d" restricted:NO];
    [shadow addPath:@"/etc/protocols" restricted:NO];
    [shadow addPath:@"/etc/racoon" restricted:NO];
    [shadow addPath:@"/etc/services" restricted:NO];
    [shadow addPath:@"/etc/ssl" restricted:NO];
    [shadow addPath:@"/etc/ttys" restricted:NO];
    
    // Restrict /Library by whitelisting
    [shadow addPath:@"/Library" restricted:YES hidden:NO];
    [shadow addPath:@"/Library/Application Support" restricted:YES hidden:NO];
    [shadow addPath:@"/Library/Application Support/AggregateDictionary" restricted:NO];
    [shadow addPath:@"/Library/Application Support/BTServer" restricted:NO];
    [shadow addPath:@"/Library/Audio" restricted:NO];
    [shadow addPath:@"/Library/Caches" restricted:NO];
    [shadow addPath:@"/Library/Filesystems" restricted:NO];
    [shadow addPath:@"/Library/Internet Plug-Ins" restricted:NO];
    [shadow addPath:@"/Library/Keychains" restricted:NO];
    [shadow addPath:@"/Library/LaunchAgents" restricted:NO];
    [shadow addPath:@"/Library/LaunchDaemons" restricted:YES hidden:NO];
    [shadow addPath:@"/Library/Logs" restricted:NO];
    [shadow addPath:@"/Library/Managed Preferences" restricted:NO];
    [shadow addPath:@"/Library/MobileDevice" restricted:NO];
    [shadow addPath:@"/Library/MusicUISupport" restricted:NO];
    [shadow addPath:@"/Library/Preferences" restricted:NO];
    [shadow addPath:@"/Library/Printers" restricted:NO];
    [shadow addPath:@"/Library/Ringtones" restricted:NO];
    [shadow addPath:@"/Library/Updates" restricted:NO];
    [shadow addPath:@"/Library/Wallpaper" restricted:NO];
    
    // Restrict /tmp
    [shadow addPath:@"/tmp" restricted:NO];
    [shadow addPath:@"/tmp/substrate" restricted:YES];
    [shadow addPath:@"/tmp/Substrate" restricted:YES];
    [shadow addPath:@"/tmp/cydia.log" restricted:YES];
    [shadow addPath:@"/tmp/syslog" restricted:YES];
    [shadow addPath:@"/tmp/slide.txt" restricted:YES];
    [shadow addPath:@"/tmp/amfidebilitate.out" restricted:YES];
    [shadow addPath:@"/tmp/org.coolstar" restricted:YES];
    
    // Restrict /User
    [shadow addPath:@"/User" restricted:NO];
    [shadow addPath:@"/User/." restricted:YES];
    [shadow addPath:@"/User/Containers" restricted:YES hidden:NO];
    [shadow addPath:@"/User/Containers/Data" restricted:YES hidden:NO];
    [shadow addPath:@"/User/Containers/Data/Application" restricted:NO];
    [shadow addPath:@"/User/Containers/Data/InternalDaemon" restricted:NO];
    [shadow addPath:@"/User/Containers/Data/PluginKitPlugin" restricted:NO];
    [shadow addPath:@"/User/Containers/Data/TempDir" restricted:NO];
    [shadow addPath:@"/User/Containers/Data/VPNPlugin" restricted:NO];
    [shadow addPath:@"/User/Containers/Data/XPCService" restricted:NO];
    [shadow addPath:@"/User/Containers/Shared" restricted:YES hidden:NO];
    [shadow addPath:@"/User/Containers/Shared/AppGroup" restricted:NO];
    [shadow addPath:@"/User/Documents" restricted:YES hidden:NO];
    [shadow addPath:@"/User/Documents/com.apple" restricted:NO];
    [shadow addPath:@"/User/Downloads" restricted:YES hidden:NO];
    [shadow addPath:@"/User/Downloads/com.apple" restricted:NO];
    [shadow addPath:@"/User/Library/Caches" restricted:YES hidden:NO];
    [shadow addPath:@"/User/Library/Caches/com.apple" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/.com.apple" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/AdMob" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/AccountMigrationInProgress" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/ACMigrationLock" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/BTAvrcp" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/cache" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/Checkpoint.plist" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/ckkeyrolld" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/CloudKit" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/DateFormats.plist" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/FamilyCircle" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/GameKit" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/GeoServices" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/AccountMigrationInProgress" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/MappedImageCache" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/OTACrashCopier" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/PassKit" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/rtcreportingd" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/sharedCaches" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/Snapshots" restricted:YES hidden:NO];
    [shadow addPath:@"/User/Library/Caches/Snapshots/com.apple" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/TelephonyUI" restricted:NO];
    [shadow addPath:@"/User/Library/Caches/Weather" restricted:NO];
    [shadow addPath:@"/User/Library/Cydia" restricted:YES];
    [shadow addPath:@"/User/Library/Logs/Cydia" restricted:YES];
    [shadow addPath:@"/User/Library/SBSettings" restricted:YES];
    [shadow addPath:@"/User/Library/Sileo" restricted:YES];
    [shadow addPath:@"/User/Library/Preferences" restricted:YES hidden:NO];
    [shadow addPath:@"/User/Library/Preferences/com.apple." restricted:NO];
    [shadow addPath:@"/User/Library/Preferences/.GlobalPreferences.plist" restricted:NO];
    [shadow addPath:@"/User/Library/Preferences/ckkeyrolld.plist" restricted:NO];
    [shadow addPath:@"/User/Library/Preferences/nfcd.plist" restricted:NO];
    [shadow addPath:@"/User/Library/Preferences/.GlobalPreferences.plist" restricted:NO];
    [shadow addPath:@"/User/Media" restricted:YES hidden:NO];
    [shadow addPath:@"/User/Media/AirFair" restricted:NO];
    [shadow addPath:@"/User/Media/Books" restricted:NO];
    [shadow addPath:@"/User/Media/CloudAssets" restricted:NO];
    [shadow addPath:@"/User/Media/DCIM" restricted:NO];
    [shadow addPath:@"/User/Media/Downloads" restricted:NO];
    [shadow addPath:@"/User/Media/iTunes_Control" restricted:NO];
    [shadow addPath:@"/User/Media/LoFiCloudAssets" restricted:NO];
    [shadow addPath:@"/User/Media/MediaAnalysis" restricted:NO];
    [shadow addPath:@"/User/Media/PhotoData" restricted:NO];
    [shadow addPath:@"/User/Media/Photos" restricted:NO];
    [shadow addPath:@"/User/Media/Purchases" restricted:NO];
    [shadow addPath:@"/User/Media/Radio" restricted:NO];
    [shadow addPath:@"/User/Media/Recordings" restricted:NO];

    // Restrict /usr
    [shadow addPath:@"/usr" restricted:NO];
    [shadow addPath:@"/usr/bin" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/include" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/lib" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/libexec" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/local" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/sbin" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/share/dpkg" restricted:YES];
    [shadow addPath:@"/usr/share/gnupg" restricted:YES];
    [shadow addPath:@"/usr/share/bigboss" restricted:YES];
    [shadow addPath:@"/usr/share/jailbreak" restricted:YES];
    [shadow addPath:@"/usr/share/entitlements" restricted:YES];
    [shadow addPath:@"/usr/share/tabset" restricted:YES];
    [shadow addPath:@"/usr/share/terminfo" restricted:YES];
    
    // Restrict /var
    [shadow addPath:@"/var" restricted:NO];
    [shadow addPath:@"/var/cache" restricted:YES hidden:NO];
    [shadow addPath:@"/var/lib" restricted:YES hidden:NO];
    [shadow addPath:@"/var/log" restricted:YES hidden:NO];
    [shadow addPath:@"/var/stash" restricted:YES];
    [shadow addPath:@"/var/db/stash" restricted:YES];
    [shadow addPath:@"/var/rocket_stashed" restricted:YES];
    [shadow addPath:@"/var/tweak" restricted:YES];
    [shadow addPath:@"/var/LIB" restricted:YES];
    [shadow addPath:@"/var/ulb" restricted:YES];
    [shadow addPath:@"/var/bin" restricted:YES];
    [shadow addPath:@"/var/sbin" restricted:YES];
    [shadow addPath:@"/var/profile" restricted:YES];
    [shadow addPath:@"/var/motd" restricted:YES];
    [shadow addPath:@"/var/dropbear" restricted:YES];
    [shadow addPath:@"/var/run" restricted:YES hidden:NO];
    [shadow addPath:@"/var/run/lockdown" restricted:NO];
    [shadow addPath:@"/var/run/lockdown.sock" restricted:NO];
    [shadow addPath:@"/var/run/lockdown_first_run" restricted:NO];
    [shadow addPath:@"/var/run/mDNSResponder" restricted:NO];
    [shadow addPath:@"/var/run/printd" restricted:NO];
    [shadow addPath:@"/var/run/syslog" restricted:NO];
    [shadow addPath:@"/var/run/syslog.pid" restricted:NO];
    [shadow addPath:@"/var/run/utmpx" restricted:NO];
    [shadow addPath:@"/var/run/vpncontrol.sock" restricted:NO];
    [shadow addPath:@"/var/run/asl_input" restricted:NO];
    [shadow addPath:@"/var/run/configd.pid" restricted:NO];
    [shadow addPath:@"/var/run/lockbot" restricted:NO];
    [shadow addPath:@"/var/run/pppconfd" restricted:NO];

    // Restrict /System
    [shadow addPath:@"/System" restricted:NO];
    [shadow addPath:@"/System/Library/PreferenceBundles/AppList.bundle" restricted:YES];
}

%ctor {
    NSBundle *bundle = [NSBundle mainBundle];

    if(bundle != nil) {
        NSString *executablePath = [bundle executablePath];
        NSString *bundleIdentifier = [bundle bundleIdentifier];

        // Load preferences file
        NSMutableDictionary *prefs = [[NSMutableDictionary alloc] initWithContentsOfFile:PREFS_PATH];

        if(!prefs) {
            // Create new preferences file
            prefs = [NSMutableDictionary new];
            [prefs writeToFile:PREFS_PATH atomically:YES];
        }

        // Check if Shadow is enabled
        if(prefs[@"enabled"] && ![prefs[@"enabled"] boolValue]) {
            // Shadow disabled in preferences
            return;
        }

        // Check if safe bundleIdentifier
        if(prefs[@"exclude_system_apps"]) {
            // Disable Shadow for Apple and jailbreak apps
            NSArray *excluded_bundleids = @[
                @"com.apple", // Apple apps
                @"is.workflow.my.app", // Shortcuts
                @"science.xnu.undecimus", // unc0ver
                @"com.electrateam.chimera", // Chimera
                @"org.coolstar.electra" // Electra
            ];

            for(NSString *bundle_id in excluded_bundleids) {
                if([bundleIdentifier hasPrefix:bundle_id]) {
                    return;
                }
            }
        }

        // Check if excluded bundleIdentifier
        if(prefs[@"mode"]) {
            if([prefs[@"mode"] isEqualToString:@"whitelist"]) {
                // Whitelist - disable Shadow if not enabled for this bundleIdentifier
                if(!prefs[bundleIdentifier] || ![prefs[bundleIdentifier] boolValue]) {
                    return;
                }
            } else {
                // Blacklist - disable Shadow if enabled for this bundleIdentifier
                if(prefs[bundleIdentifier] && [prefs[bundleIdentifier] boolValue]) {
                    return;
                }
            }
        }

        // Set default settings
        if(!prefs[@"dyld_hooks_enabled"]) {
            prefs[@"dyld_hooks_enabled"] = @YES;
        }

        if(!prefs[@"inject_compatibility_mode"]) {
            prefs[@"inject_compatibility_mode"] = @YES;
        }

        // System Applications
        if([executablePath hasPrefix:@"/Applications"]) {
            return;
        }

        // User (Sandboxed) Applications
        if([executablePath hasPrefix:@"/var/containers/Bundle/Application"]) {
            NSLog(@"bundleIdentifier: %@", bundleIdentifier);

            // Initialize Shadow
            _shadow = [Shadow new];

            if(!_shadow) {
                NSLog(@"failed to initialize Shadow");
                return;
            }

            // Initialize restricted path map
            init_path_map(_shadow);
            NSLog(@"initialized internal path map");

            // Initialize file map
            if(prefs[@"auto_file_map_generation_enabled"] && [prefs[@"auto_file_map_generation_enabled"] boolValue]) {
                prefs[@"file_map"] = [Shadow generateFileMap];
            }

            if(prefs[@"file_map"]) {
                [_shadow addPathsFromFileMap:prefs[@"file_map"]];

                NSLog(@"initialized file map (%lu items)", (unsigned long) [prefs[@"file_map"] count]);
            }

            // Generate filtered dyld array
            if(prefs[@"dyld_filter_enabled"] && [prefs[@"dyld_filter_enabled"] boolValue]) {
                uint32_t orig_count = _dyld_image_count();

                dyld_array = [_shadow generateDyldNameArray];
                // dyld_array_headers = [_shadow generateDyldHeaderArray];
                // dyld_array_slides = [_shadow generateDyldSlideArray];
                dyld_array_count = (uint32_t) [dyld_array count];

                NSLog(@"generated dyld array (%d/%d)", dyld_array_count, orig_count);
            }

            // Compatibility mode
            NSString *bundleIdentifier_compat = [NSString stringWithFormat:@"tweak_compat%@", bundleIdentifier];

            [_shadow setUseTweakCompatibilityMode:YES];

            if(prefs[bundleIdentifier_compat] && [prefs[bundleIdentifier_compat] boolValue]) {
                [_shadow setUseTweakCompatibilityMode:NO];
            }

            if([_shadow useTweakCompatibilityMode]) {
                NSLog(@"using tweak compatibility mode");
            }

            bundleIdentifier_compat = [NSString stringWithFormat:@"inject_compat%@", bundleIdentifier];

            [_shadow setUseInjectCompatibilityMode:YES];

            if(prefs[bundleIdentifier_compat] && [prefs[bundleIdentifier_compat] boolValue]) {
                [_shadow setUseInjectCompatibilityMode:NO];
            }

            // Disable this if we are using Substitute.
            if([[NSFileManager defaultManager] fileExistsAtPath:@"/usr/lib/libsubstitute.dylib"]) {
                [_shadow setUseInjectCompatibilityMode:NO];
            }

            if([_shadow useInjectCompatibilityMode]) {
                NSLog(@"using injection compatibility mode");
            }

            // Initialize stable hooks
            %init(hook_libc);
            %init(hook_NSFileHandle);
            %init(hook_NSFileManager);
            %init(hook_NSURL);
            %init(hook_UIApplication);
            %init(hook_NSBundle);
            %init(hook_NSUtilities);
            %init(hook_libraries);
            %init(hook_private);
            %init(hook_debugging);

            NSLog(@"hooked bypass methods");

            // Initialize other hooks
            if(prefs[@"dyld_hooks_enabled"] && [prefs[@"dyld_hooks_enabled"] boolValue]) {
                %init(hook_dyld_image);

                NSLog(@"hooked dyld image methods");
            }

            NSString *bundleIdentifier_dlfcn = [NSString stringWithFormat:@"dlfcn%@", bundleIdentifier];

            if(prefs[bundleIdentifier_dlfcn] && [prefs[bundleIdentifier_dlfcn] boolValue]) {
                %init(hook_dyld_dlsym);

                NSLog(@"hooked dynamic linker methods");
            }

            if(prefs[@"sandbox_hooks_enabled"] && [prefs[@"sandbox_hooks_enabled"] boolValue]) {
                %init(hook_sandbox);

                NSLog(@"hooked sandbox methods");
            }

            NSLog(@"ready");
        }
    }
}

%dtor {
    if(dyld_array_headers) {
        free(dyld_array_headers);
    }

    if(dyld_array_slides) {
        free(dyld_array_slides);
    }
}
