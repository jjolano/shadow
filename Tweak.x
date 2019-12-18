// Shadow by jjolano

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Cephei/HBPreferences.h>
#import "Includes/Shadow.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <spawn.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include "Includes/codesign.h"

static Shadow *_shadow = nil;

static NSMutableDictionary *enum_path = nil;

static NSArray *dyld_array = nil;
static uint32_t dyld_array_count = 0;

static NSError *_error_file_not_found = nil;

static BOOL passthrough = NO;
static BOOL extra_compat = YES;

static void updateDyldArray(void) {
    dyld_array_count = 0;
    dyld_array = [_shadow generateDyldArray];
    dyld_array_count = (uint32_t) [dyld_array count];

    NSLog(@"generated dyld array (%d items)", dyld_array_count);
}

static void dyld_image_added(const struct mach_header *mh, intptr_t slide) {
    passthrough = YES;

    Dl_info info;
    int addr = dladdr(mh, &info);

    if(addr) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info.dli_fname length:strlen(info.dli_fname)];

        if([_shadow isImageRestricted:path]) {
            void *handle = dlopen(info.dli_fname, RTLD_NOLOAD);

            if(handle) {
                dlclose(handle);

                NSLog(@"unloaded %s", info.dli_fname);
            }
        }
    }

    passthrough = NO;
}

// Stable Hooks
%group hook_libc
%hookf(int, access, const char *pathname, int mode) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        // workaround for tweaks not loading properly in Substrate
        if([_shadow useInjectCompatibilityMode]) {
            if([[path pathExtension] isEqualToString:@"plist"] && [path hasPrefix:@"/Library/MobileSubstrate"]) {
                return %orig;
            }
        }

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(char *, getenv, const char *name) {
    if(name) {
        NSString *env = [NSString stringWithUTF8String:name];

        if([env isEqualToString:@"DYLD_INSERT_LIBRARIES"]
        || [env isEqualToString:@"_MSSafeMode"]
        || [env isEqualToString:@"_SafeMode"]) {
            return NULL;
        }
    }

    return %orig;
}

%hookf(FILE *, fopen, const char *pathname, const char *mode) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];
        
        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    return %orig;
}

%hookf(FILE *, freopen, const char *pathname, const char *mode, FILE *stream) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            fclose(stream);
            errno = ENOENT;
            return NULL;
        }
    }

    return %orig;
}

%hookf(int, stat, const char *pathname, struct stat *statbuf) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }

        // Maybe some filesize overrides?
        if(statbuf) {
            if([path isEqualToString:@"/bin"]) {
                int ret = %orig;

                if(ret == 0 && statbuf->st_size > 128) {
                    statbuf->st_size = 128;
                    return ret;
                }
            }
        }
    }

    return %orig;
}

%hookf(int, lstat, const char *pathname, struct stat *statbuf) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }

        // Maybe some filesize overrides?
        if(statbuf) {
            if([path isEqualToString:@"/Applications"]
            || [path isEqualToString:@"/usr/share"]
            || [path isEqualToString:@"/usr/libexec"]
            || [path isEqualToString:@"/usr/include"]
            || [path isEqualToString:@"/Library/Ringtones"]
            || [path isEqualToString:@"/Library/Wallpaper"]) {
                int ret = %orig;

                if(ret == 0 && (statbuf->st_mode & S_IFLNK) == S_IFLNK) {
                    statbuf->st_mode &= ~S_IFLNK;
                    return ret;
                }
            }

            if([path isEqualToString:@"/bin"]) {
                int ret = %orig;

                if(ret == 0 && statbuf->st_size > 128) {
                    statbuf->st_size = 128;
                    return ret;
                }
            }
        }
    }

    return %orig;
}

%hookf(int, fstatfs, int fd, struct statfs *buf) {
    int ret = %orig;

    if(ret == 0) {
        // Get path of dirfd.
        char path[PATH_MAX];

        if(fcntl(fd, F_GETPATH, path) != -1) {
            NSString *pathname = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

            if([_shadow isPathRestricted:pathname]) {
                errno = ENOENT;
                return -1;
            }

            pathname = [_shadow resolveLinkInPath:pathname];
            
            if(![pathname hasPrefix:@"/var"]
            && ![pathname hasPrefix:@"/private/var"]) {
                if(buf) {
                    // Ensure root fs is marked read-only.
                    buf->f_flags |= MNT_RDONLY | MNT_ROOTFS;
                    return ret;
                }
            } else {
                // Ensure var fs is marked NOSUID.
                buf->f_flags |= MNT_NOSUID | MNT_NODEV;
                return ret;
            }
        }
    }

    return ret;
}

%hookf(int, statfs, const char *path, struct statfs *buf) {
    int ret = %orig;

    if(ret == 0) {
        NSString *pathname = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([_shadow isPathRestricted:pathname]) {
            errno = ENOENT;
            return -1;
        }

        pathname = [_shadow resolveLinkInPath:pathname];

        if(![pathname hasPrefix:@"/var"]
        && ![pathname hasPrefix:@"/private/var"]) {
            if(buf) {
                // Ensure root fs is marked read-only.
                buf->f_flags |= MNT_RDONLY | MNT_ROOTFS;
                return ret;
            }
        } else {
            // Ensure var fs is marked NOSUID.
            buf->f_flags |= MNT_NOSUID | MNT_NODEV;
            return ret;
        }
    }

    return ret;
}

%hookf(int, posix_spawn, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            return ENOENT;
        }
    }

    return %orig;
}

%hookf(int, posix_spawnp, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            return ENOENT;
        }
    }

    return %orig;
}

%hookf(char *, realpath, const char *pathname, char *resolved_path) {
    BOOL doFree = (resolved_path != NULL);
    NSString *path = nil;

    if(pathname) {
        path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    char *ret = %orig;

    // Recheck resolved path.
    if(ret) {
        NSString *resolved_path_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:ret length:strlen(ret)];

        if([_shadow isPathRestricted:resolved_path_ns]) {
            errno = ENOENT;

            // Free resolved_path if it was allocated by libc.
            if(doFree) {
                free(ret);
            }

            return NULL;
        }

        if(strcmp(ret, pathname) != 0) {
            // Possible symbolic link? Track it in Shadow
            [_shadow addLinkFromPath:path toPath:resolved_path_ns];
        }
    }

    return ret;
}

%hookf(int, symlink, const char *path1, const char *path2) {
    NSString *path1_ns = nil;
    NSString *path2_ns = nil;

    if(path1 && path2) {
        path1_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path1 length:strlen(path1)];
        path2_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path2 length:strlen(path2)];

        if([_shadow isPathRestricted:path1_ns] || [_shadow isPathRestricted:path2_ns]) {
            errno = ENOENT;
            return -1;
        }
    }

    int ret = %orig;

    if(ret == 0) {
        // Track this symlink in Shadow
        [_shadow addLinkFromPath:path1_ns toPath:path2_ns];
    }

    return ret;
}

%hookf(int, rename, const char *oldname, const char *newname) {
    NSString *oldname_ns = nil;
    NSString *newname_ns = nil;

    if(oldname && newname) {
        oldname_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:oldname length:strlen(oldname)];
        newname_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:newname length:strlen(newname)];

        if([_shadow isPathRestricted:oldname_ns] || [_shadow isPathRestricted:newname_ns]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, remove, const char *filename) {
    if(filename) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:filename length:strlen(filename)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, unlink, const char *pathname) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, unlinkat, int dirfd, const char *pathname, int flags) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get path of dirfd.
            char dirfdpath[PATH_MAX];
        
            if(fcntl(dirfd, F_GETPATH, dirfdpath) != -1) {
                NSString *dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
                path = [dirfd_path stringByAppendingPathComponent:path];
            }
        }
        
        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, rmdir, const char *pathname) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, chdir, const char *pathname) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, fchdir, int fd) {
    char dirfdpath[PATH_MAX];

    if(fcntl(fd, F_GETPATH, dirfdpath) != -1) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, link, const char *path1, const char *path2) {
    NSString *path1_ns = nil;
    NSString *path2_ns = nil;

    if(path1 && path2) {
        path1_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path1 length:strlen(path1)];
        path2_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path2 length:strlen(path2)];

        if([_shadow isPathRestricted:path1_ns] || [_shadow isPathRestricted:path2_ns]) {
            errno = ENOENT;
            return -1;
        }
    }

    int ret = %orig;

    if(ret == 0) {
        // Track this symlink in Shadow
        [_shadow addLinkFromPath:path1_ns toPath:path2_ns];
    }

    return ret;
}

%hookf(int, fstatat, int dirfd, const char *pathname, struct stat *buf, int flags) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get path of dirfd.
            char dirfdpath[PATH_MAX];
        
            if(fcntl(dirfd, F_GETPATH, dirfdpath) != -1) {
                NSString *dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
                path = [dirfd_path stringByAppendingPathComponent:path];
            }
        }
        
        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, faccessat, int dirfd, const char *pathname, int mode, int flags) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get path of dirfd.
            char dirfdpath[PATH_MAX];
        
            if(fcntl(dirfd, F_GETPATH, dirfdpath) != -1) {
                NSString *dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
                path = [dirfd_path stringByAppendingPathComponent:path];
            }
        }
        
        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, chroot, const char *dirname) {
    if(dirname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirname length:strlen(dirname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    int ret = %orig;

    if(ret == 0) {
        [_shadow addLinkFromPath:@"/" toPath:[[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirname length:strlen(dirname)]];
    }

    return ret;
}
%end

%group hook_libc_inject
%hookf(int, fstat, int fd, struct stat *buf) {
    // Get path of dirfd.
    char fdpath[PATH_MAX];

    if(fcntl(fd, F_GETPATH, fdpath) != -1) {
        NSString *fd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:fdpath length:strlen(fdpath)];
        
        if([_shadow isPathRestricted:fd_path]) {
            errno = EBADF;
            return -1;
        }

        if(buf) {
            if([fd_path isEqualToString:@"/bin"]) {
                int ret = %orig;

                if(ret == 0 && buf->st_size > 128) {
                    buf->st_size = 128;
                    return ret;
                }
            }
        }
    }

    return %orig;
}
%end

%group hook_dlopen_inject
%hookf(void *, dlopen, const char *path, int mode) {
    if(!passthrough && path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([_shadow isImageRestricted:image_name]) {
            return NULL;
        }
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
            *error = _error_file_not_found;
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
            *error = _error_file_not_found;
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
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}
%end
%end

%group hook_NSFileManager
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

- (NSURL *)URLForDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domain appropriateForURL:(NSURL *)url create:(BOOL)shouldCreate error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (NSArray<NSURL *> *)URLsForDirectory:(NSSearchPathDirectory)directory inDomains:(NSSearchPathDomainMask)domainMask {
    NSArray *ret = %orig;

    if(ret) {
        NSMutableArray *toRemove = [NSMutableArray new];
        NSMutableArray *filtered = [ret mutableCopy];

        for(NSURL *url in filtered) {
            if([_shadow isURLRestricted:url manager:self]) {
                [toRemove addObject:url];
            }
        }

        [filtered removeObjectsInArray:toRemove];
        ret = [filtered copy];
    }

    return ret;
}

- (BOOL)isUbiquitousItemAtURL:(NSURL *)url {
    if([_shadow isURLRestricted:url manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)setUbiquitous:(BOOL)flag itemAtURL:(NSURL *)url destinationURL:(NSURL *)destinationURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)replaceItemAtURL:(NSURL *)originalItemURL withItemAtURL:(NSURL *)newItemURL backupItemName:(NSString *)backupItemName options:(NSFileManagerItemReplacementOptions)options resultingItemURL:(NSURL * _Nullable *)resultingURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:originalItemURL manager:self] || [_shadow isURLRestricted:newItemURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    // Filter array.
    NSMutableArray *filtered_ret = nil;
    NSArray *ret = %orig;

    if(ret) {
        filtered_ret = [NSMutableArray new];

        for(NSURL *ret_url in ret) {
            if(![_shadow isURLRestricted:ret_url manager:self]) {
                [filtered_ret addObject:ret_url];
            }
        }
    }

    return ret ? [filtered_ret copy] : ret;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    // Filter array.
    NSMutableArray *filtered_ret = nil;
    NSArray *ret = %orig;

    if(ret) {
        filtered_ret = [NSMutableArray new];

        for(NSString *ret_path in ret) {
            // Ensure absolute path for path.
            if(![_shadow isPathRestricted:[path stringByAppendingPathComponent:ret_path] manager:self]) {
                [filtered_ret addObject:ret_path];
            }
        }
    }

    return ret ? [filtered_ret copy] : ret;
}

- (NSDirectoryEnumerator<NSURL *> *)enumeratorAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask errorHandler:(BOOL (^)(NSURL *url, NSError *error))handler {
    if([_shadow isURLRestricted:url manager:self]) {
        return %orig([NSURL fileURLWithPath:@"/.file"], keys, mask, handler);
    }

    return %orig;
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return %orig(@"/.file");
    }

    NSDirectoryEnumerator *ret = %orig;

    if(ret && enum_path) {
        // Store this path.
        [enum_path setObject:path forKey:[NSValue valueWithNonretainedObject:ret]];
    }

    return ret;
}

- (NSArray<NSString *> *)subpathsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    // Filter array.
    NSMutableArray *filtered_ret = nil;
    NSArray *ret = %orig;

    if(ret) {
        filtered_ret = [NSMutableArray new];

        for(NSString *ret_path in ret) {
            // Ensure absolute path for path.
            if(![_shadow isPathRestricted:[path stringByAppendingPathComponent:ret_path] manager:self]) {
                [filtered_ret addObject:ret_path];
            }
        }
    }

    return ret ? [filtered_ret copy] : ret;
}

- (NSArray<NSString *> *)subpathsAtPath:(NSString *)path {
    if([_shadow isPathRestricted:path manager:self]) {
        return nil;
    }

    // Filter array.
    NSMutableArray *filtered_ret = nil;
    NSArray *ret = %orig;

    if(ret) {
        filtered_ret = [NSMutableArray new];

        for(NSString *ret_path in ret) {
            // Ensure absolute path for path.
            if(![_shadow isPathRestricted:[path stringByAppendingPathComponent:ret_path] manager:self]) {
                [filtered_ret addObject:ret_path];
            }
        }
    }

    return ret ? [filtered_ret copy] : ret;
}

- (BOOL)copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:srcURL manager:self] || [_shadow isURLRestricted:dstURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:srcPath manager:self] || [_shadow isPathRestricted:dstPath manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)moveItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:srcURL manager:self] || [_shadow isURLRestricted:dstURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:srcPath manager:self] || [_shadow isPathRestricted:dstPath manager:self]) {
        if(error) {
            *error = _error_file_not_found;
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
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfFileSystemForPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (BOOL)setAttributes:(NSDictionary<NSFileAttributeKey, id> *)attributes ofItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
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
    if([_shadow isURLRestricted:directoryURL manager:self] || [_shadow isURLRestricted:otherURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domainMask toItemAtURL:(NSURL *)otherURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:otherURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
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
    if([_shadow isURLRestricted:url manager:self] || [_shadow isURLRestricted:destURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
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
    if([_shadow isPathRestricted:path] || [_shadow isPathRestricted:destPath]) {
        if(error) {
            *error = _error_file_not_found;
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
    if([_shadow isURLRestricted:srcURL manager:self] || [_shadow isURLRestricted:dstURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
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
    if([_shadow isPathRestricted:srcPath manager:self] || [_shadow isPathRestricted:dstPath manager:self]) {
        if(error) {
            *error = _error_file_not_found;
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
            *error = _error_file_not_found;
        }

        return nil;
    }

    NSString *ret = %orig;

    if(ret) {
        // Track this symlink in Shadow
        [_shadow addLinkFromPath:path toPath:ret];
    }

    return ret;
}
%end
%end

%group hook_NSEnumerator
%hook NSDirectoryEnumerator
- (id)nextObject {
    id ret = nil;
    NSString *parent = nil;

    if(enum_path) {
        parent = enum_path[[NSValue valueWithNonretainedObject:self]];
    }

    while((ret = %orig)) {
        if([ret isKindOfClass:[NSURL class]]) {
            if(![_shadow isURLRestricted:ret]) {
                break;
            }
        }

        if([ret isKindOfClass:[NSString class]]) {
            if(parent) {
                NSString *path = [parent stringByAppendingPathComponent:ret];

                if(![_shadow isPathRestricted:path]) {
                    break;
                }
            } else {
                break;
            }
        }
    }

    return ret;
}
%end
%end

%group hook_NSFileWrapper
%hook NSFileWrapper
- (instancetype)initWithURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if([_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = _error_file_not_found;
        }

        return 0;
    }

    return %orig;
}

- (instancetype)initSymbolicLinkWithDestinationURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return 0;
    }

    return %orig;
}

- (BOOL)matchesContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}

- (BOOL)readFromURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if([_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSFileWrapperWritingOptions)options originalContentsURL:(NSURL *)originalContentsURL error:(NSError * _Nullable *)outError {
    if([_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}
%end
%end

%group hook_NSFileVersion
%hook NSFileVersion
+ (NSFileVersion *)currentVersionOfItemAtURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSArray<NSFileVersion *> *)otherVersionsOfItemAtURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSFileVersion *)versionOfItemAtURL:(NSURL *)url forPersistentIdentifier:(id)persistentIdentifier {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSURL *)temporaryDirectoryURLForNewVersionOfItemAtURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSFileVersion *)addVersionOfItemAtURL:(NSURL *)url withContentsOfURL:(NSURL *)contentsURL options:(NSFileVersionAddingOptions)options error:(NSError * _Nullable *)outError {
    if([_shadow isURLRestricted:url] || [_shadow isURLRestricted:contentsURL]) {
        if(outError) {
            *outError = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (NSArray<NSFileVersion *> *)unresolvedConflictVersionsOfItemAtURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURL *)replaceItemAtURL:(NSURL *)url options:(NSFileVersionReplacingOptions)options error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (BOOL)removeOtherVersionsOfItemAtURL:(NSURL *)url error:(NSError * _Nullable *)outError {
    if([_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

+ (void)getNonlocalVersionsOfItemAtURL:(NSURL *)url completionHandler:(void (^)(NSArray<NSFileVersion *> *nonlocalFileVersions, NSError *error))completionHandler {
    if([_shadow isURLRestricted:url]) {
        if(completionHandler) {
            completionHandler(nil, _error_file_not_found);
        }

        return;
    }

    %orig;
}
%end
%end

%group hook_NSURL
%hook NSURL
- (BOOL)checkResourceIsReachableAndReturnError:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (NSURL *)fileReferenceURL {
    if([_shadow isURLRestricted:self]) {
        return nil;
    }

    return %orig;
}
%end
%end

%group hook_UIApplication
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}
/*
- (BOOL)openURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}

- (void)openURL:(NSURL *)url options:(NSDictionary<id, id> *)options completionHandler:(void (^)(BOOL success))completion {
    if([_shadow isURLRestricted:url]) {
        completion(NO);
        return;
    }

    %orig;
}
*/
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

+ (instancetype)bundleWithURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)bundleWithPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }
    
    return %orig;
}

- (instancetype)initWithPath:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}
%end
%end
/*
%group hook_CoreFoundation
%hookf(CFArrayRef, CFBundleGetAllBundles) {
    CFArrayRef cfbundles = %orig;
    CFIndex cfcount = CFArrayGetCount(cfbundles);

    NSMutableArray *filter = [NSMutableArray new];
    NSMutableArray *bundles = [NSMutableArray arrayWithArray:(__bridge NSArray *) cfbundles];

    // Filter return value.
    int i;
    for(i = 0; i < cfcount; i++) {
        CFBundleRef cfbundle = (CFBundleRef) CFArrayGetValueAtIndex(cfbundles, i);
        CFURLRef cfbundle_cfurl = CFBundleCopyExecutableURL(cfbundle);

        if(cfbundle_cfurl) {
            NSURL *bundle_url = (__bridge NSURL *) cfbundle_cfurl;

            if([_shadow isURLRestricted:bundle_url]) {
                continue;
            }
        }

        [filter addObject:bundles[i]];
    }

    return (__bridge CFArrayRef) [filter copy];
}

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
            *error = (__bridge CFErrorRef) _error_file_not_found;
        }
        
        return NULL;
    }

    return %orig;
}

%hookf(CFURLRef, CFURLCreateFileReferenceURL, CFAllocatorRef allocator, CFURLRef url, CFErrorRef *error) {
    NSURL *nsurl = (__bridge NSURL *)url;

    if([nsurl isFileURL] && [_shadow isPathRestricted:[nsurl path] partial:NO]) {
        if(error) {
            *error = (__bridge CFErrorRef) _error_file_not_found;
        }
        
        return NULL;
    }

    return %orig;
}
%end
*/
%group hook_NSUtilities
%hook NSProcessInfo
- (BOOL)isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion)version {
    // Override version checks that use this method.
    return YES;
}
%end

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

%hook NSMutableArray
- (id)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url partial:NO]) {
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
    if([_shadow isURLRestricted:url partial:NO]) {
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
    if([_shadow isURLRestricted:url partial:NO]) {
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
    if([_shadow isURLRestricted:url partial:NO]) {
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
    if([_shadow isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
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
    if([_shadow isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSString
- (instancetype)initWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (NSUInteger)completePathIntoString:(NSString * _Nullable *)outputName caseSensitive:(BOOL)flag matchesIntoArray:(NSArray<NSString *> * _Nullable *)outputArray filterTypes:(NSArray<NSString *> *)filterTypes {
    if([_shadow isPathRestricted:self]) {
        *outputName = nil;
        *outputArray = nil;

        return 0;
    }

    return %orig;
}
%end
%end

// Other Hooks
%group hook_private
%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int ret = %orig;

    if(ops == CS_OPS_STATUS && (ret & CS_PLATFORM_BINARY) == CS_PLATFORM_BINARY && pid == getpid()) {
        // Ensure that the platform binary flag is not set.
        ret &= ~CS_PLATFORM_BINARY;
    }

    return ret;
}
%end

%group hook_debugging
%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if(namelen == 4
    && name[0] == CTL_KERN
    && name[1] == KERN_PROC
    && name[2] == KERN_PROC_ALL
    && name[3] == 0) {
        // Running process check.
        *oldlenp = 0;
        return 0;
    }

    int ret = %orig;

    if(ret == 0
    && name[0] == CTL_KERN
    && name[1] == KERN_PROC
    && name[2] == KERN_PROC_PID
    && name[3] == getpid()) {
        // Remove trace flag.
        if(oldp) {
            struct kinfo_proc *p = ((struct kinfo_proc *) oldp);

            if((p->kp_proc.p_flag & P_TRACED) == P_TRACED) {
                p->kp_proc.p_flag &= ~P_TRACED;
            }
        }
    }

    return ret;
}

%hookf(pid_t, getppid) {
    return 1;
}

/*
%hookf(int, "_ptrace", int request, pid_t pid, caddr_t addr, int data) {
    // PTRACE_DENY_ATTACH = 31
    if(request == 31) {
        return 0;
    }

    return %orig;
}
*/
%end

%group hook_dyld_image
%hookf(uint32_t, _dyld_image_count) {
    if(dyld_array_count > 0) {
        return dyld_array_count;
    }

    return %orig;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    if(dyld_array_count > 0) {
        // if(image_index == 0) {
        //     updateDyldArray();
        // }

        if(image_index >= dyld_array_count) {
            return NULL;
        }

        image_index = (uint32_t) [dyld_array[image_index] unsignedIntValue];
    }

    // Basic filter.
    const char *ret = %orig(image_index);

    if(ret) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:ret length:strlen(ret)];

        if([_shadow isImageRestricted:image_name]) {
            return "/.file";
        }
    }

    return ret;
}
/*
%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
    static struct mach_header ret;

    if(dyld_array_count > 0) {
        if(image_index >= dyld_array_count) {
            return NULL;
        }

        // image_index = (uint32_t) [dyld_array[image_index] unsignedIntValue];
    }

    ret = *(%orig(image_index));

    return &ret;
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
    if(dyld_array_count > 0) {
        if(image_index >= dyld_array_count) {
            return 0;
        }

        // image_index = (uint32_t) [dyld_array[image_index] unsignedIntValue];
    }

    return %orig(image_index);
}
*/
%hookf(bool, dlopen_preflight, const char *path) {
    if(path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([_shadow isImageRestricted:image_name]) {
            NSLog(@"blocked dlopen_preflight: %@", image_name);
            return false;
        }
    }

    return %orig;
}
%end

%group hook_dyld_dlsym
%hookf(void *, dlsym, void *handle, const char *symbol) {
    if(symbol) {
        NSString *sym = [NSString stringWithUTF8String:symbol];

        if([sym hasPrefix:@"MS"]
        || [sym hasPrefix:@"Sub"]
        || [sym hasPrefix:@"PS"]
        || [sym hasPrefix:@"rocketbootstrap"]
        || [sym hasPrefix:@"LM"]
        || [sym hasPrefix:@"substitute_"]
        || [sym hasPrefix:@"_logos"]) {
            NSLog(@"blocked dlsym lookup: %@", sym);
            return NULL;
        }
    }

    return %orig;
}
%end

%group hook_sandbox
%hook NSArray
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if([_shadow isPathRestricted:path partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if([_shadow isURLRestricted:url partial:NO]) {
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
    if([_shadow isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if([_shadow isURLRestricted:url partial:NO]) {
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
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)useAuxiliaryFile {
    if([_shadow isURLRestricted:url partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSDataWritingOptions)writeOptionsMask error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
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
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)useAuxiliaryFile encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}
%end

%hook NSFileManager
- (BOOL)createDirectoryAtURL:(NSURL *)url withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary<NSFileAttributeKey, id> *)attr {
    if([_shadow isPathRestricted:path partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtURL:(NSURL *)URL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:URL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)trashItemAtURL:(NSURL *)url resultingItemURL:(NSURL * _Nullable *)outResultingURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}
%end

%hookf(int, creat, const char *pathname, mode_t mode) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = EACCES;
            return -1;
        }
    }

    return %orig;
}

%hookf(pid_t, vfork) {
    errno = ENOSYS;
    return -1;
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

%group hook_runtime
%hookf(const char * _Nonnull *, objc_copyImageNames, unsigned int *outCount) {
    const char * _Nonnull *ret = %orig;

    if(ret && outCount) {
        NSLog(@"copyImageNames: %d", *outCount);

        const char *exec_name = _dyld_get_image_name(0);
        unsigned int i;

        for(i = 0; i < *outCount; i++) {
            if(strcmp(ret[i], exec_name) == 0) {
                // Stop after app executable.
                *outCount = (i + 1);
                break;
            }
        }
    }

    return ret;
}

%hookf(const char * _Nonnull *, objc_copyClassNamesForImage, const char *image, unsigned int *outCount) {
    if(image) {
        NSLog(@"copyClassNamesForImage: %s", image);

        NSString *image_ns = [NSString stringWithUTF8String:image];

        if([_shadow isImageRestricted:image_ns]) {
            *outCount = 0;
            return NULL;
        }
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

- (bool)isDFPHookedDetecedByVOS {
    return false;
}

- (bool)isCodeInjectionDetectedByVOS {
    return false;
}

- (bool)isDebuggerCheckDetectedByVOS {
    return false;
}

- (bool)isAppSignerCheckDetectedByVOS {
    return false;
}

- (bool)v_checkAModified {
    return false;
}
%end

%hook SDMUtils
- (BOOL)isJailBroken {
    return NO;
}
%end

%hook OneSignalJailbreakDetection
+ (BOOL)isJailbroken {
    return NO;
}
%end

%hook DigiPassHandler
- (BOOL)rootedDeviceTestResult {
    return NO;
}
%end

%hook AWMyDeviceGeneralInfo
- (bool)isCompliant {
    return true;
}
%end
%end

%group hook_experimental
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
    if([_shadow isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
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
    if([_shadow isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([_shadow isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}
%end

%hookf(int32_t, NSVersionOfRunTimeLibrary, const char *libraryName) {
    if(libraryName) {
        NSString *name = [NSString stringWithUTF8String:libraryName];

        if([_shadow isImageRestricted:name]) {
            return -1;
        }
    }
    
    return %orig;
}

%hookf(int32_t, NSVersionOfLinkTimeLibrary, const char *libraryName) {
    if(libraryName) {
        NSString *name = [NSString stringWithUTF8String:libraryName];

        if([_shadow isImageRestricted:name]) {
            return -1;
        }
    }
    
    return %orig;
}
%end

void init_path_map(Shadow *shadow) {
    // Restrict / by whitelisting
    [shadow addPath:@"/" restricted:YES hidden:NO];
    [shadow addPath:@"/.file" restricted:NO];
    [shadow addPath:@"/.ba" restricted:NO];
    [shadow addPath:@"/.mb" restricted:NO];
    [shadow addPath:@"/.HFS" restricted:NO];
    [shadow addPath:@"/.Trashes" restricted:NO];
    // [shadow addPath:@"/AppleInternal" restricted:NO];
    [shadow addPath:@"/cores" restricted:NO];
    [shadow addPath:@"/Developer" restricted:NO];
    [shadow addPath:@"/lib" restricted:NO];
    [shadow addPath:@"/mnt" restricted:NO];

    // Restrict /bin by whitelisting
    [shadow addPath:@"/bin" restricted:YES hidden:NO];
    [shadow addPath:@"/bin/df" restricted:NO];
    [shadow addPath:@"/bin/ps" restricted:NO];

    // Restrict /sbin by whitelisting
    [shadow addPath:@"/sbin" restricted:YES hidden:NO];
    [shadow addPath:@"/sbin/fsck" restricted:NO];
    [shadow addPath:@"/sbin/launchd" restricted:NO];
    [shadow addPath:@"/sbin/mount" restricted:NO];
    [shadow addPath:@"/sbin/pfctl" restricted:NO];

    // Restrict /Applications by whitelisting
    [shadow addPath:@"/Applications" restricted:YES hidden:NO];
    [shadow addPath:@"/Applications/AXUIViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/AccountAuthenticationDialog.app" restricted:NO];
    [shadow addPath:@"/Applications/ActivityMessagesApp.app" restricted:NO];
    [shadow addPath:@"/Applications/AdPlatformsDiagnostics.app" restricted:NO];
    [shadow addPath:@"/Applications/AppStore.app" restricted:NO];
    [shadow addPath:@"/Applications/AskPermissionUI.app" restricted:NO];
    [shadow addPath:@"/Applications/BusinessExtensionsWrapper.app" restricted:NO];
    [shadow addPath:@"/Applications/CTCarrierSpaceAuth.app" restricted:NO];
    [shadow addPath:@"/Applications/Camera.app" restricted:NO];
    [shadow addPath:@"/Applications/CheckerBoard.app" restricted:NO];
    [shadow addPath:@"/Applications/CompassCalibrationViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/ContinuityCamera.app" restricted:NO];
    [shadow addPath:@"/Applications/CoreAuthUI.app" restricted:NO];
    [shadow addPath:@"/Applications/DDActionsService.app" restricted:NO];
    [shadow addPath:@"/Applications/DNDBuddy.app" restricted:NO];
    [shadow addPath:@"/Applications/DataActivation.app" restricted:NO];
    [shadow addPath:@"/Applications/DemoApp.app" restricted:NO];
    [shadow addPath:@"/Applications/Diagnostics.app" restricted:NO];
    [shadow addPath:@"/Applications/DiagnosticsService.app" restricted:NO];
    [shadow addPath:@"/Applications/FTMInternal-4.app" restricted:NO];
    [shadow addPath:@"/Applications/Family.app" restricted:NO];
    [shadow addPath:@"/Applications/Feedback Assistant iOS.app" restricted:NO];
    [shadow addPath:@"/Applications/FieldTest.app" restricted:NO];
    [shadow addPath:@"/Applications/FindMyiPhone.app" restricted:NO];
    [shadow addPath:@"/Applications/FunCameraShapes.app" restricted:NO];
    [shadow addPath:@"/Applications/FunCameraText.app" restricted:NO];
    [shadow addPath:@"/Applications/GameCenterUIService.app" restricted:NO];
    [shadow addPath:@"/Applications/HashtagImages.app" restricted:NO];
    [shadow addPath:@"/Applications/Health.app" restricted:NO];
    [shadow addPath:@"/Applications/HealthPrivacyService.app" restricted:NO];
    [shadow addPath:@"/Applications/HomeUIService.app" restricted:NO];
    [shadow addPath:@"/Applications/InCallService.app" restricted:NO];
    [shadow addPath:@"/Applications/Magnifier.app" restricted:NO];
    [shadow addPath:@"/Applications/MailCompositionService.app" restricted:NO];
    [shadow addPath:@"/Applications/MessagesViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/MobilePhone.app" restricted:NO];
    [shadow addPath:@"/Applications/MobileSMS.app" restricted:NO];
    [shadow addPath:@"/Applications/MobileSafari.app" restricted:NO];
    [shadow addPath:@"/Applications/MobileSlideShow.app" restricted:NO];
    [shadow addPath:@"/Applications/MobileTimer.app" restricted:NO];
    [shadow addPath:@"/Applications/MusicUIService.app" restricted:NO];
    [shadow addPath:@"/Applications/Passbook.app" restricted:NO];
    [shadow addPath:@"/Applications/PassbookUIService.app" restricted:NO];
    [shadow addPath:@"/Applications/PhotosViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/PreBoard.app" restricted:NO];
    [shadow addPath:@"/Applications/Preferences.app" restricted:NO];
    [shadow addPath:@"/Applications/Print Center.app" restricted:NO];
    [shadow addPath:@"/Applications/SIMSetupUIService.app" restricted:NO];
    [shadow addPath:@"/Applications/SLGoogleAuth.app" restricted:NO];
    [shadow addPath:@"/Applications/SLYahooAuth.app" restricted:NO];
    [shadow addPath:@"/Applications/SafariViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/ScreenSharingViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/ScreenshotServicesService.app" restricted:NO];
    [shadow addPath:@"/Applications/Setup.app" restricted:NO];
    [shadow addPath:@"/Applications/SharedWebCredentialViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/SharingViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/SiriViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/SoftwareUpdateUIService.app" restricted:NO];
    [shadow addPath:@"/Applications/StoreDemoViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/StoreKitUIService.app" restricted:NO];
    [shadow addPath:@"/Applications/TrustMe.app" restricted:NO];
    [shadow addPath:@"/Applications/Utilities" restricted:NO];
    [shadow addPath:@"/Applications/VideoSubscriberAccountViewService.app" restricted:NO];
    [shadow addPath:@"/Applications/WLAccessService.app" restricted:NO];
    [shadow addPath:@"/Applications/Web.app" restricted:NO];
    [shadow addPath:@"/Applications/WebApp1.app" restricted:NO];
    [shadow addPath:@"/Applications/WebContentAnalysisUI.app" restricted:NO];
    [shadow addPath:@"/Applications/WebSheet.app" restricted:NO];
    [shadow addPath:@"/Applications/iAdOptOut.app" restricted:NO];
    [shadow addPath:@"/Applications/iCloud.app" restricted:NO];

    // Restrict /dev
    [shadow addPath:@"/dev" restricted:NO];
    [shadow addPath:@"/dev/dlci." restricted:YES];
    [shadow addPath:@"/dev/vn0" restricted:YES];
    [shadow addPath:@"/dev/vn1" restricted:YES];
    [shadow addPath:@"/dev/kmem" restricted:YES];
    [shadow addPath:@"/dev/mem" restricted:YES];

    // Restrict /private by whitelisting
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
    [shadow addPath:@"/etc/protocols" restricted:NO];
    [shadow addPath:@"/etc/racoon" restricted:NO];
    [shadow addPath:@"/etc/services" restricted:NO];
    [shadow addPath:@"/etc/ttys" restricted:NO];
    
    // Restrict /Library by whitelisting
    [shadow addPath:@"/Library" restricted:YES hidden:NO];
    [shadow addPath:@"/Library/Application Support" restricted:YES hidden:NO];
    [shadow addPath:@"/Library/Application Support/AggregateDictionary" restricted:NO];
    [shadow addPath:@"/Library/Application Support/BTServer" restricted:NO];
    [shadow addPath:@"/Library/Audio" restricted:NO];
    [shadow addPath:@"/Library/Caches" restricted:NO];
    [shadow addPath:@"/Library/Caches/cy-" restricted:YES];
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
    [shadow addPath:@"/tmp" restricted:YES hidden:NO];
    [shadow addPath:@"/tmp/com.apple" restricted:NO];
    [shadow addPath:@"/tmp/substrate" restricted:YES];
    [shadow addPath:@"/tmp/Substrate" restricted:YES];
    [shadow addPath:@"/tmp/cydia.log" restricted:YES];
    [shadow addPath:@"/tmp/syslog" restricted:YES];
    [shadow addPath:@"/tmp/slide.txt" restricted:YES];
    [shadow addPath:@"/tmp/amfidebilitate.out" restricted:YES];
    [shadow addPath:@"/tmp/org.coolstar" restricted:YES];
    [shadow addPath:@"/tmp/amfid_payload.alive" restricted:YES];
    [shadow addPath:@"/tmp/jailbreakd.pid" restricted:YES];

    // Restrict /var by whitelisting
    [shadow addPath:@"/var" restricted:YES hidden:NO];
    [shadow addPath:@"/var/.DocumentRevisions" restricted:NO];
    [shadow addPath:@"/var/.fseventsd" restricted:NO];
    [shadow addPath:@"/var/.overprovisioning_file" restricted:NO];
    [shadow addPath:@"/var/audit" restricted:NO];
    [shadow addPath:@"/var/backups" restricted:NO];
    [shadow addPath:@"/var/buddy" restricted:NO];
    [shadow addPath:@"/var/containers" restricted:NO];
    [shadow addPath:@"/var/containers/Bundle" restricted:YES hidden:NO];
    [shadow addPath:@"/var/containers/Bundle/Application" restricted:NO];
    [shadow addPath:@"/var/containers/Bundle/Framework" restricted:NO];
    [shadow addPath:@"/var/containers/Bundle/PluginKitPlugin" restricted:NO];
    [shadow addPath:@"/var/containers/Bundle/VPNPlugin" restricted:NO];
    [shadow addPath:@"/var/cores" restricted:NO];
    [shadow addPath:@"/var/db" restricted:NO];
    [shadow addPath:@"/var/db/stash" restricted:YES];
    [shadow addPath:@"/var/ea" restricted:NO];
    [shadow addPath:@"/var/empty" restricted:NO];
    [shadow addPath:@"/var/folders" restricted:NO];
    [shadow addPath:@"/var/hardware" restricted:NO];
    [shadow addPath:@"/var/installd" restricted:NO];
    [shadow addPath:@"/var/internal" restricted:NO];
    [shadow addPath:@"/var/keybags" restricted:NO];
    [shadow addPath:@"/var/Keychains" restricted:NO];
    [shadow addPath:@"/var/lib" restricted:YES hidden:NO];
    [shadow addPath:@"/var/local" restricted:NO];
    [shadow addPath:@"/var/lock" restricted:NO];
    [shadow addPath:@"/var/log" restricted:YES hidden:NO];
    [shadow addPath:@"/var/log/asl" restricted:NO];
    [shadow addPath:@"/var/log/com.apple.xpc.launchd" restricted:NO];
    [shadow addPath:@"/var/log/corecaptured.log" restricted:NO];
    [shadow addPath:@"/var/log/ppp" restricted:NO];
    [shadow addPath:@"/var/log/ppp.log" restricted:NO];
    [shadow addPath:@"/var/log/racoon.log" restricted:NO];
    [shadow addPath:@"/var/log/sa" restricted:NO];
    [shadow addPath:@"/var/logs" restricted:NO];
    [shadow addPath:@"/var/Managed Preferences" restricted:NO];
    [shadow addPath:@"/var/MobileAsset" restricted:NO];
    [shadow addPath:@"/var/MobileDevice" restricted:NO];
    [shadow addPath:@"/var/MobileSoftwareUpdate" restricted:NO];
    [shadow addPath:@"/var/msgs" restricted:NO];
    [shadow addPath:@"/var/networkd" restricted:NO];
    [shadow addPath:@"/var/preferences" restricted:NO];
    [shadow addPath:@"/var/root" restricted:NO];
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
    [shadow addPath:@"/var/run/fudinit" restricted:NO];
    [shadow addPath:@"/var/spool" restricted:NO];
    [shadow addPath:@"/var/staged_system_apps" restricted:NO];
    [shadow addPath:@"/var/tmp" restricted:NO];
    [shadow addPath:@"/var/vm" restricted:NO];
    [shadow addPath:@"/var/wireless" restricted:NO];
    
    // Restrict /var/mobile by whitelisting
    [shadow addPath:@"/var/mobile" restricted:YES hidden:NO];
    [shadow addPath:@"/var/mobile/Applications" restricted:NO];
    [shadow addPath:@"/var/mobile/Containers" restricted:YES hidden:NO];
    [shadow addPath:@"/var/mobile/Containers/Data" restricted:YES hidden:NO];
    [shadow addPath:@"/var/mobile/Containers/Data/Application" restricted:NO];
    [shadow addPath:@"/var/mobile/Containers/Data/InternalDaemon" restricted:NO];
    [shadow addPath:@"/var/mobile/Containers/Data/PluginKitPlugin" restricted:NO];
    [shadow addPath:@"/var/mobile/Containers/Data/TempDir" restricted:NO];
    [shadow addPath:@"/var/mobile/Containers/Data/VPNPlugin" restricted:NO];
    [shadow addPath:@"/var/mobile/Containers/Data/XPCService" restricted:NO];
    [shadow addPath:@"/var/mobile/Containers/Shared" restricted:YES hidden:NO];
    [shadow addPath:@"/var/mobile/Containers/Shared/AppGroup" restricted:NO];
    [shadow addPath:@"/var/mobile/Documents" restricted:NO];
    [shadow addPath:@"/var/mobile/Downloads" restricted:NO];
    [shadow addPath:@"/var/mobile/Library" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches" restricted:YES hidden:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/com.apple" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/.com.apple" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/AdMob" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/AccountMigrationInProgress" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/ACMigrationLock" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/BTAvrcp" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/cache" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/Checkpoint.plist" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/ckkeyrolld" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/CloudKit" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/DateFormats.plist" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/FamilyCircle" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/GameKit" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/GeoServices" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/AccountMigrationInProgress" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/MappedImageCache" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/OTACrashCopier" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/PassKit" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/rtcreportingd" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/sharedCaches" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/Snapshots" restricted:YES hidden:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/Snapshots/com.apple" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/TelephonyUI" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Caches/Weather" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/ControlCenter" restricted:YES hidden:NO];
    [shadow addPath:@"/var/mobile/Library/ControlCenter/ModuleConfiguration.plist" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Cydia" restricted:YES];
    [shadow addPath:@"/var/mobile/Library/Logs/Cydia" restricted:YES];
    [shadow addPath:@"/var/mobile/Library/SBSettings" restricted:YES];
    [shadow addPath:@"/var/mobile/Library/Sileo" restricted:YES];
    [shadow addPath:@"/var/mobile/Library/Preferences" restricted:YES hidden:NO];
    [shadow addPath:@"/var/mobile/Library/Preferences/com.apple." restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Preferences/.GlobalPreferences.plist" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Preferences/ckkeyrolld.plist" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Preferences/nfcd.plist" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Preferences/UITextInputContextIdentifiers.plist" restricted:NO];
    [shadow addPath:@"/var/mobile/Library/Preferences/Wallpaper.png" restricted:NO];
    [shadow addPath:@"/var/mobile/Media" restricted:NO];
    [shadow addPath:@"/var/mobile/MobileSoftwareUpdate" restricted:NO];

    // Restrict /usr by whitelisting
    [shadow addPath:@"/usr" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/bin" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/bin/DumpBasebandCrash" restricted:NO];
    [shadow addPath:@"/usr/bin/PerfPowerServicesExtended" restricted:NO];
    [shadow addPath:@"/usr/bin/abmlite" restricted:NO];
    [shadow addPath:@"/usr/bin/brctl" restricted:NO];
    [shadow addPath:@"/usr/bin/footprint" restricted:NO];
    [shadow addPath:@"/usr/bin/hidutil" restricted:NO];
    [shadow addPath:@"/usr/bin/hpmdiagnose" restricted:NO];
    [shadow addPath:@"/usr/bin/kbdebug" restricted:NO];
    [shadow addPath:@"/usr/bin/powerlogHelperd" restricted:NO];
    [shadow addPath:@"/usr/bin/sysdiagnose" restricted:NO];
    [shadow addPath:@"/usr/bin/tailspin" restricted:NO];
    [shadow addPath:@"/usr/bin/taskinfo" restricted:NO];
    [shadow addPath:@"/usr/bin/vm_stat" restricted:NO];
    [shadow addPath:@"/usr/bin/zprint" restricted:NO];

    if([shadow useTweakCompatibilityMode] && extra_compat) {
        [shadow addPath:@"/usr/lib" restricted:NO];
        [shadow addPath:@"/usr/lib/libsubstrate" restricted:YES];
        [shadow addPath:@"/usr/lib/libsubstitute" restricted:YES];
        [shadow addPath:@"/usr/lib/libSubstitrate" restricted:YES];
        [shadow addPath:@"/usr/lib/TweakInject" restricted:YES];
        [shadow addPath:@"/usr/lib/substrate" restricted:YES];
        [shadow addPath:@"/usr/lib/tweaks" restricted:YES];
        [shadow addPath:@"/usr/lib/apt" restricted:YES];
        [shadow addPath:@"/usr/lib/bash" restricted:YES];
        [shadow addPath:@"/usr/lib/cycript" restricted:YES];
        [shadow addPath:@"/usr/lib/libmis.dylib" restricted:YES];
    } else {
        [shadow addPath:@"/usr/lib" restricted:YES hidden:NO];
        [shadow addPath:@"/usr/lib/FDRSealingMap.plist" restricted:NO];
        [shadow addPath:@"/usr/lib/bbmasks" restricted:NO];
        [shadow addPath:@"/usr/lib/dyld" restricted:NO];
        [shadow addPath:@"/usr/lib/libCRFSuite" restricted:NO];
        [shadow addPath:@"/usr/lib/libDHCPServer" restricted:NO];
        [shadow addPath:@"/usr/lib/libMatch" restricted:NO];
        [shadow addPath:@"/usr/lib/libSystem" restricted:NO];
        [shadow addPath:@"/usr/lib/libarchive" restricted:NO];
        [shadow addPath:@"/usr/lib/libbsm" restricted:NO];
        [shadow addPath:@"/usr/lib/libbz2" restricted:NO];
        [shadow addPath:@"/usr/lib/libc++" restricted:NO];
        [shadow addPath:@"/usr/lib/libc" restricted:NO];
        [shadow addPath:@"/usr/lib/libcharset" restricted:NO];
        [shadow addPath:@"/usr/lib/libcurses" restricted:NO];
        [shadow addPath:@"/usr/lib/libdbm" restricted:NO];
        [shadow addPath:@"/usr/lib/libdl" restricted:NO];
        [shadow addPath:@"/usr/lib/libeasyperf" restricted:NO];
        [shadow addPath:@"/usr/lib/libedit" restricted:NO];
        [shadow addPath:@"/usr/lib/libexslt" restricted:NO];
        [shadow addPath:@"/usr/lib/libextension" restricted:NO];
        [shadow addPath:@"/usr/lib/libform" restricted:NO];
        [shadow addPath:@"/usr/lib/libiconv" restricted:NO];
        [shadow addPath:@"/usr/lib/libicucore" restricted:NO];
        [shadow addPath:@"/usr/lib/libinfo" restricted:NO];
        [shadow addPath:@"/usr/lib/libipsec" restricted:NO];
        [shadow addPath:@"/usr/lib/liblzma" restricted:NO];
        [shadow addPath:@"/usr/lib/libm" restricted:NO];
        [shadow addPath:@"/usr/lib/libmecab" restricted:NO];
        [shadow addPath:@"/usr/lib/libncurses" restricted:NO];
        [shadow addPath:@"/usr/lib/libobjc" restricted:NO];
        [shadow addPath:@"/usr/lib/libpcap" restricted:NO];
        [shadow addPath:@"/usr/lib/libpmsample" restricted:NO];
        [shadow addPath:@"/usr/lib/libpoll" restricted:NO];
        [shadow addPath:@"/usr/lib/libproc" restricted:NO];
        [shadow addPath:@"/usr/lib/libpthread" restricted:NO];
        [shadow addPath:@"/usr/lib/libresolv" restricted:NO];
        [shadow addPath:@"/usr/lib/librpcsvc" restricted:NO];
        [shadow addPath:@"/usr/lib/libsandbox" restricted:NO];
        [shadow addPath:@"/usr/lib/libsqlite3" restricted:NO];
        [shadow addPath:@"/usr/lib/libstdc++" restricted:NO];
        [shadow addPath:@"/usr/lib/libtidy" restricted:NO];
        [shadow addPath:@"/usr/lib/libutil" restricted:NO];
        [shadow addPath:@"/usr/lib/libxml2" restricted:NO];
        [shadow addPath:@"/usr/lib/libxslt" restricted:NO];
        [shadow addPath:@"/usr/lib/libz" restricted:NO];
        [shadow addPath:@"/usr/lib/libperfcheck" restricted:NO];
        [shadow addPath:@"/usr/lib/libedit" restricted:NO];
        [shadow addPath:@"/usr/lib/log" restricted:NO];
        [shadow addPath:@"/usr/lib/system" restricted:NO];
        [shadow addPath:@"/usr/lib/updaters" restricted:NO];
        [shadow addPath:@"/usr/lib/xpc" restricted:NO];
    }
    
    [shadow addPath:@"/usr/libexec" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/libexec/BackupAgent" restricted:NO];
    [shadow addPath:@"/usr/libexec/BackupAgent2" restricted:NO];
    [shadow addPath:@"/usr/libexec/CrashHousekeeping" restricted:NO];
    [shadow addPath:@"/usr/libexec/DataDetectorsSourceAccess" restricted:NO];
    [shadow addPath:@"/usr/libexec/FSTaskScheduler" restricted:NO];
    [shadow addPath:@"/usr/libexec/FinishRestoreFromBackup" restricted:NO];
    [shadow addPath:@"/usr/libexec/IOAccelMemoryInfoCollector" restricted:NO];
    [shadow addPath:@"/usr/libexec/IOMFB_bics_daemon" restricted:NO];
    [shadow addPath:@"/usr/libexec/Library" restricted:NO];
    [shadow addPath:@"/usr/libexec/MobileGestaltHelper" restricted:NO];
    [shadow addPath:@"/usr/libexec/MobileStorageMounter" restricted:NO];
    [shadow addPath:@"/usr/libexec/NANDTaskScheduler" restricted:NO];
    [shadow addPath:@"/usr/libexec/OTATaskingAgent" restricted:NO];
    [shadow addPath:@"/usr/libexec/PowerUIAgent" restricted:NO];
    [shadow addPath:@"/usr/libexec/PreboardService" restricted:NO];
    [shadow addPath:@"/usr/libexec/ProxiedCrashCopier" restricted:NO];
    [shadow addPath:@"/usr/libexec/PurpleReverseProxy" restricted:NO];
    [shadow addPath:@"/usr/libexec/ReportMemoryException" restricted:NO];
    [shadow addPath:@"/usr/libexec/SafariCloudHistoryPushAgent" restricted:NO];
    [shadow addPath:@"/usr/libexec/SidecarRelay" restricted:NO];
    [shadow addPath:@"/usr/libexec/SyncAgent" restricted:NO];
    [shadow addPath:@"/usr/libexec/UserEventAgent" restricted:NO];
    [shadow addPath:@"/usr/libexec/addressbooksyncd" restricted:NO];
    [shadow addPath:@"/usr/libexec/adid" restricted:NO];
    [shadow addPath:@"/usr/libexec/adprivacyd" restricted:NO];
    [shadow addPath:@"/usr/libexec/adservicesd" restricted:NO];
    [shadow addPath:@"/usr/libexec/afcd" restricted:NO];
    [shadow addPath:@"/usr/libexec/airtunesd" restricted:NO];
    [shadow addPath:@"/usr/libexec/amfid" restricted:NO];
    [shadow addPath:@"/usr/libexec/asd" restricted:NO];
    [shadow addPath:@"/usr/libexec/assertiond" restricted:NO];
    [shadow addPath:@"/usr/libexec/atc" restricted:NO];
    [shadow addPath:@"/usr/libexec/atwakeup" restricted:NO];
    [shadow addPath:@"/usr/libexec/backboardd" restricted:NO];
    [shadow addPath:@"/usr/libexec/biometrickitd" restricted:NO];
    [shadow addPath:@"/usr/libexec/bootpd" restricted:NO];
    [shadow addPath:@"/usr/libexec/bulletindistributord" restricted:NO];
    [shadow addPath:@"/usr/libexec/captiveagent" restricted:NO];
    [shadow addPath:@"/usr/libexec/cc_fips_test" restricted:NO];
    [shadow addPath:@"/usr/libexec/checkpointd" restricted:NO];
    [shadow addPath:@"/usr/libexec/cloudpaird" restricted:NO];
    [shadow addPath:@"/usr/libexec/com.apple.automation.defaultslockdownserviced" restricted:NO];
    [shadow addPath:@"/usr/libexec/companion_proxy" restricted:NO];
    [shadow addPath:@"/usr/libexec/configd" restricted:NO];
    [shadow addPath:@"/usr/libexec/corecaptured" restricted:NO];
    [shadow addPath:@"/usr/libexec/coreduetd" restricted:NO];
    [shadow addPath:@"/usr/libexec/crash_mover" restricted:NO];
    [shadow addPath:@"/usr/libexec/dasd" restricted:NO];
    [shadow addPath:@"/usr/libexec/demod" restricted:NO];
    [shadow addPath:@"/usr/libexec/demod_helper" restricted:NO];
    [shadow addPath:@"/usr/libexec/dhcpd" restricted:NO];
    [shadow addPath:@"/usr/libexec/diagnosticd" restricted:NO];
    [shadow addPath:@"/usr/libexec/diagnosticextensionsd" restricted:NO];
    [shadow addPath:@"/usr/libexec/dmd" restricted:NO];
    [shadow addPath:@"/usr/libexec/dprivacyd" restricted:NO];
    [shadow addPath:@"/usr/libexec/dtrace" restricted:NO];
    [shadow addPath:@"/usr/libexec/duetexpertd" restricted:NO];
    [shadow addPath:@"/usr/libexec/eventkitsyncd" restricted:NO];
    [shadow addPath:@"/usr/libexec/fdrhelper" restricted:NO];
    [shadow addPath:@"/usr/libexec/findmydeviced" restricted:NO];
    [shadow addPath:@"/usr/libexec/finish_demo_restore" restricted:NO];
    [shadow addPath:@"/usr/libexec/fmfd" restricted:NO];
    [shadow addPath:@"/usr/libexec/fmflocatord" restricted:NO];
    [shadow addPath:@"/usr/libexec/fseventsd" restricted:NO];
    [shadow addPath:@"/usr/libexec/ftp-proxy" restricted:NO];
    [shadow addPath:@"/usr/libexec/gamecontrollerd" restricted:NO];
    [shadow addPath:@"/usr/libexec/gamed" restricted:NO];
    [shadow addPath:@"/usr/libexec/gpsd" restricted:NO];
    [shadow addPath:@"/usr/libexec/hangreporter" restricted:NO];
    [shadow addPath:@"/usr/libexec/hangtracerd" restricted:NO];
    [shadow addPath:@"/usr/libexec/heartbeatd" restricted:NO];
    [shadow addPath:@"/usr/libexec/hostapd" restricted:NO];
    [shadow addPath:@"/usr/libexec/idamd" restricted:NO];
    [shadow addPath:@"/usr/libexec/init_data_protection -> seputil" restricted:NO];
    [shadow addPath:@"/usr/libexec/installd" restricted:NO];
    [shadow addPath:@"/usr/libexec/ioupsd" restricted:NO];
    [shadow addPath:@"/usr/libexec/keybagd" restricted:NO];
    [shadow addPath:@"/usr/libexec/languageassetd" restricted:NO];
    [shadow addPath:@"/usr/libexec/locationd" restricted:NO];
    [shadow addPath:@"/usr/libexec/lockdownd" restricted:NO];
    [shadow addPath:@"/usr/libexec/logd" restricted:NO];
    [shadow addPath:@"/usr/libexec/lsd" restricted:NO];
    [shadow addPath:@"/usr/libexec/lskdd" restricted:NO];
    [shadow addPath:@"/usr/libexec/lskdmsed" restricted:NO];
    [shadow addPath:@"/usr/libexec/magicswitchd" restricted:NO];
    [shadow addPath:@"/usr/libexec/mc_mobile_tunnel" restricted:NO];
    [shadow addPath:@"/usr/libexec/microstackshot" restricted:NO];
    [shadow addPath:@"/usr/libexec/misagent" restricted:NO];
    [shadow addPath:@"/usr/libexec/misd" restricted:NO];
    [shadow addPath:@"/usr/libexec/mmaintenanced" restricted:NO];
    [shadow addPath:@"/usr/libexec/mobile_assertion_agent" restricted:NO];
    [shadow addPath:@"/usr/libexec/mobile_diagnostics_relay" restricted:NO];
    [shadow addPath:@"/usr/libexec/mobile_house_arrest" restricted:NO];
    [shadow addPath:@"/usr/libexec/mobile_installation_proxy" restricted:NO];
    [shadow addPath:@"/usr/libexec/mobile_obliterator" restricted:NO];
    [shadow addPath:@"/usr/libexec/mobile_storage_proxy" restricted:NO];
    [shadow addPath:@"/usr/libexec/mobileactivationd" restricted:NO];
    [shadow addPath:@"/usr/libexec/mobileassetd" restricted:NO];
    [shadow addPath:@"/usr/libexec/mobilewatchdog" restricted:NO];
    [shadow addPath:@"/usr/libexec/mtmergeprops" restricted:NO];
    [shadow addPath:@"/usr/libexec/nanomediaremotelinkagent" restricted:NO];
    [shadow addPath:@"/usr/libexec/nanoregistryd" restricted:NO];
    [shadow addPath:@"/usr/libexec/nanoregistrylaunchd" restricted:NO];
    [shadow addPath:@"/usr/libexec/neagent" restricted:NO];
    [shadow addPath:@"/usr/libexec/nehelper" restricted:NO];
    [shadow addPath:@"/usr/libexec/nesessionmanager" restricted:NO];
    [shadow addPath:@"/usr/libexec/networkserviceproxy" restricted:NO];
    [shadow addPath:@"/usr/libexec/nfcd" restricted:NO];
    [shadow addPath:@"/usr/libexec/nfrestore_service" restricted:NO];
    [shadow addPath:@"/usr/libexec/nlcd" restricted:NO];
    [shadow addPath:@"/usr/libexec/notification_proxy" restricted:NO];
    [shadow addPath:@"/usr/libexec/nptocompaniond" restricted:NO];
    [shadow addPath:@"/usr/libexec/nsurlsessiond" restricted:NO];
    [shadow addPath:@"/usr/libexec/nsurlstoraged" restricted:NO];
    [shadow addPath:@"/usr/libexec/online-auth-agent" restricted:NO];
    [shadow addPath:@"/usr/libexec/oscard" restricted:NO];
    [shadow addPath:@"/usr/libexec/pcapd" restricted:NO];
    [shadow addPath:@"/usr/libexec/pcsstatus" restricted:NO];
    [shadow addPath:@"/usr/libexec/pfd" restricted:NO];
    [shadow addPath:@"/usr/libexec/pipelined" restricted:NO];
    [shadow addPath:@"/usr/libexec/pkd" restricted:NO];
    [shadow addPath:@"/usr/libexec/pkreporter" restricted:NO];
    [shadow addPath:@"/usr/libexec/ptpd" restricted:NO];
    [shadow addPath:@"/usr/libexec/rapportd" restricted:NO];
    [shadow addPath:@"/usr/libexec/replayd" restricted:NO];
    [shadow addPath:@"/usr/libexec/resourcegrabberd" restricted:NO];
    [shadow addPath:@"/usr/libexec/rolld" restricted:NO];
    [shadow addPath:@"/usr/libexec/routined" restricted:NO];
    [shadow addPath:@"/usr/libexec/rtbuddyd" restricted:NO];
    [shadow addPath:@"/usr/libexec/rtcreportingd" restricted:NO];
    [shadow addPath:@"/usr/libexec/safarifetcherd" restricted:NO];
    [shadow addPath:@"/usr/libexec/screenshotsyncd" restricted:NO];
    [shadow addPath:@"/usr/libexec/security-sysdiagnose" restricted:NO];
    [shadow addPath:@"/usr/libexec/securityd" restricted:NO];
    [shadow addPath:@"/usr/libexec/securityuploadd" restricted:NO];
    [shadow addPath:@"/usr/libexec/seld" restricted:NO];
    [shadow addPath:@"/usr/libexec/seputil" restricted:NO];
    [shadow addPath:@"/usr/libexec/sharingd" restricted:NO];
    [shadow addPath:@"/usr/libexec/signpost_reporter" restricted:NO];
    [shadow addPath:@"/usr/libexec/silhouette" restricted:NO];
    [shadow addPath:@"/usr/libexec/siriknowledged" restricted:NO];
    [shadow addPath:@"/usr/libexec/smcDiagnose" restricted:NO];
    [shadow addPath:@"/usr/libexec/splashboardd" restricted:NO];
    [shadow addPath:@"/usr/libexec/springboardservicesrelay" restricted:NO];
    [shadow addPath:@"/usr/libexec/streaming_zip_conduit" restricted:NO];
    [shadow addPath:@"/usr/libexec/swcd" restricted:NO];
    [shadow addPath:@"/usr/libexec/symptomsd" restricted:NO];
    [shadow addPath:@"/usr/libexec/symptomsd-helper" restricted:NO];
    [shadow addPath:@"/usr/libexec/sysdiagnose_helper" restricted:NO];
    [shadow addPath:@"/usr/libexec/sysstatuscheck" restricted:NO];
    [shadow addPath:@"/usr/libexec/tailspind" restricted:NO];
    [shadow addPath:@"/usr/libexec/timed" restricted:NO];
    [shadow addPath:@"/usr/libexec/tipsd" restricted:NO];
    [shadow addPath:@"/usr/libexec/topicsmap.db" restricted:NO];
    [shadow addPath:@"/usr/libexec/transitd" restricted:NO];
    [shadow addPath:@"/usr/libexec/trustd" restricted:NO];
    [shadow addPath:@"/usr/libexec/tursd" restricted:NO];
    [shadow addPath:@"/usr/libexec/tzd" restricted:NO];
    [shadow addPath:@"/usr/libexec/tzinit" restricted:NO];
    [shadow addPath:@"/usr/libexec/tzlinkd" restricted:NO];
    [shadow addPath:@"/usr/libexec/videosubscriptionsd" restricted:NO];
    [shadow addPath:@"/usr/libexec/wapic" restricted:NO];
    [shadow addPath:@"/usr/libexec/wcd" restricted:NO];
    [shadow addPath:@"/usr/libexec/webbookmarksd" restricted:NO];
    [shadow addPath:@"/usr/libexec/webinspectord" restricted:NO];
    [shadow addPath:@"/usr/libexec/wifiFirmwareLoader" restricted:NO];
    [shadow addPath:@"/usr/libexec/wifivelocityd" restricted:NO];
    [shadow addPath:@"/usr/libexec/xpcproxy" restricted:NO];
    [shadow addPath:@"/usr/libexec/xpcroleaccountd" restricted:NO];
    [shadow addPath:@"/usr/local" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/local/bin" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/local/lib" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/local/standalone" restricted:NO];
    [shadow addPath:@"/usr/sbin" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/sbin/BTAvrcp" restricted:NO];
    [shadow addPath:@"/usr/sbin/BTLEServer" restricted:NO];
    [shadow addPath:@"/usr/sbin/BTMap" restricted:NO];
    [shadow addPath:@"/usr/sbin/BTPbap" restricted:NO];
    [shadow addPath:@"/usr/sbin/BlueTool" restricted:NO];
    [shadow addPath:@"/usr/sbin/WiFiNetworkStoreModel.momd" restricted:NO];
    [shadow addPath:@"/usr/sbin/WirelessRadioManagerd" restricted:NO];
    [shadow addPath:@"/usr/sbin/absd" restricted:NO];
    [shadow addPath:@"/usr/sbin/addNetworkInterface" restricted:NO];
    [shadow addPath:@"/usr/sbin/applecamerad" restricted:NO];
    [shadow addPath:@"/usr/sbin/aslmanager" restricted:NO];
    [shadow addPath:@"/usr/sbin/bluetoothd" restricted:NO];
    [shadow addPath:@"/usr/sbin/cfprefsd" restricted:NO];
    [shadow addPath:@"/usr/sbin/ckksctl" restricted:NO];
    [shadow addPath:@"/usr/sbin/distnoted" restricted:NO];
    [shadow addPath:@"/usr/sbin/fairplayd.H2" restricted:NO];
    [shadow addPath:@"/usr/sbin/filecoordinationd" restricted:NO];
    [shadow addPath:@"/usr/sbin/ioreg" restricted:NO];
    [shadow addPath:@"/usr/sbin/ipconfig" restricted:NO];
    [shadow addPath:@"/usr/sbin/mDNSResponder" restricted:NO];
    [shadow addPath:@"/usr/sbin/mDNSResponderHelper" restricted:NO];
    [shadow addPath:@"/usr/sbin/mediaserverd" restricted:NO];
    [shadow addPath:@"/usr/sbin/notifyd" restricted:NO];
    [shadow addPath:@"/usr/sbin/nvram" restricted:NO];
    [shadow addPath:@"/usr/sbin/pppd" restricted:NO];
    [shadow addPath:@"/usr/sbin/racoon" restricted:NO];
    [shadow addPath:@"/usr/sbin/rtadvd" restricted:NO];
    [shadow addPath:@"/usr/sbin/scutil" restricted:NO];
    [shadow addPath:@"/usr/sbin/spindump" restricted:NO];
    [shadow addPath:@"/usr/sbin/syslogd" restricted:NO];
    [shadow addPath:@"/usr/sbin/wifid" restricted:NO];
    [shadow addPath:@"/usr/sbin/wirelessproxd" restricted:NO];
    [shadow addPath:@"/usr/share" restricted:YES hidden:NO];
    [shadow addPath:@"/usr/share/com.apple.languageassetd" restricted:NO];
    [shadow addPath:@"/usr/share/CSI" restricted:NO];
    [shadow addPath:@"/usr/share/firmware" restricted:NO];
    [shadow addPath:@"/usr/share/icu" restricted:NO];
    [shadow addPath:@"/usr/share/langid" restricted:NO];
    [shadow addPath:@"/usr/share/locale" restricted:NO];
    [shadow addPath:@"/usr/share/mecabra" restricted:NO];
    [shadow addPath:@"/usr/share/misc" restricted:NO];
    [shadow addPath:@"/usr/share/progressui" restricted:NO];
    [shadow addPath:@"/usr/share/tokenizer" restricted:NO];
    [shadow addPath:@"/usr/share/zoneinfo" restricted:NO];
    [shadow addPath:@"/usr/share/zoneinfo.default" restricted:NO];
    [shadow addPath:@"/usr/standalone" restricted:NO];

    // Restrict /System
    [shadow addPath:@"/System" restricted:NO];
    [shadow addPath:@"/System/Library/PreferenceBundles/AppList.bundle" restricted:YES];
}

// Manual hooks
#include <dirent.h>

static int (*orig_open)(const char *path, int oflag, ...);
static int hook_open(const char *path, int oflag, ...) {
    int result = 0;

    if(path) {
        NSString *pathname = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([_shadow isPathRestricted:pathname]) {
            errno = ((oflag & O_CREAT) == O_CREAT) ? EACCES : ENOENT;
            return -1;
        }
    }
    
    if((oflag & O_CREAT) == O_CREAT) {
        mode_t mode;
        va_list args;
        
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);

        result = orig_open(path, oflag, mode);
    } else {
        result = orig_open(path, oflag);
    }

    return result;
}

static int (*orig_openat)(int fd, const char *path, int oflag, ...);
static int hook_openat(int fd, const char *path, int oflag, ...) {
    int result = 0;

    if(path) {
        NSString *nspath = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if(![nspath isAbsolutePath]) {
            // Get path of dirfd.
            char dirfdpath[PATH_MAX];
        
            if(fcntl(fd, F_GETPATH, dirfdpath) != -1) {
                NSString *dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
                nspath = [dirfd_path stringByAppendingPathComponent:nspath];
            }
        }
        
        if([_shadow isPathRestricted:nspath]) {
            errno = ((oflag & O_CREAT) == O_CREAT) ? EACCES : ENOENT;
            return -1;
        }
    }
    
    if((oflag & O_CREAT) == O_CREAT) {
        mode_t mode;
        va_list args;
        
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);

        result = orig_openat(fd, path, oflag, mode);
    } else {
        result = orig_openat(fd, path, oflag);
    }

    return result;
}

static DIR *(*orig_opendir)(const char *filename);
static DIR *hook_opendir(const char *filename) {
    if(filename) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:filename length:strlen(filename)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    return orig_opendir(filename);
}

static struct dirent *(*orig_readdir)(DIR *dirp);
static struct dirent *hook_readdir(DIR *dirp) {
    struct dirent *ret = NULL;
    NSString *path = nil;

    // Get path of dirfd.
    NSString *dirfd_path = nil;
    int fd = dirfd(dirp);
    char dirfdpath[PATH_MAX];

    if(fcntl(fd, F_GETPATH, dirfdpath) != -1) {
        dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
    } else {
        return orig_readdir(dirp);
    }

    // Filter returned results, skipping over restricted paths.
    do {
        ret = orig_readdir(dirp);

        if(ret) {
            path = [dirfd_path stringByAppendingPathComponent:[NSString stringWithUTF8String:ret->d_name]];
        } else {
            break;
        }
    } while([_shadow isPathRestricted:path]);

    return ret;
}

static int (*orig_dladdr)(const void *addr, Dl_info *info);
static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);

    if(!passthrough && ret) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info->dli_fname length:strlen(info->dli_fname)];

        if([_shadow isImageRestricted:path]) {
            return 0;
        }
    }

    return ret;
}

static ssize_t (*orig_readlink)(const char *path, char *buf, size_t bufsiz);
static ssize_t hook_readlink(const char *path, char *buf, size_t bufsiz) {
    if(!path || !buf) {
        return orig_readlink(path, buf, bufsiz);
    }

    NSString *nspath = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

    if([_shadow isPathRestricted:nspath]) {
        errno = ENOENT;
        return -1;
    }

    ssize_t ret = orig_readlink(path, buf, bufsiz);

    if(ret != -1) {
        buf[ret] = '\0';

        // Track this symlink in Shadow
        [_shadow addLinkFromPath:nspath toPath:[[NSFileManager defaultManager] stringWithFileSystemRepresentation:buf length:strlen(buf)]];
    }

    return ret;
}

static ssize_t (*orig_readlinkat)(int fd, const char *path, char *buf, size_t bufsiz);
static ssize_t hook_readlinkat(int fd, const char *path, char *buf, size_t bufsiz) {
    if(!path || !buf) {
        return orig_readlinkat(fd, path, buf, bufsiz);
    }

    NSString *nspath = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

    if(![nspath isAbsolutePath]) {
        // Get path of dirfd.
        char dirfdpath[PATH_MAX];
    
        if(fcntl(fd, F_GETPATH, dirfdpath) != -1) {
            NSString *dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
            nspath = [dirfd_path stringByAppendingPathComponent:nspath];
        }
    }

    if([_shadow isPathRestricted:nspath]) {
        errno = ENOENT;
        return -1;
    }

    ssize_t ret = orig_readlinkat(fd, path, buf, bufsiz);

    if(ret != -1) {
        buf[ret] = '\0';

        // Track this symlink in Shadow
        [_shadow addLinkFromPath:nspath toPath:[[NSFileManager defaultManager] stringWithFileSystemRepresentation:buf length:strlen(buf)]];
    }

    return ret;
}

%group hook_springboard
%hook SpringBoard
- (void)applicationDidFinishLaunching:(UIApplication *)application {
    %orig;

    HBPreferences *prefs = [HBPreferences preferencesForIdentifier:BLACKLIST_PATH];

    NSArray *file_map = [Shadow generateFileMap];
    NSArray *url_set = [Shadow generateSchemeArray];

    [prefs setObject:file_map forKey:@"files"];
    [prefs setObject:url_set forKey:@"schemes"];
}
%end
%end

%ctor {
    NSString *processName = [[NSProcessInfo processInfo] processName];

    if([processName isEqualToString:@"SpringBoard"]) {
        HBPreferences *prefs = [HBPreferences preferencesForIdentifier:PREFS_TWEAK_ID];

        if(prefs && [prefs boolForKey:@"auto_file_map_generation_enabled"]) {
            %init(hook_springboard);
        }

        return;
    }

    NSBundle *bundle = [NSBundle mainBundle];

    if(bundle != nil) {
        NSString *executablePath = [bundle executablePath];
        NSString *bundleIdentifier = [bundle bundleIdentifier];

        // User (Sandboxed) Applications
        if([executablePath hasPrefix:@"/var/containers/Bundle/Application"]
        || [executablePath hasPrefix:@"/private/var/containers/Bundle/Application"]
        || [executablePath hasPrefix:@"/var/mobile/Containers/Bundle/Application"]
        || [executablePath hasPrefix:@"/private/var/mobile/Containers/Bundle/Application"]) {
            NSLog(@"bundleIdentifier: %@", bundleIdentifier);

            HBPreferences *prefs = [HBPreferences preferencesForIdentifier:PREFS_TWEAK_ID];

            [prefs registerDefaults:@{
                @"enabled" : @YES,
                @"mode" : @"whitelist",
                @"bypass_checks" : @YES,
                @"exclude_system_apps" : @YES,
                @"dyld_hooks_enabled" : @YES,
                @"extra_compat_enabled" : @YES
            }];

            extra_compat = [prefs boolForKey:@"extra_compat_enabled"];
            
            // Check if Shadow is enabled
            if(![prefs boolForKey:@"enabled"]) {
                // Shadow disabled in preferences
                return;
            }

            // Check if safe bundleIdentifier
            if([prefs boolForKey:@"exclude_system_apps"]) {
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

            HBPreferences *prefs_apps = [HBPreferences preferencesForIdentifier:APPS_PATH];

            // Check if excluded bundleIdentifier
            NSString *mode = [prefs objectForKey:@"mode"];

            if([mode isEqualToString:@"whitelist"]) {
                // Whitelist - disable Shadow if not enabled for this bundleIdentifier
                if(![prefs_apps boolForKey:bundleIdentifier]) {
                    return;
                }
            } else {
                // Blacklist - disable Shadow if enabled for this bundleIdentifier
                if([prefs_apps boolForKey:bundleIdentifier]) {
                    return;
                }
            }

            HBPreferences *prefs_blacklist = [HBPreferences preferencesForIdentifier:BLACKLIST_PATH];
            HBPreferences *prefs_tweakcompat = [HBPreferences preferencesForIdentifier:TWEAKCOMPAT_PATH];
            HBPreferences *prefs_lockdown = [HBPreferences preferencesForIdentifier:LOCKDOWN_PATH];
            HBPreferences *prefs_dlfcn = [HBPreferences preferencesForIdentifier:DLFCN_PATH];

            // Initialize Shadow
            _shadow = [Shadow new];

            if(!_shadow) {
                NSLog(@"failed to initialize Shadow");
                return;
            }

            // Compatibility mode
            [_shadow setUseTweakCompatibilityMode:[prefs_tweakcompat boolForKey:bundleIdentifier] ? NO : YES];

            // Disable inject compatibility if we are using Substitute.
            NSFileManager *fm = [NSFileManager defaultManager];
            BOOL isSubstitute = ([fm fileExistsAtPath:@"/usr/lib/libsubstitute.dylib"] && ![fm fileExistsAtPath:@"/usr/lib/substrate"]);

            if(isSubstitute) {
                [_shadow setUseInjectCompatibilityMode:NO];
                NSLog(@"detected Substitute");
            } else {
                [_shadow setUseInjectCompatibilityMode:YES];
                NSLog(@"detected Substrate");
            }

            // Lockdown mode
            if([prefs_lockdown boolForKey:bundleIdentifier]) {
                %init(hook_libc_inject);
                %init(hook_dlopen_inject);

                MSHookFunction((void *) open, (void *) hook_open, (void **) &orig_open);
                MSHookFunction((void *) openat, (void *) hook_openat, (void **) &orig_openat);

                [_shadow setUseInjectCompatibilityMode:NO];
                [_shadow setUseTweakCompatibilityMode:NO];

                _dyld_register_func_for_add_image(dyld_image_added);

                if([prefs boolForKey:@"experimental_enabled"]) {
                    %init(hook_experimental);
                }

                if([prefs boolForKey:@"standardize_paths"]) {
                    [_shadow setUsePathStandardization:YES];
                }

                NSLog(@"enabled lockdown mode");
            }

            if([_shadow useInjectCompatibilityMode]) {
                NSLog(@"using injection compatibility mode");
            } else {
                // Substitute doesn't like hooking opendir :(
                if(!isSubstitute) {
                    MSHookFunction((void *) opendir, (void *) hook_opendir, (void **) &orig_opendir);
                }

                MSHookFunction((void *) readdir, (void *) hook_readdir, (void **) &orig_readdir);
            }

            if([_shadow useTweakCompatibilityMode]) {
                NSLog(@"using tweak compatibility mode");
            }

            // Initialize restricted path map
            init_path_map(_shadow);
            NSLog(@"initialized internal path map");

            // Initialize file map
            NSArray *file_map = [prefs_blacklist objectForKey:@"files"];
            NSArray *url_set = [prefs_blacklist objectForKey:@"schemes"];

            if(file_map) {
                [_shadow addPathsFromFileMap:file_map];

                NSLog(@"initialized file map (%lu items)", (unsigned long) [file_map count]);
            }

            if(url_set) {
                [_shadow addSchemesFromURLSet:url_set];

                NSLog(@"initialized url set (%lu items)", (unsigned long) [url_set count]);
            }

            // Initialize stable hooks
            %init(hook_private);
            %init(hook_NSFileManager);
            %init(hook_NSFileWrapper);
            %init(hook_NSFileVersion);
            %init(hook_libc);
            %init(hook_debugging);
            %init(hook_NSFileHandle);
            %init(hook_NSURL);
            %init(hook_UIApplication);
            %init(hook_NSBundle);
            %init(hook_NSUtilities);
            %init(hook_NSEnumerator);

            MSHookFunction((void *) readlink, (void *) hook_readlink, (void **) &orig_readlink);
            MSHookFunction((void *) readlinkat, (void *) hook_readlinkat, (void **) &orig_readlinkat);

            NSLog(@"hooked bypass methods");

            // Initialize other hooks
            if([prefs boolForKey:@"bypass_checks"]) {
                %init(hook_libraries);

                NSLog(@"hooked detection libraries");
            }

            if([prefs boolForKey:@"dyld_hooks_enabled"]) {
                %init(hook_dyld_image);
                MSHookFunction((void *) dladdr, (void *) hook_dladdr, (void **) &orig_dladdr);

                NSLog(@"filtering dynamic libraries");
            }

            if([prefs boolForKey:@"sandbox_hooks_enabled"]) {
                %init(hook_sandbox);

                NSLog(@"hooked sandbox methods");
            }

            // Generate filtered dyld array
            if([prefs boolForKey:@"dyld_filter_enabled"]) {
                updateDyldArray();

                // %init(hook_dyld_advanced);
                // %init(hook_CoreFoundation);
                %init(hook_runtime);

                NSLog(@"enabled advanced dynamic library filtering");
            }

            if([prefs_dlfcn boolForKey:bundleIdentifier]) {
                %init(hook_dyld_dlsym);

                NSLog(@"hooked dynamic linker methods");
            }

            _error_file_not_found = [Shadow generateFileNotFoundError];
            enum_path = [NSMutableDictionary new];

            NSLog(@"ready");
        }
    }
}
