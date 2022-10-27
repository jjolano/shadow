#import "hooks.h"

#import <stdio.h>
#import <sys/stat.h>

%group shadowhook_libc
%hookf(int, access, const char *pathname, int mode) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([[Shadow sharedInstance] isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, stat, const char *pathname, struct stat *statbuf) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([[Shadow sharedInstance] isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, lstat, const char *pathname, struct stat *statbuf) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([[Shadow sharedInstance] isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(FILE *, fopen, const char *pathname, const char *mode) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([[Shadow sharedInstance] isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    return %orig;
}
%end

void shadowhook_libc(void) {
    %init(shadowhook_libc);
}
