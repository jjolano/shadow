#import <Shadow/JBPath.h>
#import <Shadow/Core.h>

#import <limits.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <dirent.h>

#if !defined(SHADOW_ROOTHIDE) && !defined(SHADOW_TEST_HARNESS)

// Runtime jbroot probe with 1s TTL, SHADOW_INTERNAL_SCOPE for device file ops.
// Probe order: env JBROOT/SHADOW_JBROOT, realpath /var/jb, scan /private/preboot/*/jb, fallback compile-time prefix.

static NSString *sJBRoot = nil;
static NSTimeInterval sJBRootExpiry = 0;

static NSString* shdw_probe_jbroot(void) {
    // 1. env JBROOT / SHADOW_JBROOT
    const char *env = getenv("JBROOT");
    if (!env || !env[0]) env = getenv("SHADOW_JBROOT");
    if (env && env[0]) {
        NSString *p = [NSString stringWithUTF8String:env];
        BOOL exists = NO;
        SHADOW_INTERNAL_SCOPE {
            exists = [[NSFileManager defaultManager] fileExistsAtPath:p];
        }
        if (exists) return p;
    }

    // 2. realpath /var/jb
    char resolved[PATH_MAX];
    BOOL ok = NO;
    SHADOW_INTERNAL_SCOPE {
        ok = realpath("/var/jb", resolved) != NULL;
    }
    if (ok) {
        return [NSString stringWithUTF8String:resolved];
    }

    SHADOW_INTERNAL_SCOPE {
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
            return @"/var/jb";
        }
    }

    // 3. scan /private/preboot/*/jb
    SHADOW_INTERNAL_SCOPE {
        NSString *preboot = @"/private/preboot";
        NSArray *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:preboot error:nil];
        for (NSString *e in entries) {
            NSString *candidate = [[preboot stringByAppendingPathComponent:e] stringByAppendingPathComponent:@"jb"];
            BOOL isDir = NO;
            if ([[NSFileManager defaultManager] fileExistsAtPath:candidate isDirectory:&isDir] && isDir) {
                char candResolved[PATH_MAX];
                if (realpath([candidate fileSystemRepresentation], candResolved)) {
                    return [NSString stringWithUTF8String:candResolved];
                }
                return candidate;
            }
        }
    }

    // 4. fallback compile-time prefix
#ifndef THEOS_PACKAGE_INSTALL_PREFIX
#define THEOS_PACKAGE_INSTALL_PREFIX ""
#endif
    NSString *fallback = @THEOS_PACKAGE_INSTALL_PREFIX;
    if ([fallback length] > 0) return fallback;
    return @"";
}

NSString* shdw_jbroot_prefix(void) {
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    if (sJBRoot && now < sJBRootExpiry) return sJBRoot;

    NSString *fresh = shdw_probe_jbroot();
    sJBRoot = [fresh copy];
    sJBRootExpiry = now + 1.0;
    return sJBRoot;
}

NSString* JBPath(NSString* path) {
    if (!path) return path;

    NSString *root = shdw_jbroot_prefix();
    BOOL isRootless = [root length] > 0;

    if (isRootless && ([path hasPrefix:@"/Library/"]
        || [path hasPrefix:@"/usr/"]
        || [path hasPrefix:@"/Applications/"])) {
        if ([path hasPrefix:root]) return path;
        return [root stringByAppendingString:path];
    }

    return path;
}

BOOL JBIsRootless(void) {
    return [shdw_jbroot_prefix() length] > 0;
}

BOOL shdw_is_restricted_root(const char *path) {
    if (!path || !path[0]) return NO;
    // /private/preboot itself is present on stock iOS. Hide jailbreak
    // descendants, but let the stock directory reach the ruleset.
    if (strcmp(path, "/private/preboot") == 0 || strcmp(path, "/preboot") == 0) return NO;

    if (strncmp(path, "/var/jb", 7) == 0
        && (path[7] == '\0' || path[7] == '/')) return YES;
    if (strncmp(path, "/private/var/jb", 15) == 0
        && (path[15] == '\0' || path[15] == '/')) return YES;
    if (strncmp(path, "/cores/", 7) == 0) return YES;
    if (strncmp(path, "/private/preboot", 16) == 0
        && (path[16] == '\0' || path[16] == '/')) return YES;
    if (strncmp(path, "/preboot", 8) == 0
        && (path[8] == '\0' || path[8] == '/')) return YES;

    NSString *root = shdw_jbroot_prefix();
    if (root && [root length] > 0) {
        const char *r = [root fileSystemRepresentation];
        size_t rl = strlen(r);
        if (rl > 0 && strncmp(path, r, rl) == 0) {
            if (r[rl - 1] == '/') return YES;
            if (path[rl] == '\0' || path[rl] == '/') return YES;
        }
    }

    return NO;
}

BOOL shdw_is_restricted_root_c(const char *path) {
    return shdw_is_restricted_root(path);
}

BOOL shdw_path_contains_restricted_root_c(const char *path) {
    if (!path || !path[0]) return NO;

    if (strstr(path, "/var/jb") != NULL) return YES;
    if (strstr(path, "/private/preboot") != NULL) return YES;
    if (strstr(path, "/preboot") != NULL) return YES;
    if (strstr(path, "/cores/") != NULL) return YES;

    NSString *root = shdw_jbroot_prefix();
    if (root && [root length] > 0) {
        const char *r = [root fileSystemRepresentation];
        if (r && r[0] && strstr(path, r) != NULL) return YES;
    }

    return NO;
}

BOOL shdw_is_path_in_restricted_root(NSString *path) {
    return path ? shdw_is_restricted_root([path fileSystemRepresentation]) : NO;
}

#endif
