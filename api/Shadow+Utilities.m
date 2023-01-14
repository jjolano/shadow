#import "Shadow+Utilities.h"

#import <sys/stat.h>

@implementation Shadow (Utilities)
+ (BOOL)shouldResolvePath:(NSString *)path lstat:(void *)lstat_ptr {
    if(![path isAbsolutePath] || [path characterAtIndex:0] == '~') {
        return YES;
    }

    NSPredicate* pred = [NSPredicate predicateWithFormat:@"SELF LIKE '*/./*' OR SELF LIKE '*/../*' OR SELF ENDSWITH '/.' OR SELF ENDSWITH '/..'"];

    if([pred evaluateWithObject:path]) {
        // resolving relative path component
        return YES;
    }

    // check if path is symlink
    NSString* path_tmp = path;

    struct stat buf;
    int (*original_lstat)(const char* pathname, struct stat* buf) = lstat_ptr;
    if(!original_lstat) return NO;
    
    while(![path_tmp isEqualToString:@"/"]) {
        if(original_lstat([path UTF8String], &buf) != -1 && buf.st_mode & S_IFLNK) {
            return YES;
        }

        path_tmp = [path_tmp stringByDeletingLastPathComponent];
    }
    
    return NO;
}

+ (NSString *)getStandardizedPath:(NSString *)path {
    while([path containsString:@"/./"]) {
        path = [path stringByReplacingOccurrencesOfString:@"/./" withString:@"/"];
    }

    while([path containsString:@"//"]) {
        path = [path stringByReplacingOccurrencesOfString:@"//" withString:@"/"];
    }

    if([path length] > 1) {
        if([path hasSuffix:@"/"]) {
            path = [path substringToIndex:[path length] - 1];
        }

        while([path hasSuffix:@"/."]) {
            path = [path stringByDeletingLastPathComponent];
        }
        
        while([path hasSuffix:@"/.."]) {
            path = [path stringByDeletingLastPathComponent];
            path = [path stringByDeletingLastPathComponent];
        }
    }

    if([path hasPrefix:@"/private/var"] || [path hasPrefix:@"/private/etc"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    if([path hasPrefix:@"/var/tmp"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    return path;
}
@end
