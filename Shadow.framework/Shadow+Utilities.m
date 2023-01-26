#import "Shadow+Utilities.h"

@implementation Shadow (Utilities)
+ (BOOL)shouldResolvePath:(NSString *)path {
    if([path characterAtIndex:0] == '~') {
        return YES;
    }

    NSPredicate* pred = [NSPredicate predicateWithFormat:@"SELF LIKE '*/./*' OR SELF LIKE '*/../*' OR SELF ENDSWITH '/.' OR SELF ENDSWITH '/..'"];

    if([pred evaluateWithObject:path]) {
        // resolving relative path component
        return YES;
    }

    return NO;
}

+ (NSString *)getStandardizedPath:(NSString *)path {
    NSURL* url = [NSURL URLWithString:path];

    if(url) {
        path = [[url standardizedURL] path];
    } else {
        NSString* filename = [path lastPathComponent];
        NSString* basename = [path stringByDeletingLastPathComponent];

        url = [NSURL URLWithString:basename];

        if(url) {
            path = [[url standardizedURL] path];
            path = [path stringByAppendingPathComponent:filename];
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
