#import "Shadow+Utilities.h"

extern char*** _NSGetArgv();

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

// code from Choicy
//methods of getting executablePath and bundleIdentifier with the least side effects possible
//for more information, check out https://github.com/checkra1n/BugTracker/issues/343
+ (NSString *)getExecutablePath {
	char* executablePathC = **_NSGetArgv();
	return [NSString stringWithUTF8String:executablePathC];
}

+ (NSString *)getBundleIdentifier {
	CFBundleRef mainBundle = CFBundleGetMainBundle();

	if(mainBundle != NULL) {
		CFStringRef bundleIdentifierCF = CFBundleGetIdentifier(mainBundle);
		return (__bridge NSString *) bundleIdentifierCF;
	}

	return nil;
}
@end