#import <Shadow/Core+Utilities.h>
#import "../vendor/apple/dyld_priv.h"

extern char*** _NSGetArgv();

@implementation Shadow (Utilities)
+ (NSString *)getStandardizedPath:(NSString *)path {
    if(!path) {
        return path;
    }

    NSURL* url = [[NSURL fileURLWithPath:path isDirectory:NO] standardizedURL];

    if(url) {
        path = [url path];
    }

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

// code from Choicy
//methods of getting executablePath and bundleIdentifier with the least side effects possible
//for more information, check out https://github.com/checkra1n/BugTracker/issues/343
+ (NSString *)getExecutablePath {
    static NSString* executablePath = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
	    char* executablePathC = **_NSGetArgv();

        if(executablePathC) {
            executablePath = @(executablePathC);
        }
    });

    return executablePath;
}

+ (NSString *)getBundleIdentifier {
    static NSString* bundleIdentifier = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        CFBundleRef mainBundle = CFBundleGetMainBundle();

        if(mainBundle != NULL) {
            CFStringRef bundleIdentifierCF = CFBundleGetIdentifier(mainBundle);
            bundleIdentifier = (__bridge NSString *)bundleIdentifierCF;
        }
    });

	return bundleIdentifier;
}

+ (NSString *)getCallerPath {
    const void* ret_addr = __builtin_extract_return_addr(__builtin_return_address(0));

    if(ret_addr) {
        const char* ret_image_name = dyld_image_path_containing_address(ret_addr);

        if(ret_image_name) {
            return @(ret_image_name);
        }
    }

    return nil;
}

+ (BOOL)isJBRootless {
    static BOOL rootless = NO;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        NSString* caller_path = [self getCallerPath];
        rootless = !([caller_path hasPrefix:@"/Library"] || [caller_path hasPrefix:@"/usr"]);
    });
    
    return rootless;
}

+ (NSString *)getJBPath:(NSString *)path {
    if(![self isJBRootless] || !path || ![path isAbsolutePath] || [path hasPrefix:@"/var/jb"]) {
        return path;
    }

    return [@"/var/jb" stringByAppendingPathComponent:path];
}
@end
