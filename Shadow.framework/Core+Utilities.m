#import <Shadow/Core+Utilities.h>

#import "../vendor/apple/dyld_priv.h"

extern char*** _NSGetArgv();

@implementation Shadow (Utilities)

+ (NSString *)getStandardizedPath:(NSString *)path {
    if(!path) {
        return path;
    }

    // Fast path: an absolute path containing none of the sequences the
    // standardization below transforms passes through the NSURL machinery
    // byte-for-byte, so return it directly. Every transform the slow path
    // can apply has a trigger here: "/." (dot components, incl. "/./" and
    // "/../", which standardizedURL resolves), "//" (empty segments), a
    // trailing slash, the query/fragment/parameter markers "?", "#" and ";"
    // (URLWithString strips them from -path), percent-encoding ("%": %2e dot
    // components, and %2f etc. that -path decodes), and the /private/var,
    // /private/etc and /var/tmp prefixes the rewrites below target. Anything
    // else — relative paths, tildes, scheme-like strings — also takes the
    // slow path, which is the only code that may transform them.
    if([path hasPrefix:@"/"]
        && ![path hasSuffix:@"/"]
        && ![path containsString:@"/."]
        && ![path containsString:@"//"]
        && ![path containsString:@"%"]
        && ![path containsString:@"?"]
        && ![path containsString:@"#"]
        && ![path containsString:@";"]
        && ![path hasPrefix:@"/private/var"]
        && ![path hasPrefix:@"/private/etc"]
        && ![path hasPrefix:@"/var/tmp"]) {
        return path;
    }

    // Darwin's NSURL standardization turns "/../x" into a RELATIVE "x"
    // (it consumes the root slash), so collapse leading dot-dots ourselves
    // before handing off — the result must stay absolute.
    while([path hasPrefix:@"/../"]) {
        path = [path substringFromIndex:3];
    }
    if([path isEqualToString:@"/.."]) {
        path = @"/";
    }

    NSURL* url = [NSURL URLWithString:path];

    if(!url) {
        url = [NSURL fileURLWithPath:path];
    }

    NSString* standardized_path = [[url standardizedURL] path];

    if(standardized_path) {
        path = standardized_path;
    }

    while([path containsString:@"/./"]) {
        path = [path stringByReplacingOccurrencesOfString:@"/./" withString:@"/"];
    }

    // ponytail: /./ and // collapse are kept — NSURL standardizedURL preserves empty path segments.
    while([path containsString:@"//"]) {
        path = [path stringByReplacingOccurrencesOfString:@"//" withString:@"/"];
    }

    if([path length] > 1) {
        if([path hasSuffix:@"/"]) {
            path = [path substringToIndex:[path length] - 1];
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
    return executablePathC ? @(executablePathC) : nil;
}

+ (NSString *)getBundleIdentifier {
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    return mainBundle ? (__bridge NSString *)CFBundleGetIdentifier(mainBundle) : nil;
}

+ (NSArray *)filterPathArray:(NSArray *)array restricted:(BOOL)restricted options:(NSDictionary<NSString *, id> *)options {
    Shadow* shadow = [Shadow sharedInstance];
    __block BOOL _restricted = restricted;

    NSIndexSet* indexes = [array indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL* stop) {
        if([obj isKindOfClass:[NSString class]]) {
            return [shadow isPathRestricted:obj options:options] == _restricted;
        }
        
        if([obj isKindOfClass:[NSURL class]]) {
            return [shadow isURLRestricted:obj options:options] == _restricted;
        }

        return NO;
    }];

    return [array objectsAtIndexes:indexes];
}

// C0-3: error factory for the file layer. Stock-looking NSCocoaErrorDomain
// errors with the standard file userInfo keys; path and/or url may be nil.
+ (NSError *)fileErrorWithCode:(NSInteger)code path:(NSString *)path url:(NSURL *)url {
    NSMutableDictionary* userInfo = [NSMutableDictionary new];

    if(path) {
        [userInfo setObject:path forKey:NSFilePathErrorKey];
    }

    if(url) {
        [userInfo setObject:url forKey:NSURLErrorKey];
    }

    return [NSError errorWithDomain:NSCocoaErrorDomain code:code userInfo:userInfo];
}

+ (NSError *)fileNoSuchFileErrorForPath:(NSString *)path {
    return [self fileErrorWithCode:NSFileNoSuchFileError path:path url:nil];
}

+ (NSError *)fileNoSuchFileErrorForURL:(NSURL *)url {
    return [self fileErrorWithCode:NSFileNoSuchFileError path:url ? [url path] : nil url:url];
}
@end
