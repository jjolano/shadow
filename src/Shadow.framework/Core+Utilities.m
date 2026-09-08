#import <Shadow/Core+Utilities.h>
#import <string.h>

#import "../../vendor/apple/dyld_priv.h"

extern char*** _NSGetArgv();

@implementation Shadow (Utilities)

+ (NSString *)getStandardizedPath:(NSString *)path {
    if(!path) {
        return path;
    }

    // Plain absolute paths need no URL parsing. Keep dot/empty components,
    // trailing slashes, percent escapes and URL punctuation on the slow
    // path. Only URL-safe ASCII root aliases are rewritten directly.
    if([path hasPrefix:@"/"]
        && ![path hasSuffix:@"/"]
        && ![path containsString:@"/."]
        && ![path containsString:@"//"]
        && ![path containsString:@"%"]
        && ![path containsString:@"?"]
        && ![path containsString:@"#"]
        && ![path containsString:@";"]) {
        BOOL aliasPrefix = [path hasPrefix:@"/private/var"]
            || [path hasPrefix:@"/private/etc"]
            || [path hasPrefix:@"/var/tmp"];
        if(!aliasPrefix) return path;

        // Only bypass NSURL for URL-safe ASCII. Keep spaces, controls,
        // Unicode and embedded NULs on the existing alias slow path.
        const char* ascii = [path cStringUsingEncoding:NSASCIIStringEncoding];
        if(ascii && strspn(ascii,
            "/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,=:@") == path.length) {
            if([path isEqualToString:@"/private/var"] || [path hasPrefix:@"/private/var/"] ||
               [path isEqualToString:@"/private/etc"] || [path hasPrefix:@"/private/etc/"]) {
                path = [path substringFromIndex:8];
            }
            // Independent check: /private/var/tmp also maps to /tmp.
            if([path isEqualToString:@"/var/tmp"] || [path hasPrefix:@"/var/tmp/"]) {
                path = [path substringFromIndex:4];
            }
            // Preserve Foundation's path representation for later path operations.
            return [NSString pathWithComponents:[path pathComponents]];
        }
    }

    // Darwin NSURL pitfalls for adversarial absolute input: "//x" parses
    // "x" as an authority (standardizedURL then drops it), "/../x" comes
    // back RELATIVE, and "/.//x" cascades through both. Collapse slash/dot
    // degeneracies to a fixpoint before handing off — the collapses feed
    // each other ("/./.." -> "/.." -> "/", "//../x" -> "/../x" -> "/x") —
    // NSURL keeps the remaining legitimate work (percent decoding, ?/#
    // stripping, interior dot segments).
    if([path hasPrefix:@"/"]) {
        NSString* previous = nil;
        while(![path isEqualToString:previous]) {
            previous = path;
            while([path hasPrefix:@"/../"]) {
                path = [path substringFromIndex:3];
            }
            if([path isEqualToString:@"/.."]) {
                path = @"/";
            }
            while([path containsString:@"//"]) {
                path = [path stringByReplacingOccurrencesOfString:@"//" withString:@"/"];
            }
            while([path containsString:@"/./"]) {
                path = [path stringByReplacingOccurrencesOfString:@"/./" withString:@"/"];
            }
        }
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

    if([path isEqualToString:@"/private/var"] || [path hasPrefix:@"/private/var/"] ||
       [path isEqualToString:@"/private/etc"] || [path hasPrefix:@"/private/etc/"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    if([path isEqualToString:@"/var/tmp"] || [path hasPrefix:@"/var/tmp/"]) {
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
