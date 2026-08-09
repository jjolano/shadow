#import "hooks.h"

typedef void (^NSAttributedStringCompletionHandler)(NSAttributedString *, NSDictionary<NSAttributedStringDocumentAttributeKey, id> *, NSError *);

// Stock-shaped NSURLError for blocked URL reads: domain/code plus the
// standard userInfo keys (NSURLErrorKey + NSFilePathErrorKey). Boxed errors
// without the keys diverge from what a stock device answers for the same
// query and are a fingerprint for a detector that parses error.userInfo.
static NSError* _shdw_urlReadError(NSURL* url) {
    NSMutableDictionary* userInfo = [NSMutableDictionary new];

    if(url) {
        userInfo[NSURLErrorKey] = url;

        NSString* path = [url path];

        if(path) {
            userInfo[NSFilePathErrorKey] = path;
        }
    }

    return [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:userInfo];
}

%group shadowhook_NSString
%hook NSString
- (instancetype)initWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isPathRestricted:path]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isPathRestricted:path]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isPathRestricted:path]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isPathRestricted:path]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfURL:(NSURL *)url encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = _shdw_urlReadError(url);
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = _shdw_urlReadError(url);
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfURL:(NSURL *)url usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = _shdw_urlReadError(url);
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = _shdw_urlReadError(url);
        }

        return nil;
    }

    return %orig;
}

- (NSUInteger)completePathIntoString:(NSString * _Nullable *)outputName caseSensitive:(BOOL)flag matchesIntoArray:(NSArray<NSString *> * _Nullable *)outputArray filterTypes:(NSArray<NSString *> *)filterTypes {
    // Always consult the original — a partial-prefix probe can return
    // restricted candidates even when the receiver itself is benign. The
    // candidates are filtered afterwards and the common completion is
    // recomputed from the survivors.
    NSUInteger result = %orig;

    if(!isCallerExternal()) {
        return result;
    }

    NSArray<NSString *>* matches = (outputArray && *outputArray) ? *outputArray : nil;

    if(result > 0 && matches.count > 0) {
        NSMutableArray<NSString *>* result_filtered = [NSMutableArray arrayWithCapacity:matches.count];

        for(NSString* candidate in matches) {
            if(![_shadow isPathRestricted:candidate]) {
                [result_filtered addObject:candidate];
            }
        }

        if(result_filtered.count == 0) {
            if(outputArray) {
                *outputArray = @[];
            }

            if(outputName) {
                *outputName = nil;
            }

            return 0;
        }

        if(outputArray) {
            *outputArray = result_filtered;
        }

        if(outputName) {
            // Recompute the safe common completion (longest common prefix,
            // honoring the case-sensitivity flag) from the survivors.
            NSString* prefix = result_filtered[0];

            for(NSUInteger i = 1; i < result_filtered.count && prefix.length > 0; i++) {
                prefix = [prefix commonPrefixWithString:result_filtered[i] options:(flag ? 0 : NSCaseInsensitiveSearch)];
            }

            *outputName = prefix;
        }

        return result_filtered.count;
    }

    return result;
}

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(error) {
            *error = [Shadow fileErrorWithCode:NSFileWriteUnknownError path:path url:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)useAuxiliaryFile encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(error) {
            *error = [Shadow fileErrorWithCode:NSFileWriteUnknownError path:[url path] url:url];
        }

        return NO;
    }

    return %orig;
}

- (NSString *)stringByResolvingSymlinksInPath {
    NSString* result = %orig;

    if(isCallerExternal() && [_shadow isPathRestricted:result]) {
        // Stock shape for a path that does not resolve on a stock device:
        // the input, lexically standardized, with no symlink resolution.
        // (Resolution of a restricted path is what would leak the preboot/
        // jbroot target; returning the raw unresolved self would leave a
        // ".."-containing intermediate, which stock never produces.)
        return [self stringByStandardizingPath];
    }

    return result;
}

// - (NSString *)stringByExpandingTildeInPath {
//     NSString* result = %orig;

//     if(isCallerExternal() && [_shadow isPathRestricted:result]) {
//         return self;
//     }

//     return result;
// }

- (NSString *)stringByStandardizingPath {
    // Pure lexical normalization — ".." collapsing and duplicate-slash
    // removal — whose output carries no information beyond the receiver, so
    // no restriction check (a filtered value here is a stock-impossible
    // answer for the exact query the detector constructed).
    return %orig;
}
%end

%hook NSAttributedString
- (instancetype)initWithHTML:(NSData *)data baseURL:(NSURL *)base documentAttributes:(NSDictionary<NSAttributedStringDocumentAttributeKey, id> * _Nullable *)dict {
    if(isCallerExternal() && [_shadow isURLRestricted:base]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithURL:(NSURL *)url options:(NSDictionary<NSAttributedStringDocumentReadingOptionKey, id> *)options documentAttributes:(NSDictionary<NSAttributedStringDocumentAttributeKey, id> * _Nullable *)dict error:(NSError * _Nullable *)error {
    if(isCallerExternal()) {
        // NSReadAccessURLDocumentOption isn't declared in the SDK's UIKit
        // stubs; the runtime constant is the literal string.
        NSURL* readAccessURL = options[@"NSReadAccessURLDocumentOption"];

        if([_shadow isURLRestricted:url] || (readAccessURL && [_shadow isURLRestricted:readAccessURL])) {
            if(error) {
                *error = _shdw_urlReadError(url);
            }

            return nil;
        }
    }

    return %orig;
}

+ (void)loadFromHTMLWithFileURL:(NSURL *)fileURL options:(NSDictionary<NSAttributedStringDocumentReadingOptionKey, id> *)options completionHandler:(NSAttributedStringCompletionHandler)completionHandler {
    if(isCallerExternal() && [_shadow isURLRestricted:fileURL]) {
        if(completionHandler) {
            // Async contract: blocked-path failures are never delivered
            // inline — dispatch the (nil, nil, error) result to a background
            // queue exactly like the WebKit loader would.
            NSError* error = _shdw_urlReadError(fileURL);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                completionHandler(nil, nil, error);
            });
        }

        return;
    }

    %orig;
}

+ (void)loadFromHTMLWithRequest:(NSURLRequest *)request options:(NSDictionary<NSAttributedStringDocumentReadingOptionKey, id> *)options completionHandler:(NSAttributedStringCompletionHandler)completionHandler {
    if(isCallerExternal() && request && [_shadow isURLRestricted:[request URL]]) {
        if(completionHandler) {
            NSError* error = _shdw_urlReadError([request URL]);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                completionHandler(nil, nil, error);
            });
        }

        return;
    }

    %orig;
}

+ (void)loadFromHTMLWithString:(NSString *)string options:(NSDictionary<NSAttributedStringDocumentReadingOptionKey, id> *)options completionHandler:(NSAttributedStringCompletionHandler)completionHandler {
    if(isCallerExternal()) {
        // String loads carry their base URL in the options dictionary;
        // NSBaseURLDocumentOption isn't declared in the SDK stubs, so the
        // runtime constant is used literally.
        NSURL* baseURL = options[@"NSBaseURLDocumentOption"];

        if(baseURL && [_shadow isURLRestricted:baseURL]) {
            if(completionHandler) {
                NSError* error = _shdw_urlReadError(baseURL);
                dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                    completionHandler(nil, nil, error);
                });
            }

            return;
        }
    }

    %orig;
}
%end
%end

%group shadowhook_NSCharacterSet
%hook NSCharacterSet
+ (NSCharacterSet *)characterSetWithContentsOfFile:(NSString *)fName {
    if(isCallerExternal() && [_shadow isPathRestricted:fName]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSMutableCharacterSet
+ (NSMutableCharacterSet *)characterSetWithContentsOfFile:(NSString *)fName {
    if(isCallerExternal() && [_shadow isPathRestricted:fName]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSString(HKSubstitutor* hooks) {
    %init(shadowhook_NSString);
    %init(shadowhook_NSCharacterSet);
}
