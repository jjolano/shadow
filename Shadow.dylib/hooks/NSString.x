#import "hooks.h"

typedef void (^NSAttributedStringCompletionHandler)(NSAttributedString *, NSDictionary<NSAttributedStringDocumentAttributeKey, id> *, NSError *);

%group shadowhook_NSString
%hook NSString
- (instancetype)initWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        if(error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfURL:(NSURL *)url encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfURL:(NSURL *)url usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (NSUInteger)completePathIntoString:(NSString * _Nullable *)outputName caseSensitive:(BOOL)flag matchesIntoArray:(NSArray<NSString *> * _Nullable *)outputArray filterTypes:(NSArray<NSString *> *)filterTypes {
    if(isCallerTweak() || ![_shadow isPathRestricted:self]) {
        return %orig;
    }

    NSUInteger result = %orig;

    if(result && ([_shadow isPathRestricted:self] || (outputName && [_shadow isPathRestricted:*outputName]))) {
        if(outputName) {
            *outputName = nil;
        }

        if(outputArray) {
            *outputArray = nil;
        }
        
        return 0;
    }

    return result;
}

- (NSString *)stringByResolvingSymlinksInPath {
    NSString* result = %orig;

    if(!isCallerTweak() && [_shadow isPathRestricted:result]) {
        return self;
    }

    return result;
}

// - (NSString *)stringByExpandingTildeInPath {
//     NSString* result = %orig;

//     if(!isCallerTweak() && [_shadow isPathRestricted:result]) {
//         return self;
//     }

//     return result;
// }

- (NSString *)stringByStandardizingPath {
    NSString* result = %orig;

    if(!isCallerTweak() && [_shadow isPathRestricted:result]) {
        return self;
    }

    return result;
}
%end

%hook NSAttributedString
- (instancetype)initWithHTML:(NSData *)data baseURL:(NSURL *)base documentAttributes:(NSDictionary<NSAttributedStringDocumentAttributeKey, id> * _Nullable *)dict {
    if(!isCallerTweak() && [_shadow isURLRestricted:base]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithURL:(NSURL *)url options:(NSDictionary<NSAttributedStringDocumentReadingOptionKey, id> *)options documentAttributes:(NSDictionary<NSAttributedStringDocumentAttributeKey, id> * _Nullable *)dict error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (void)loadFromHTMLWithFileURL:(NSURL *)fileURL options:(NSDictionary<NSAttributedStringDocumentReadingOptionKey, id> *)options completionHandler:(NSAttributedStringCompletionHandler)completionHandler {
    if(!isCallerTweak() && [_shadow isURLRestricted:fileURL]) {
        if(completionHandler) {
            completionHandler(nil, nil, nil);
        }

        return;
    }

    %orig;
}
%end
%end

%group shadowhook_NSCharacterSet
%hook NSCharacterSet
+ (NSCharacterSet *)characterSetWithContentsOfFile:(NSString *)fName {
    if(!isCallerTweak() && [_shadow isPathRestricted:fName]) {
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
