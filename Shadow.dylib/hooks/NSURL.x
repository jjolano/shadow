#import "hooks.h"

%group shadowhook_NSURL
%hook NSURL
- (BOOL)checkResourceIsReachableAndReturnError:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:self]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)checkPromisedItemIsReachableAndReturnError:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:self]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)getPromisedItemResourceValue:(id  _Nullable *)value forKey:(NSURLResourceKey)key error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:self]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (NSDictionary<NSURLResourceKey, id> *)promisedItemResourceValuesForKeys:(NSArray<NSURLResourceKey> *)keys error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:self]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (NSURL *)fileReferenceURL {
    if(!isCallerTweak() && [_shadow isURLRestricted:self]) {
        return nil;
    }

    return %orig;
}

- (NSURL *)filePathURL {
    if(!isCallerTweak() && [_shadow isURLRestricted:self]) {
        return nil;
    }

    return %orig;
}

- (NSURL *)URLByResolvingSymlinksInPath {
    if(!isCallerTweak() && [_shadow isURLRestricted:self]) {
        return nil;
    }

    return %orig;
}

- (NSURL *)URLByStandardizingPath {
    if(!isCallerTweak() && [_shadow isURLRestricted:self]) {
        return nil;
    }

    return %orig;
}

+ (NSData *)bookmarkDataWithContentsOfURL:(NSURL *)bookmarkFileURL error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:bookmarkFileURL]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}
%end
%end

%group shadowhook_NSURLSession
%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSURL *location, NSURLResponse *response, NSError *error))completionHandler {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL {
    if(!isCallerTweak() && [_shadow isURLRestricted:fileURL]) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if(!isCallerTweak() && [_shadow isURLRestricted:fileURL]) {
        return nil;
    }

    return %orig;
}
%end
%end

%group shadowhook_NSURLRequest
%hook NSURLRequest
+ (instancetype)requestWithURL:(NSURL *)URL {
    if(!isCallerTweak() && [_shadow isURLRestricted:URL]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithURL:(NSURL *)URL {
    if(!isCallerTweak() && [_shadow isURLRestricted:URL]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)requestWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
    if(!isCallerTweak() && [_shadow isURLRestricted:URL]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
    if(!isCallerTweak() && [_shadow isURLRestricted:URL]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSURL(HKSubstitutor* hooks) {
    %init(shadowhook_NSURL);
    %init(shadowhook_NSURLRequest);
    %init(shadowhook_NSURLSession);
}
