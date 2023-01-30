#import "hooks.h"

%group shadowhook_NSURL
%hook NSURL
- (BOOL)checkResourceIsReachableAndReturnError:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:self] && !isCallerTweak()) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)checkPromisedItemIsReachableAndReturnError:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:self] && !isCallerTweak()) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return NO;
    }

    return %orig;
}

- (NSURL *)fileReferenceURL {
    if([_shadow isURLRestricted:self] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

+ (NSData *)bookmarkDataWithContentsOfURL:(NSURL *)bookmarkFileURL error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:bookmarkFileURL] && !isCallerTweak()) {
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
    if([_shadow isURLRestricted:url] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if([_shadow isURLRestricted:url] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithURL:(NSURL *)url {
    if([_shadow isURLRestricted:url] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSURL *location, NSURLResponse *response, NSError *error))completionHandler {
    if([_shadow isURLRestricted:url] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL {
    if([_shadow isURLRestricted:fileURL] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if([_shadow isURLRestricted:fileURL] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}
%end
%end

%group shadowhook_NSURLRequest
%hook NSURLRequest
+ (instancetype)requestWithURL:(NSURL *)URL {
    if([_shadow isURLRestricted:URL] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithURL:(NSURL *)URL {
    if([_shadow isURLRestricted:URL] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

+ (instancetype)requestWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
    if([_shadow isURLRestricted:URL] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
    if([_shadow isURLRestricted:URL] && !isCallerTweak()) {
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
