#import "hooks.h"

// Classify a RESULT URL after %orig. Plain file URLs classify directly;
// file-reference URLs do not — Core.m resolves them through -filePathURL,
// whose hook returns nil for a restricted reference, so a reference that
// resolves to nil (or to a restricted path) is itself restricted. An
// allowed alias resolving to /var/jb must not be returned.
static BOOL _shdw_resultURLRestrictedWithOptions(NSURL* result, NSDictionary* options) {
    if(!result) {
        return NO;
    }

    if([_shadow isURLRestricted:result options:options]) {
        return YES;
    }

    if([result isFileReferenceURL]) {
        NSURL* resolved = [result filePathURL];

        if(!resolved || [_shadow isURLRestricted:resolved options:options]) {
            return YES;
        }
    }

    return NO;
}

static BOOL _shdw_resultURLRestricted(NSURL* result) {
    return _shdw_resultURLRestrictedWithOptions(result, nil);
}

%group shadowhook_NSURL
%hook NSURL
- (BOOL)checkResourceIsReachableAndReturnError:(NSError * _Nullable *)error {
    if(isCallerExternal() && _shdw_resultURLRestricted(self)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)checkPromisedItemIsReachableAndReturnError:(NSError * _Nullable *)error {
    if(isCallerExternal() && _shdw_resultURLRestricted(self)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)getPromisedItemResourceValue:(id  _Nullable *)value forKey:(NSURLResourceKey)key error:(NSError * _Nullable *)error {
    if(isCallerExternal() && _shdw_resultURLRestricted(self)) {
        if(value) {
            *value = nil;
        }

        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return NO;
    }

    return %orig;
}

- (NSDictionary<NSURLResourceKey, id> *)promisedItemResourceValuesForKeys:(NSArray<NSURLResourceKey> *)keys error:(NSError * _Nullable *)error {
    if(isCallerExternal() && _shdw_resultURLRestricted(self)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return nil;
    }

    return %orig;
}

- (NSURL *)fileReferenceURL {
    NSURL* result = %orig;

    if(isCallerExternal() && _shdw_resultURLRestricted(result)) {
        return nil;
    }

    return result;
}

- (NSURL *)filePathURL {
    NSURL* result = %orig;

    if(isCallerExternal() && _shdw_resultURLRestricted(result)) {
        return nil;
    }

    return result;
}

- (NSURL *)URLByResolvingSymlinksInPath {
    NSURL* result = %orig;

    if(isCallerExternal() && _shdw_resultURLRestricted(result)) {
        // Stock shape for a path that does not resolve on a stock device:
        // the receiver, lexically standardized, with no symlink resolution
        // (resolving a restricted path is what leaks the preboot/jbroot
        // target). Matches -[NSString stringByResolvingSymlinksInPath].
        return [self URLByStandardizingPath];
    }

    return result;
}

- (NSURL *)URLByStandardizingPath {
    // Pure lexical normalization — the output carries no information beyond
    // the receiver — so no restriction check (a filtered value here is a
    // stock-impossible answer for the query the detector constructed).
    return %orig;
}

+ (NSData *)bookmarkDataWithContentsOfURL:(NSURL *)bookmarkFileURL error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:bookmarkFileURL]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:bookmarkFileURL];
        }

        return nil;
    }

    return %orig;
}

- (BOOL)getResourceValue:(id _Nullable *)value forKey:(NSURLResourceKey)key error:(NSError * _Nullable *)error {
    if(isCallerExternal() && _shdw_resultURLRestricted(self)) {
        if(value) {
            *value = nil;
        }

        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return NO;
    }

    return %orig;
}

- (NSDictionary<NSURLResourceKey, id> *)resourceValuesForKeys:(NSArray<NSURLResourceKey> *)keys error:(NSError * _Nullable *)error {
    if(isCallerExternal() && _shdw_resultURLRestricted(self)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return nil;
    }

    return %orig;
}

- (BOOL)setResourceValue:(id)value forKey:(NSURLResourceKey)key error:(NSError * _Nullable *)error {
    if(isCallerExternal() && _shdw_resultURLRestrictedWithOptions(self, shdw_restriction_write_options())) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)setResourceValues:(NSDictionary<NSURLResourceKey, id> *)keyedValues error:(NSError * _Nullable *)error {
    if(isCallerExternal() && _shdw_resultURLRestrictedWithOptions(self, shdw_restriction_write_options())) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return NO;
    }

    return %orig;
}

// Cache-mutation APIs: no-ops for restricted URLs — the value cache of a
// hidden resource must not be observable or manipulable.
- (void)removeCachedResourceValueForKey:(NSURLResourceKey)key {
    if(isCallerExternal() && _shdw_resultURLRestricted(self)) {
        return;
    }

    %orig;
}

- (void)removeAllCachedResourceValues {
    if(isCallerExternal() && _shdw_resultURLRestricted(self)) {
        return;
    }

    %orig;
}

- (void)setTemporaryResourceValue:(id)value forKey:(NSURLResourceKey)key {
    if(isCallerExternal() && _shdw_resultURLRestricted(self)) {
        return;
    }

    %orig;
}

- (instancetype)initByResolvingBookmarkData:(NSData *)bookmarkData options:(NSURLBookmarkResolutionOptions)options relativeToURL:(NSURL *)relativeURL bookmarkDataIsStale:(BOOL *)isStale error:(NSError * _Nullable *)error {
    self = %orig;

    if(isCallerExternal() && self && _shdw_resultURLRestricted(self)) {
        // Clear the stale/output values: a denied resolution reports neither
        // staleness nor a URL.
        if(isStale) {
            *isStale = NO;
        }

        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return nil;
    }

    return self;
}

+ (NSURL *)URLByResolvingBookmarkData:(NSData *)bookmarkData options:(NSURLBookmarkResolutionOptions)options relativeToURL:(NSURL *)relativeURL bookmarkDataIsStale:(BOOL *)isStale error:(NSError * _Nullable *)error {
    NSURL* result = %orig;

    if(isCallerExternal() && _shdw_resultURLRestricted(result)) {
        if(isStale) {
            *isStale = NO;
        }

        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:result];
        }

        return nil;
    }

    return result;
}

+ (NSDictionary<NSURLResourceKey, id> *)resourceValuesForKeys:(NSArray<NSURLResourceKey> *)keys fromBookmarkData:(NSData *)bookmarkData {
    NSDictionary* result = %orig;

    if(isCallerExternal() && result) {
        // No URL output to classify; resolve the bookmark through our own
        // (hooked) resolver — nil means the target is unresolvable or
        // restricted, so the values are hidden too.
        NSURL* resolved = [NSURL URLByResolvingBookmarkData:bookmarkData options:0 relativeToURL:nil bookmarkDataIsStale:NULL error:NULL];

        if(!resolved) {
            return nil;
        }
    }

    return result;
}
%end
%end

// Disabled: Firebase Performance and similar SDKs instrument NSURLSession at
// launch; chaining another method instrumentor here makes their selector
// registry abort. Keep the implementation for a later late-install design.
#if 0
%group shadowhook_NSURLSession
%hook NSURLSession
// Blocked-task helper (C0-3): create a REAL suspended task via %orig, wrap
// its completion so the caller gets exactly one asynchronous
// NSURLErrorFileDoesNotExist delivery, cancel the task before any I/O, and
// return the native task — never nil, per the NSURLSession nonnull contract.
// The wrapper swallows whatever the session later reports (cancellation) so
// the caller's handler fires exactly once, from our dispatch. Non-completion
// variants return the cancelled task: its failure surfaces through the
// delegate callbacks per the NSURLSession contract.
static NSError* _shdw_sessionBlockedError(void) {
    return [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
}

static BOOL _shdw_requestRestricted(NSURLRequest* request) {
    return request && [_shadow isURLRestricted:[request URL]];
}

static void _shdw_deliverBlockedCompletion(void (^completionHandler)(void)) {
    if(completionHandler) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), completionHandler);
    }
}

- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        NSURLSessionDataTask* task = %orig;
        [task cancel];

        return task;
    }

    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        NSURLSessionDataTask* task = %orig(url, ^(NSData *data, NSURLResponse *response, NSError *error) {
            // swallow — the blocked completion below is the only one delivered
        });

        [task cancel];

        _shdw_deliverBlockedCompletion(^{
            completionHandler(nil, nil, _shdw_sessionBlockedError());
        });

        return task;
    }

    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithURL:(NSURL *)url {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        NSURLSessionDownloadTask* task = %orig;
        [task cancel];

        return task;
    }

    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSURL *location, NSURLResponse *response, NSError *error))completionHandler {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        NSURLSessionDownloadTask* task = %orig(url, ^(NSURL *location, NSURLResponse *response, NSError *error) {
            // swallow
        });

        [task cancel];

        _shdw_deliverBlockedCompletion(^{
            completionHandler(nil, nil, _shdw_sessionBlockedError());
        });

        return task;
    }

    return %orig;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL {
    if(isCallerExternal() && (_shdw_requestRestricted(request) || [_shadow isURLRestricted:fileURL])) {
        NSURLSessionUploadTask* task = %orig;
        [task cancel];

        return task;
    }

    return %orig;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if(isCallerExternal() && (_shdw_requestRestricted(request) || [_shadow isURLRestricted:fileURL])) {
        NSURLSessionUploadTask* task = %orig(request, fileURL, ^(NSData *data, NSURLResponse *response, NSError *error) {
            // swallow
        });

        [task cancel];

        _shdw_deliverBlockedCompletion(^{
            completionHandler(nil, nil, _shdw_sessionBlockedError());
        });

        return task;
    }

    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request {
    if(isCallerExternal() && _shdw_requestRestricted(request)) {
        NSURLSessionDataTask* task = %orig;
        [task cancel];

        return task;
    }

    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if(isCallerExternal() && _shdw_requestRestricted(request)) {
        NSURLSessionDataTask* task = %orig(request, ^(NSData *data, NSURLResponse *response, NSError *error) {
            // swallow
        });

        [task cancel];

        _shdw_deliverBlockedCompletion(^{
            completionHandler(nil, nil, _shdw_sessionBlockedError());
        });

        return task;
    }

    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)request {
    if(isCallerExternal() && _shdw_requestRestricted(request)) {
        NSURLSessionDownloadTask* task = %orig;
        [task cancel];

        return task;
    }

    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURL *location, NSURLResponse *response, NSError *error))completionHandler {
    if(isCallerExternal() && _shdw_requestRestricted(request)) {
        NSURLSessionDownloadTask* task = %orig(request, ^(NSURL *location, NSURLResponse *response, NSError *error) {
            // swallow
        });

        [task cancel];

        _shdw_deliverBlockedCompletion(^{
            completionHandler(nil, nil, _shdw_sessionBlockedError());
        });

        return task;
    }

    return %orig;
}
%end
%end
#endif

void shadowhook_NSURL(HKSubstitutor* hooks) {
    %init(shadowhook_NSURL);
    // ponytail: NSURLSession hiding is disabled; add a post-instrumentation
    // install path if preserving this coverage becomes necessary.
}
