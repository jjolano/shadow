#import "hooks.h"

// Write intent for URL mutations: restricted-classified paths are denied
// even when the probe target does not exist (Core.m skips the existence
// gate for write operations).
static NSDictionary* _shdw_urlWriteOptions(void) {
    return @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};
}

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
    if(!isCallerExternal() && _shdw_resultURLRestricted(self)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)checkPromisedItemIsReachableAndReturnError:(NSError * _Nullable *)error {
    if(!isCallerExternal() && _shdw_resultURLRestricted(self)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)getPromisedItemResourceValue:(id  _Nullable *)value forKey:(NSURLResourceKey)key error:(NSError * _Nullable *)error {
    if(!isCallerExternal() && _shdw_resultURLRestricted(self)) {
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
    if(!isCallerExternal() && _shdw_resultURLRestricted(self)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return nil;
    }

    return %orig;
}

- (NSURL *)fileReferenceURL {
    NSURL* result = %orig;

    if(!isCallerExternal() && _shdw_resultURLRestricted(result)) {
        return nil;
    }

    return result;
}

- (NSURL *)filePathURL {
    NSURL* result = %orig;

    if(!isCallerExternal() && _shdw_resultURLRestricted(result)) {
        return nil;
    }

    return result;
}

- (NSURL *)URLByResolvingSymlinksInPath {
    NSURL* result = %orig;

    if(!isCallerExternal() && _shdw_resultURLRestricted(result)) {
        return nil;
    }

    return result;
}

- (NSURL *)URLByStandardizingPath {
    if(!isCallerExternal() && [_shadow isURLRestricted:self]) {
        return nil;
    }

    return %orig;
}

+ (NSData *)bookmarkDataWithContentsOfURL:(NSURL *)bookmarkFileURL error:(NSError * _Nullable *)error {
    if(!isCallerExternal() && [_shadow isURLRestricted:bookmarkFileURL]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:bookmarkFileURL];
        }

        return nil;
    }

    return %orig;
}

- (BOOL)getResourceValue:(id _Nullable *)value forKey:(NSURLResourceKey)key error:(NSError * _Nullable *)error {
    if(!isCallerExternal() && _shdw_resultURLRestricted(self)) {
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
    if(!isCallerExternal() && _shdw_resultURLRestricted(self)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return nil;
    }

    return %orig;
}

- (BOOL)setResourceValue:(id)value forKey:(NSURLResourceKey)key error:(NSError * _Nullable *)error {
    if(!isCallerExternal() && _shdw_resultURLRestrictedWithOptions(self, _shdw_urlWriteOptions())) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:self];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)setResourceValues:(NSDictionary<NSURLResourceKey, id> *)keyedValues error:(NSError * _Nullable *)error {
    if(!isCallerExternal() && _shdw_resultURLRestrictedWithOptions(self, _shdw_urlWriteOptions())) {
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
    if(!isCallerExternal() && _shdw_resultURLRestricted(self)) {
        return;
    }

    %orig;
}

- (void)removeAllCachedResourceValues {
    if(!isCallerExternal() && _shdw_resultURLRestricted(self)) {
        return;
    }

    %orig;
}

- (void)setTemporaryResourceValue:(id)value forKey:(NSURLResourceKey)key {
    if(!isCallerExternal() && _shdw_resultURLRestricted(self)) {
        return;
    }

    %orig;
}

- (instancetype)initByResolvingBookmarkData:(NSData *)bookmarkData options:(NSURLBookmarkResolutionOptions)options relativeToURL:(NSURL *)relativeURL bookmarkDataIsStale:(BOOL *)isStale error:(NSError * _Nullable *)error {
    self = %orig;

    if(!isCallerExternal() && self && _shdw_resultURLRestricted(self)) {
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

    if(!isCallerExternal() && _shdw_resultURLRestricted(result)) {
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

    if(!isCallerExternal() && result) {
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

%group shadowhook_NSURLSession
%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url {
    if(!isCallerExternal() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if(!isCallerExternal() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithURL:(NSURL *)url {
    if(!isCallerExternal() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSURL *location, NSURLResponse *response, NSError *error))completionHandler {
    if(!isCallerExternal() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL {
    if(!isCallerExternal() && [_shadow isURLRestricted:fileURL]) {
        return nil;
    }

    return %orig;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if(!isCallerExternal() && [_shadow isURLRestricted:fileURL]) {
        return nil;
    }

    return %orig;
}
%end
%end

%group shadowhook_NSURLRequest
%hook NSURLRequest
+ (instancetype)requestWithURL:(NSURL *)URL {
    if(!isCallerExternal() && [_shadow isURLRestricted:URL]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithURL:(NSURL *)URL {
    if(!isCallerExternal() && [_shadow isURLRestricted:URL]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)requestWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
    if(!isCallerExternal() && [_shadow isURLRestricted:URL]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
    if(!isCallerExternal() && [_shadow isURLRestricted:URL]) {
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
