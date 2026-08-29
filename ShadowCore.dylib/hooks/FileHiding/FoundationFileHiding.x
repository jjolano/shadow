// Foundation file/URL read-write restriction hooks (merged: NSArray, NSDictionary, NSData, NSFileHandle, NSFileWrapper, NSFileVersion, NSTask).
// Entry functions keep their per-group names — dylib.x's installer table calls them individually.
#import "hooks.h"

%group shadowhook_NSArray
%hook NSArray
- (id)initWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

- (NSArray *)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

+ (NSArray *)arrayWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(error) {
            *error = [Shadow fileErrorWithCode:NSFileWriteUnknownError path:[url path] url:url];
        }

        return NO;
    }

    return %orig;
}
%end

%hook NSMutableArray
- (id)initWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}
%end
%end

void shadowhook_NSArray(SHDWHookSession* hooks) {
    %init(shadowhook_NSArray);
}

%group shadowhook_NSDictionary
%hook NSDictionary
- (id)initWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(error) {
            *error = [Shadow fileErrorWithCode:NSFileWriteUnknownError path:[url path] url:url];
        }

        return NO;
    }

    return %orig;
}
%end

%hook NSMutableDictionary
- (id)initWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (NSMutableDictionary *)dictionaryWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (NSMutableDictionary *)dictionaryWithContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}
%end
%end

void shadowhook_NSDictionary(SHDWHookSession* hooks) {
    %init(shadowhook_NSDictionary);
}

%group shadowhook_NSData
%hook NSData
+ (instancetype)dataWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfMappedFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (id)dataWithContentsOfMappedFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToFile:(NSString *)path options:(NSDataWritingOptions)writeOptionsMask error:(NSError * _Nullable *)errorPtr __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileErrorWithCode:NSFileWriteUnknownError path:path url:nil];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSDataWritingOptions)writeOptionsMask error:(NSError * _Nullable *)errorPtr __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(errorPtr) {
            *errorPtr = [Shadow fileErrorWithCode:NSFileWriteUnknownError path:[url path] url:url];
        }

        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSData(SHDWHookSession* hooks) {
    %init(shadowhook_NSData);
}

%group shadowhook_NSFileHandle
%hook NSFileHandle
// fd-based surfaces: resolve the fd to a path via F_GETPATH. The call
// fails (EBADF, ENOTSUP) for pipes/sockets/other non-files — those pass
// through untouched. `options` is the restriction op for the surface:
// shdw_restriction_write_options() for write surfaces, nil for reads.
static BOOL shdw_fd_is_restricted(int fd, NSDictionary* options) {
    char pathname[PATH_MAX];

    if(fcntl(fd, F_GETPATH, pathname) == -1) {
        return NO;
    }

    return [_shadow isPathRestricted:@(pathname) options:options];
}

- (instancetype)initWithFileDescriptor:(int)fd closeOnDealloc:(BOOL)closeOpt __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_fd_is_restricted(fd, shdw_restriction_write_options())) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithFileDescriptor:(int)fd __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_fd_is_restricted(fd, shdw_restriction_write_options())) {
        return nil;
    }

    return %orig;
}

- (int)fileDescriptor __attribute__((annotate("hookkit:allow_inherited"))) {
    // %orig is a pure getter; safe to evaluate in the gate and pass through.
    int fd = %orig;

    if(isCallerExternal() && shdw_fd_is_restricted(fd, shdw_restriction_write_options())) {
        return -1;
    }

    return fd;
}

- (NSData *)readDataToEndOfFile __attribute__((annotate("hookkit:allow_inherited"))) {
    // [self fileDescriptor] resolves the real fd: the fileDescriptor hook
    // passes Shadow's own caller (this hook body) through untouched.
    if(isCallerExternal() && shdw_fd_is_restricted([self fileDescriptor], nil)) {
        return [NSData data];
    }

    return %orig;
}

- (NSData *)readDataOfLength:(NSUInteger)length __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_fd_is_restricted([self fileDescriptor], nil)) {
        return [NSData data];
    }

    return %orig;
}

- (NSData *)availableData __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_fd_is_restricted([self fileDescriptor], nil)) {
        return [NSData data];
    }

    return %orig;
}

- (void)writeData:(NSData *)data __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_fd_is_restricted([self fileDescriptor], shdw_restriction_write_options())) {
        return;
    }

    return %orig;
}

+ (instancetype)fileHandleForReadingAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);
    
    return %orig;
}

+ (instancetype)fileHandleForReadingFromURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }
        
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForWritingAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:shdw_restriction_write_options()]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForWritingToURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:shdw_restriction_write_options()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }
        
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForUpdatingAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:shdw_restriction_write_options()]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForUpdatingURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:shdw_restriction_write_options()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }
        
        return nil;
    }
    
    return %orig;
}
%end
%end

void shadowhook_NSFileHandle(SHDWHookSession* hooks) {
    %init(shadowhook_NSFileHandle);
}

// Source-URL association: initWithURL:/readFromURL: record the wrapper's
// source URL so the tree accessors (fileWrappers, regularFileContents,
// symbolicLinkDestinationURL, serializedRepresentation) and
// writeToURL:originalContentsURL: can enforce containment on wrappers
// descended from a restricted source.
static const void* _NSFileWrapper_shdw_source_url_key = &_NSFileWrapper_shdw_source_url_key;

static NSURL* shdw_wrapper_source_url(NSFileWrapper* w) {
    return objc_getAssociatedObject(w, _NSFileWrapper_shdw_source_url_key);
}

static BOOL shdw_wrapper_source_restricted(NSFileWrapper* w) {
    NSURL* url = shdw_wrapper_source_url(w);

    return url && [_shadow isURLRestricted:url];
}

%group shadowhook_NSFileWrapper
%hook NSFileWrapper
- (instancetype)initWithURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return 0;
    }

    self = %orig;

    if(self) {
        objc_setAssociatedObject(self, _NSFileWrapper_shdw_source_url_key, url, OBJC_ASSOCIATION_COPY_NONATOMIC);
    }

    return self;
}

// initSymbolicLinkWithDestinationURL: intentionally NOT hooked — it only
// records the destination (no I/O at construction, so nothing can leak) and
// stock never returns nil from it, so a filtered nil would be a
// stock-impossible answer for the exact value the caller supplied.

- (BOOL)matchesContentsOfURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}

- (BOOL)readFromURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(outError) {
            *outError = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    BOOL result = %orig;

    if(result) {
        objc_setAssociatedObject(self, _NSFileWrapper_shdw_source_url_key, url, OBJC_ASSOCIATION_COPY_NONATOMIC);
    }

    return result;
}

- (NSDictionary<NSString *,NSFileWrapper *> *)fileWrappers __attribute__((annotate("hookkit:allow_inherited"))) {
    NSDictionary<NSString *,NSFileWrapper *> *result = %orig;

    if(result && isCallerExternal()) {
        NSMutableDictionary<NSString *,NSFileWrapper *> *filtered = [NSMutableDictionary dictionaryWithCapacity:[result count]];

        for(NSString* name in result) {
            NSFileWrapper* child = result[name];

            if(!shdw_wrapper_source_restricted(child)) {
                filtered[name] = child;
            }
        }

        result = filtered;
    }

    return result;
}

- (NSData *)regularFileContents __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_wrapper_source_restricted(self)) {
        return nil;
    }

    return %orig;
}

- (NSURL *)symbolicLinkDestinationURL __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_wrapper_source_restricted(self)) {
        return nil;
    }

    return %orig;
}

- (NSData *)serializedRepresentation __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_wrapper_source_restricted(self)) {
        return nil;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSFileWrapperWritingOptions)options originalContentsURL:(NSURL *)originalContentsURL error:(NSError * _Nullable *)outError __attribute__((annotate("hookkit:allow_inherited"))) {
    NSDictionary* writeOptions = shdw_restriction_write_options();

    if(isCallerExternal() && ([_shadow isURLRestricted:url options:writeOptions] || [_shadow isURLRestricted:originalContentsURL])) {
        if(outError) {
            *outError = [Shadow fileNoSuchFileErrorForURL:originalContentsURL];
        }

        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSFileWrapper(SHDWHookSession* hooks) {
    %init(shadowhook_NSFileWrapper);
}

// Drop versions whose real URL is hidden: the -URL hook already returns nil
// for restricted versions, so nil is a denial signal in either direction
// (filtered answer for external callers, truthful answer for Shadow's own).
static NSArray* _shdw_filterVersionArray(NSArray* versions) {
    NSMutableArray* filtered = [NSMutableArray arrayWithCapacity:[versions count]];

    for(NSFileVersion* version in versions) {
        NSURL* url = [version URL];

        if(url && ![_shadow isURLRestricted:url]) {
            [filtered addObject:version];
        }
    }

    return filtered;
}

%group shadowhook_NSFileVersion
%hook NSFileVersion
+ (NSFileVersion *)currentVersionOfItemAtURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (NSArray<NSFileVersion *> *)otherVersionsOfItemAtURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    NSArray* result = %orig;

    if(result && isCallerExternal()) {
        result = _shdw_filterVersionArray(result);
    }

    return result;
}

+ (NSFileVersion *)versionOfItemAtURL:(NSURL *)url forPersistentIdentifier:(id)persistentIdentifier __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (NSURL *)temporaryDirectoryURLForNewVersionOfItemAtURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    return %orig;
}

+ (NSFileVersion *)addVersionOfItemAtURL:(NSURL *)url withContentsOfURL:(NSURL *)contentsURL options:(NSFileVersionAddingOptions)options error:(NSError * _Nullable *)outError __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        // The versioned item is written; the contents source is read.
        NSDictionary* writeOptions = @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};

        if([_shadow isURLRestricted:url options:writeOptions] || [_shadow isURLRestricted:contentsURL]) {
            if(outError) {
                *outError = [Shadow fileNoSuchFileErrorForURL:url];
            }

            return nil;
        }
    }

    return %orig;
}

+ (NSArray<NSFileVersion *> *)unresolvedConflictVersionsOfItemAtURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);

    NSArray* result = %orig;

    if(result && isCallerExternal()) {
        result = _shdw_filterVersionArray(result);
    }

    return result;
}

// The receiver's real location: hidden versions report nil so a version
// object obtained before a ruleset change (or via an unfiltered path)
// cannot disclose its file.
- (NSURL *)URL __attribute__((annotate("hookkit:allow_inherited"))) {
    NSURL* result = %orig;

    if(isCallerExternal() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSURL *)replaceItemAtURL:(NSURL *)url options:(NSFileVersionReplacingOptions)options error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        NSDictionary* writeOptions = @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};

        NSURL* selfURL = [self URL];

        if(!selfURL || [_shadow isURLRestricted:selfURL options:writeOptions] || [_shadow isURLRestricted:url options:writeOptions]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForURL:url];
            }

            return nil;
        }
    }

    NSURL* result = %orig;

    if(result && isCallerExternal() && [_shadow isURLRestricted:result]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:result];
        }

        return nil;
    }

    return result;
}

- (BOOL)removeAndReturnError:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        NSURL* selfURL = [self URL];

        if(!selfURL || [_shadow isURLRestricted:selfURL options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForURL:selfURL];
            }

            return NO;
        }
    }

    return %orig;
}

+ (BOOL)removeOtherVersionsOfItemAtURL:(NSURL *)url error:(NSError * _Nullable *)outError __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
        if(outError) {
            *outError = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    return %orig;
}

+ (void)getNonlocalVersionsOfItemAtURL:(NSURL *)url completionHandler:(void (^)(NSArray<NSFileVersion *> *nonlocalFileVersions, NSError *error))completionHandler __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(completionHandler) {
            // Async-contract: never invoke a blocked-path completion inline.
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                completionHandler(nil, [Shadow fileNoSuchFileErrorForURL:url]);
            });
        }

        return;
    }

    %orig;
}
%end
%end

void shadowhook_NSFileVersion(SHDWHookSession* hooks) {
    %init(shadowhook_NSFileVersion);
}

// The toolchain's SDK Foundation headers ship no NSTask.h (and the cached
// Foundation module declares no NSTask), so the vendored Apple header is the
// only class declaration in this TU. It carries no availability guards, so
// all selectors below hook unconditionally.
#import "../../../vendor/apple/NSTask.h"

// The vendored header predates the designated initializer (macOS 10.13 /
// iOS 11 era); declare it here so the hook and its %orig compile against a
// real signature.
@interface NSTask (ShadowInitWithLaunchPath)
- (nullable instancetype)initWithLaunchPath:(NSString *)path arguments:(NSArray<NSString *> *) __attribute__((annotate("hookkit:allow_inherited")))arguments;
@end

%group shadowhook_NSTask
%hook NSTask

- (void)launch __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && self.launchPath && [_shadow isPathRestricted:self.launchPath options:shdw_restriction_write_options()]) {
        // Stock raises exactly this exception when the launch path is
        // invalid ("Couldn't posix_spawn: No such file or directory"); a
        // denied spawn therefore looks like a missing binary —
        // fingerprint-plausible, exercises the caller's normal error path,
        // and never hangs.
        [NSException raise:NSInternalInconsistencyException format:@"Couldn't posix_spawn: No such file or directory"];
    }

    %orig;
}

+ (instancetype)launchedTaskWithLaunchPath:(NSString *)path arguments:(NSArray<NSString *> *)arguments __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && path && [_shadow isPathRestricted:path options:shdw_restriction_write_options()]) {
        // The convenience raises NSInvalidArgumentException for an unusable
        // launch path; mirror it so a denied task fails the same way stock
        // fails on a bad path.
        [NSException raise:NSInvalidArgumentException format:@"launch path not accessible"];
    }

    return %orig;
}

// -launchPath intentionally NOT hooked: it only reports the configured path,
// and filtering it would corrupt the task's own configuration (the path is
// what -launch executes); the denial lives in -launch.

%end
%end

void shadowhook_NSTask(SHDWHookSession* hooks) {
    %init(shadowhook_NSTask);
}
