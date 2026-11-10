#import "UniversalHooks.h"
#import "../../policy/PathPolicy.h"
#import <fcntl.h>

static char* _NSDirectoryEnumerator_shdw_key = "shdw";
static char* _NSDirectoryEnumerator_shdw_state_key = "shdw_state";

// One-time-checked debug gate: SHADOW_DEBUG in the environment enables the
// per-call NSLogs (enumerator creation, changeCurrentDirectoryPath). Checked
// once — a static initializer can't call getenv, so the flag is read lazily.
static bool g_shdw_debug = false;
static bool g_shdw_debug_checked = false;

static bool shdw_debug_logging_enabled(void) {
    if(!g_shdw_debug_checked) {
        g_shdw_debug_checked = true;
        g_shdw_debug = getenv("SHADOW_DEBUG") != NULL;
    }

    return g_shdw_debug;
}

// The working-dir option is only consulted for relative paths (Shadow/Core.m);
// absolute paths and file URLs skip it, so avoid building the dict / fetching cwd for them.
static NSDictionary* _shdw_optionsForAbsolute(NSFileManager* fm, BOOL allAbsolute) {
    if(allAbsolute) {
        return nil;
    }

    return @{kShadowRestrictionWorkingDir : [fm currentDirectoryPath]};
}

// Link-location checks must not resolve through the link: the queried entry's
// own spelling decides, exactly like the libc readlink hook.
static NSDictionary* _shdw_optionsForNoFollow(NSFileManager* fm, BOOL allAbsolute) {
    if(allAbsolute) {
        return @{kShadowRestrictionNoFollow : @YES};
    }

    return @{kShadowRestrictionNoFollow : @YES,
             kShadowRestrictionWorkingDir : [fm currentDirectoryPath]};
}

// Write/create/delete intent. Never nil: a nil options dict reads as read
// intent and is served from the decision cache, while the write key also
// disables Core.m's existence gate so a restricted-classified path is denied
// even when the target does not exist (nonexistent-target write probes).
// Built lazily like _shdw_optionsForAbsolute: the mutable dict and the
// currentDirectoryPath query only happen for relative paths.
static NSDictionary* _shdw_writeOptions(NSFileManager* fm, BOOL allAbsolute) {
    if(allAbsolute) {
        return @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};
    }

    return @{kShadowRestrictionOperation : kShadowRestrictionOpWrite,
             kShadowRestrictionWorkingDir : [fm currentDirectoryPath]};
}

static NSDictionary* _shdw_writeNoFollowOptions(NSFileManager* fm, BOOL allAbsolute) {
    if(allAbsolute) {
        return @{kShadowRestrictionOperation : kShadowRestrictionOpWrite,
                 kShadowRestrictionNoFollow : @YES};
    }

    return @{kShadowRestrictionOperation : kShadowRestrictionOpWrite,
             kShadowRestrictionNoFollow : @YES,
             kShadowRestrictionWorkingDir : [fm currentDirectoryPath]};
}

static BOOL shdw_foundation_path_denied(NSFileManager* fm, NSString* path, NSDictionary* options, BOOL nofollow) {
    if(!path) {
        return NO;
    }
    NSString* absolute = [path isAbsolutePath] ? path : [[fm currentDirectoryPath] stringByAppendingPathComponent:path];
    const char* cpath = [absolute UTF8String];
    if(cpath && shdw_path_is_main_bundle_exempt(cpath)) {
        return NO;
    }
    BOOL externalHidden = nofollow
        ? shdw_path_is_external_hidden_nofollow(cpath)
        : shdw_path_is_external_hidden(cpath);
    if(externalHidden) {
        return YES;
    }
    NSDictionary* policyOptions = options;
    if(nofollow && ![options[kShadowRestrictionNoFollow] boolValue]) {
        NSMutableDictionary* merged = options ? [options mutableCopy] : [NSMutableDictionary dictionary];
        merged[kShadowRestrictionNoFollow] = @YES;
        policyOptions = merged;
    }
    return [_shadow isPathRestricted:path options:policyOptions];
}

static BOOL shdw_foundation_url_denied(NSURL* url, NSDictionary* options, BOOL nofollow) {
    return url.isFileURL && shdw_foundation_path_denied([NSFileManager defaultManager], url.path, options, nofollow);
}

// Enumeration results consult the same hidden set the point lookups hide:
// a listed entry the access()/stat() hooks report absent must not survive
// a listing. The ruleset filters below cannot see these objects by design,
// so the union lives here, next to each enumeration filter.
static BOOL shdw_enumerated_entry_hidden(NSString* base, NSString* name) {
    if(!name || name.length == 0) {
        return NO;
    }
    NSString* full = name;
    if(![name isAbsolutePath] && base.length) {
        full = [base stringByAppendingPathComponent:name];
    }
    if(SHDWAdapterPathIsHidden(full)) {
        return YES;
    }
    const char* c = [full UTF8String];
    if(c && shdw_path_is_external_hidden(c)) {
        return YES;
    }
    // Leaf check against the containing directory: a bind mount's backing
    // store can rename the parent out from under the join.
    const char* pc = [[full stringByDeletingLastPathComponent] UTF8String];
    const char* lc = [[full lastPathComponent] UTF8String];
    if(pc && lc && shdw_dir_leaf_external_hidden(pc, lc)) {
        return YES;
    }
    return NO;
}
static BOOL shdw_enumerated_url_hidden(NSURL* url, NSString* base) {
    if(!url || ![url isFileURL]) {
        return NO;
    }
    // A reference URL carries no path; a relative one must stay relative so the
    // base join (not the process cwd) decides what it names.
    if([url isFileReferenceURL]) {
        NSURL* resolved = [url filePathURL];
        if(!resolved) {
            return YES;
        }
        return shdw_enumerated_entry_hidden(base, [resolved path]);
    }
    return shdw_enumerated_entry_hidden(base, [url path]);
}

// Enumerator state and the per-item decision used by directory listings.
static NSString* shdw_enumerator_base(id enumerator) {
    NSString* base = objc_getAssociatedObject(enumerator, _NSDirectoryEnumerator_shdw_key);

    if(!base) {
        NSLog(@"NSDirectoryEnumerator base not found");
        base = @"";
    }

    return base;
}

// The child options dict is invariant for the life of the enumerator, so cache
// it (avoids per-item allocation); the base restriction decision itself is
// rechecked on every item so ruleset reloads / filesystem changes stay
// effective (Core.m's bounded decision cache keeps that recheck cheap in
// steady state).
static NSDictionary* shdw_enumerator_child_options(id enumerator, NSString* base) {
    NSDictionary* childOptions = objc_getAssociatedObject(enumerator, _NSDirectoryEnumerator_shdw_state_key);

    if(!childOptions) {
        childOptions = @{kShadowRestrictionWorkingDir : base};
        objc_setAssociatedObject(enumerator, _NSDirectoryEnumerator_shdw_state_key, childOptions, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }

    return childOptions;
}

// One yielded item: ruleset first (path spelling, URL path or entry name),
// then the hidden-set union the access()/stat() hooks enforce.
static BOOL shdw_enumerator_item_hidden(id obj, NSString* base, NSDictionary* childOptions) {
    NSString* path = nil;

    if([obj isKindOfClass:[NSURL class]]) {
        path = [obj path];
    } else if([obj isKindOfClass:[NSString class]]) {
        path = obj;
    }

    if([_shadow isPathRestricted:path options:childOptions]) {
        return YES;
    }
    if([obj isKindOfClass:[NSURL class]]) {
        return shdw_enumerated_url_hidden(obj, base);
    }
    if([obj isKindOfClass:[NSString class]]) {
        return shdw_enumerated_entry_hidden(base, path);
    }

    return NO;
}

// Copy the kept items from one fast-enumeration batch into the caller's
// buffer. The producer may hand its batch back through state->itemsPtr
// instead of stackbuf; read that pointer, never assume the fetch landed in
// stackbuf. Returns the kept count; the caller loops on %orig (which advanced
// its cursor) when it is zero.
static NSUInteger shdw_enumerator_compact(id __unsafe_unretained* source, id __unsafe_unretained* destination, NSUInteger fetched, NSString* base, NSDictionary* childOptions) {
    NSUInteger kept = 0;

    for(NSUInteger i = 0; i < fetched; i++) {
        id obj = source[i];

        if(!obj || shdw_enumerator_item_hidden(obj, base, childOptions)) {
            continue;
        }

        destination[kept++] = obj;
    }

    return kept;
}

// A producer may return a batch larger than the caller's stack buffer when it
// points itemsPtr at its own storage (NSFastEnumeration allows count > len in
// that case). Keep the filtered batch in per-state storage; it must stay alive
// until the next batch or the end of enumeration. An abandoned loop leaves the
// last buffer associated with the enumerator until dealloc, which is bounded
// and far safer than exposing the batch unfiltered.
static char shdw_enumerator_batches_key;

static NSMutableData* shdw_enumerator_batch_alloc(NSUInteger count) {
    if(count == 0 || count > NSUIntegerMax / sizeof(id)) {
        return nil;
    }

    return [NSMutableData dataWithLength:count * sizeof(id)];
}

static void shdw_enumerator_batch_store(id enumerator, NSFastEnumerationState* state, NSMutableData* data) {
    NSMutableDictionary* batches = objc_getAssociatedObject(enumerator, &shdw_enumerator_batches_key);

    if(!batches) {
        batches = [NSMutableDictionary new];
        objc_setAssociatedObject(enumerator, &shdw_enumerator_batches_key, batches, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }

    batches[[NSValue valueWithPointer:state]] = data;
}

static void shdw_enumerator_batch_release(id enumerator, NSFastEnumerationState* state) {
    NSMutableDictionary* batches = objc_getAssociatedObject(enumerator, &shdw_enumerator_batches_key);

    if(batches) {
        [batches removeObjectForKey:[NSValue valueWithPointer:state]];
    }
}

static NSArray* shdw_enumerator_filter_all(NSArray* array, NSString* base) {
    if(!array) {
        return nil;
    }

    array = [Shadow filterPathArray:array restricted:NO options:@{kShadowRestrictionWorkingDir : base}];
    // The ruleset filter cannot see loader-visible objects by design.
    return [array objectsAtIndexes:[array indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL* stop) {
        if([obj isKindOfClass:[NSURL class]]) {
            return !shdw_enumerated_url_hidden(obj, base);
        }
        if([obj isKindOfClass:[NSString class]]) {
            return !shdw_enumerated_entry_hidden(base, obj);
        }
        return YES;
    }]];
}

// Subtree preflight: a directory that contains a restricted descendant is
// denied even when the root itself is allowed — copying, moving, removing or
// replacing such a tree would carry or destroy restricted content. The walk
// runs inside the internal scope so Shadow's own opendir/readdir hooks pass
// it through unfiltered. Depth-capped; fails open (NO) on any error, since
// the site's root check already denied the directly-restricted case.
static BOOL shdw_has_restricted_descendant_internal(NSString* path, NSDictionary* options, int depth, BOOL nofollow) {
    if(!path || depth > 64) {
        return NO;
    }

    shdw_enter_internal();

    BOOL restricted = NO;
    struct stat st;

    if(lstat(path.UTF8String, &st) == 0 && S_ISDIR(st.st_mode)) {
        DIR* dir = opendir(path.UTF8String);

        if(dir) {
            struct dirent* entry;

            while((entry = readdir(dir)) != NULL) {
                if(entry->d_name[0] == '.' && (entry->d_name[1] == '\0'
                    || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
                    continue;
                }

                // Per-entry pool: a wide/deep tree would otherwise pile up the
                // child strings and every isPathRestricted: temporary until the
                // outer hooked op returns (host-app memory spike, not a leak).
                @autoreleasepool {
                    NSString* child = [path stringByAppendingPathComponent:@(entry->d_name)];

                    NSString* absoluteChild = child;
                    if(![absoluteChild isAbsolutePath]) {
                        NSString* workingDir = options[kShadowRestrictionWorkingDir];
                        if(workingDir.length) {
                            absoluteChild = [workingDir stringByAppendingPathComponent:absoluteChild];
                        }
                    }
                    if(shdw_foundation_path_denied([NSFileManager defaultManager], absoluteChild, options, nofollow)) {
                        restricted = YES;
                    } else if(lstat(child.UTF8String, &st) == 0 && S_ISDIR(st.st_mode)
                        && shdw_has_restricted_descendant_internal(child, options, depth + 1, nofollow)) {
                        restricted = YES;
                    }
                }

                if(restricted) {
                    break;
                }
            }

            closedir(dir);
        }
    }

    shdw_exit_internal();

    return restricted;
}

static BOOL shdw_has_restricted_descendant(NSString* path, NSDictionary* options, BOOL nofollow) {
    return shdw_has_restricted_descendant_internal(path, options, 0, nofollow);
}

%group shadowhook_NSFileManager
%hook NSDirectoryEnumerator
- (NSArray *)allObjects __attribute__((annotate("hookkit:allow_inherited"))) {
    // C0-2: filter unconditionally — app, detector, and system-framework
    // callers (Foundation forwarding, for-in mediation) all get the same
    // filtered stream; only Shadow-internal scopes see truth, and Shadow
    // does not enumerate through NSDirectoryEnumerator.
    NSString* base = shdw_enumerator_base(self);

    if([_shadow isPathRestricted:base]) {
        return @[];
    }

    NSArray* result = %orig;

    return shdw_enumerator_filter_all(result, base);
}

- (id)nextObject __attribute__((annotate("hookkit:allow_inherited"))) {
    NSString* base = shdw_enumerator_base(self);
    NSDictionary* childOptions = shdw_enumerator_child_options(self, base);

    if([_shadow isPathRestricted:base]) {
        return nil;
    }

    id result = %orig;

    // keep looping until we get something unrestricted or nil
    while(result && shdw_enumerator_item_hidden(result, base, childOptions)) {
        result = %orig;
    }

    return result;
}

// Fast enumeration (for…in) bypasses nextObject, so it needs its own filter.
// ABI notes: the runtime zeroes the NSFastEnumerationState before the first
// call and reads itemsPtr/mutationsPtr after each call; %orig advances
// state->state (an opaque cursor) with every batch. The producer may return
// its batch through stackbuf or through its own itemsPtr storage, and an
// external batch may be larger than len. Read itemsPtr, compact from it, and
// use stackbuf only when the fetched or kept count fits; retain per-state
// storage for larger batches. A batch that filters to zero must NOT return 0
// (that terminates enumeration), so we loop: fetch again — %orig continues
// from the cursor it just advanced — until we have at least one item or
// %orig reports end-of-stream.
// The buffer type mirrors the SDK's NSFastEnumeration declaration
// (id __unsafe_unretained): the enumerator's objects are borrowed, not
// owned, and __unsafe_unenumerated is not a keyword in this toolchain.
- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(id __unsafe_unretained *)stackbuf count:(NSUInteger)len __attribute__((annotate("hookkit:allow_inherited"))) {
    NSString* base = shdw_enumerator_base(self);
    NSDictionary* childOptions = shdw_enumerator_child_options(self, base);

    if([_shadow isPathRestricted:base]) {
        return 0;
    }

    NSUInteger filteredCount = 0;

    while(filteredCount == 0) {
        shdw_enumerator_batch_release(self, state);
        state->itemsPtr = stackbuf;
        NSUInteger fetched = %orig(state, stackbuf, len);

        if(fetched == 0) {
            return 0;
        }

        id __unsafe_unretained* batch = state->itemsPtr ? state->itemsPtr : stackbuf;

        if(fetched <= len) {
            filteredCount = shdw_enumerator_compact(batch, stackbuf, fetched, base, childOptions);
            state->itemsPtr = stackbuf;
        } else {
            NSMutableData* storage = shdw_enumerator_batch_alloc(fetched);

            if(!storage) {
                return 0;
            }

            id __unsafe_unretained* filtered = (id __unsafe_unretained*)storage.mutableBytes;
            filteredCount = shdw_enumerator_compact(batch, filtered, fetched, base, childOptions);

            if(filteredCount == 0) {
                continue;
            }

            if(filteredCount <= len) {
                memcpy(stackbuf, filtered, filteredCount * sizeof(id));
                state->itemsPtr = stackbuf;
            } else {
                shdw_enumerator_batch_store(self, state, storage);
                state->itemsPtr = filtered;
            }
        }
    }

    return filteredCount;
}
%end


%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    BOOL ext = isCallerExternal();
    // Resolve-stable fast lane (see replaced_access in libc.x): pin the
    // object so a planted link hides like its target, plus the bounded
    // post on TRUE results. Ruleset verdicts are not consulted on this
    // lane, exactly as before.
    if(shdw_is_fast_allowed_nspath(path) && ext) {
        const char* cpath = [path fileSystemRepresentation];
        if(cpath && shdw_path_needs_verify(cpath) && shdw_verify_open_hidden(AT_FDCWD, cpath) == -1) {
            return NO;
        }
        BOOL r = %orig;
        // Fallback verdict for the TRUE shape (see shdw_at_post_verify
        // in policy/PathPolicy.m).
        if(r && cpath && shdw_at_post_verify(AT_FDCWD, cpath) != SHDW_POST_ADMIT) {
            return NO;
        }
        return r;
    }
    if(ext && (SHDWAdapterPathIsHidden(path) ||
       [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])])) {
        return NO;
    }

    return %orig;
}
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory __attribute__((annotate("hookkit:allow_inherited"))) {
    BOOL ext = isCallerExternal();
    // Resolve-stable fast lane (see the sibling above).
    if(shdw_is_fast_allowed_nspath(path) && ext) {
        const char* cpath = [path fileSystemRepresentation];
        if(cpath && shdw_path_needs_verify(cpath) && shdw_verify_open_hidden(AT_FDCWD, cpath) == -1) {
            if(isDirectory) {
                *isDirectory = NO;
            }
            return NO;
        }
        BOOL r = %orig;
        if(r && cpath && shdw_at_post_verify(AT_FDCWD, cpath) != SHDW_POST_ADMIT) {
            if(isDirectory) {
                *isDirectory = NO;
            }
            return NO;
        }
        return r;
    }
    if(ext && (SHDWAdapterPathIsHidden(path) ||
       [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])])) {
        // Out-param leak: the directory bit must not survive the hiding.
        if(isDirectory) {
            *isDirectory = NO;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isWritableFileAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_writeOptions(self, [path isAbsolutePath])]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isDeletableFileAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return NO;
    }

    return %orig;
}

- (NSData *)contentsAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return nil;
    }

    return %orig;
}

- (BOOL)contentsEqualAtPath:(NSString *)path1 andPath:(NSString *)path2 __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        // One options object shared by both checks; cwd is only needed if an input is relative.
        NSDictionary* options = _shdw_optionsForAbsolute(self, [path1 isAbsolutePath] && [path2 isAbsolutePath]);

        if([_shadow isPathRestricted:path1 options:options] || [_shadow isPathRestricted:path2 options:options]) {
            return NO;
        }
    }

    return %orig;
}

- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(!isCallerExternal()) {
        return %orig;
    }

    if([_shadow isURLRestricted:url options:nil]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:nil];
        // The ruleset filter cannot see loader-visible objects by design.
        result = [result objectsAtIndexes:[result indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL* stop) {
            return ![obj isKindOfClass:[NSURL class]] || !shdw_enumerated_url_hidden(obj, [url path]);
        }]];
    }

    return result;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(!isCallerExternal()) {
        return %orig;
    }

    if(shdw_foundation_path_denied(self, path, _shdw_optionsForAbsolute(self, [path isAbsolutePath]), NO)) {
        if(error) {
            *error = [Shadow fileErrorWithCode:NSFileReadNoSuchFileError path:path url:nil];
        }

        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : path}];
        // The ruleset filter cannot see loader-visible objects by design.
        NSString* base = path;
        result = [result objectsAtIndexes:[result indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL* stop) {
            return ![obj isKindOfClass:[NSString class]] || !shdw_enumerated_entry_hidden(base, obj);
        }]];
    }

    return result;
}

- (NSDirectoryEnumerator<NSURL *> *)enumeratorAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask errorHandler:(BOOL (^)(NSURL *url, NSError *error))handler __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:nil]) {
        return nil;
    }

    // The base is the URL's own path spelling (never absoluteURL: that would
    // resolve a relative URL against the caller's cwd), so a relative yielded
    // URL joins to the same directory the enumerator was created with.
    NSString* basePath = [url path];
    if(!basePath && [url isFileReferenceURL]) {
        basePath = [[url filePathURL] path];
    }
    // roothide logos cannot parse block literals inside %orig(...) args.
    BOOL (^filteredHandler)(NSURL *, NSError *) = ^BOOL(NSURL *childURL, NSError *childError) {
        // Suppress errors for restricted entries: the app handler must not
        // learn about (or be able to react to) hidden subtrees.
        if(shdw_enumerated_url_hidden(childURL, basePath) || [_shadow isURLRestricted:childURL options:nil]) {
            return NO;  // continue enumeration, do not call the app handler
        }

        if(handler) {
            return handler(childURL, childError);
        }

        return NO;
    };
    NSDirectoryEnumerator* result = %orig(url, keys, mask, filteredHandler);
    
    if(result) {
        objc_setAssociatedObject(result, _NSDirectoryEnumerator_shdw_key, basePath, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

        if(shdw_debug_logging_enabled()) {
            NSLog(@"enumeratorAtURL: %@", url);
        }
    }

    return result;
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return nil;
    }

    NSDirectoryEnumerator* result = %orig;

    if(result) {
        objc_setAssociatedObject(result, _NSDirectoryEnumerator_shdw_key, path, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

        if(shdw_debug_logging_enabled()) {
            NSLog(@"enumeratorAtPath: %@", path);
        }
    }
    
    return result;
}

- (NSArray<NSString *> *)subpathsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(!isCallerExternal()) {
        return %orig;
    }

    if([_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : path}];
        // The ruleset filter cannot see loader-visible objects by design.
        NSString* base = path;
        result = [result objectsAtIndexes:[result indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL* stop) {
            return ![obj isKindOfClass:[NSString class]] || !shdw_enumerated_entry_hidden(base, obj);
        }]];
    }

    return result;
}

- (NSArray<NSString *> *)subpathsAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(!isCallerExternal()) {
        return %orig;
    }

    if([_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return nil;
    }
    
    NSArray* result = %orig;
    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : path}];
        // The ruleset filter cannot see loader-visible objects by design.
        NSString* base = path;
        result = [result objectsAtIndexes:[result indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL* stop) {
            return ![obj isKindOfClass:[NSString class]] || !shdw_enumerated_entry_hidden(base, obj);
        }]];
    }

    return result;
}

- (void)getFileProviderServicesForItemAtURL:(NSURL *)url completionHandler:(void (^)(NSDictionary *services, NSError *error))completionHandler __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:nil]) {
        if(completionHandler) {
            // Async contract: never invoke a blocked-path completion inline.
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                completionHandler(nil, [Shadow fileNoSuchFileErrorForURL:url]);
            });
        }

        return;
    }

    %orig;
}

// A symlink's destination is stored as written; a relative destination is
// interpreted relative to the directory containing the link. Resolve it for
// classification so a relative link pointing into a restricted tree is
// caught. Returns the destination unchanged when it is absolute.
static NSString* _shdw_resolveLinkDestination(NSString* linkPath, NSString* destPath) {
    if(!destPath) {
        return nil;
    }

    if([destPath isAbsolutePath]) {
        return destPath;
    }

    return [[linkPath stringByDeletingLastPathComponent] stringByAppendingPathComponent:destPath];
}

- (NSArray<NSString *> *)componentsToDisplayForPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return nil;
    }

    return %orig;
}

- (NSString *)displayNameAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return nil;
    }

    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        if(error) {
            *error = [Shadow fileErrorWithCode:NSFileReadNoSuchFileError path:path url:nil];
        }

        return nil;
    }

    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfFileSystemForPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        const char* cpath = path.fileSystemRepresentation;
        if(cpath && shdw_path_is_main_bundle_exempt(cpath)) {
            return %orig;
        }
        if(cpath && shdw_path_is_external_hidden(cpath)) {
            if(error) {
                *error = [Shadow fileErrorWithCode:NSFileReadNoSuchFileError path:path url:nil];
            }
            return nil;
        }
        if([_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
            if(error) {
                *error = [Shadow fileErrorWithCode:NSFileReadNoSuchFileError path:path url:nil];
            }
            return nil;
        }
    }

    return %orig;
}


- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectoryAtURL:(NSURL *)directoryURL toItemAtURL:(NSURL *)otherURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && ([_shadow isURLRestricted:directoryURL options:nil] || [_shadow isURLRestricted:otherURL options:nil])) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:directoryURL];
        }
        
        return NO;
    }

    return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domainMask toItemAtURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:nil]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)changeCurrentDirectoryPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_logging_enabled()) {
        NSLog(@"changeCurrentDirectoryPath: %@", path);
    }

    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return NO;
    }

    return %orig;
}

- (NSDictionary *)fileAttributesAtPath:(NSString *)path traverseLink:(BOOL)yorn __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return nil;
    }

    return %orig;
}

- (NSDictionary *)fileSystemAttributesAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        const char* cpath = path.fileSystemRepresentation;
        if(cpath && shdw_path_is_main_bundle_exempt(cpath)) {
            return %orig;
        }
        if(cpath && (shdw_path_is_external_hidden(cpath)
                     || [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])])) {
            return nil;
        }
    }

    return %orig;
}

- (NSArray *)directoryContentsAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(!isCallerExternal()) {
        return %orig;
    }

    if([_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return nil;
    }
    
    NSArray* result = %orig;
    
    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : path}];
        // The ruleset filter cannot see loader-visible objects by design.
        NSString* base = path;
        result = [result objectsAtIndexes:[result indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL* stop) {
            return ![obj isKindOfClass:[NSString class]] || !shdw_enumerated_entry_hidden(base, obj);
        }]];
    }

    return result;
}

- (NSString *)pathContentOfSymbolicLinkAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return nil;
    }

    NSString* result = %orig;

    if(result && isCallerExternal()) {
        NSString* resolvedDest = _shdw_resolveLinkDestination(path, result);

        if(resolvedDest && [_shadow isPathRestricted:resolvedDest options:_shdw_optionsForAbsolute(self, [resolvedDest isAbsolutePath])]) {
            return nil;
        }
    }

    return result;
}

- (BOOL)replaceItemAtURL:(NSURL *)originalItemURL withItemAtURL:(NSURL *)newItemURL backupItemName:(NSString *)backupItemName options:(NSFileManagerItemReplacementOptions)options resultingItemURL:(NSURL * _Nullable *)resultingURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && (shdw_foundation_url_denied(originalItemURL, shdw_restriction_write_options(), YES) || shdw_foundation_url_denied(newItemURL, shdw_restriction_write_options(), YES))) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:originalItemURL];
        }

        return NO;
    }

    // Subtree preflight: replacing a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && [originalItemURL isFileURL]
        && shdw_has_restricted_descendant([originalItemURL path], shdw_restriction_write_options(), YES)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:originalItemURL];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && (shdw_foundation_url_denied(srcURL, nil, NO) || shdw_foundation_url_denied(dstURL, _shdw_writeNoFollowOptions([NSFileManager defaultManager], YES), YES))) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:srcURL];
        }

        return NO;
    }

    // Subtree preflight: copying a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && [srcURL isFileURL]
        && shdw_has_restricted_descendant([srcURL path], nil, NO)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:srcURL];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        if(shdw_foundation_path_denied(self, srcPath, _shdw_optionsForAbsolute(self, [srcPath isAbsolutePath]), NO)
            || shdw_foundation_path_denied(self, dstPath, _shdw_writeNoFollowOptions(self, [dstPath isAbsolutePath]), YES)) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:srcPath];
            }

            return NO;
        }

        // Subtree preflight: copying a directory that contains a restricted
        // descendant must be denied even when the root itself is allowed.
        if(shdw_has_restricted_descendant(srcPath, _shdw_optionsForAbsolute(self, [srcPath isAbsolutePath]), NO)) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:srcPath];
            }

            return NO;
        }
    }

    return %orig;
}

- (BOOL)moveItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && (shdw_foundation_url_denied(srcURL, shdw_restriction_write_options(), YES) || shdw_foundation_url_denied(dstURL, shdw_restriction_write_options(), YES))) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:srcURL];
        }

        return NO;
    }

    // Subtree preflight: moving a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && [srcURL isFileURL]
        && shdw_has_restricted_descendant([srcURL path], shdw_restriction_write_options(), YES)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:srcURL];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        if(shdw_foundation_path_denied(self, srcPath, _shdw_writeNoFollowOptions(self, [srcPath isAbsolutePath]), YES)
            || shdw_foundation_path_denied(self, dstPath, _shdw_writeNoFollowOptions(self, [dstPath isAbsolutePath]), YES)) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:srcPath];
            }

            return NO;
        }

        // Subtree preflight: moving a directory that contains a restricted
        // descendant must be denied even when the root itself is allowed.
        if(shdw_has_restricted_descendant(srcPath, _shdw_writeNoFollowOptions(self, [srcPath isAbsolutePath]), YES)) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:srcPath];
            }

            return NO;
        }
    }

    return %orig;
}

- (BOOL)isUbiquitousItemAtURL:(NSURL *)url __attribute__((annotate("hookkit:allow_inherited"))) {
    BOOL result = %orig;

    if(isCallerExternal() && result && [_shadow isURLRestricted:url options:nil]) {
        return NO;
    }

    return result;
}

- (BOOL)setUbiquitous:(BOOL)flag itemAtURL:(NSURL *)url destinationURL:(NSURL *)destinationURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && ([_shadow isURLRestricted:url options:shdw_restriction_write_options()] || [_shadow isURLRestricted:destinationURL options:shdw_restriction_write_options()])) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)startDownloadingUbiquitousItemAtURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:shdw_restriction_write_options()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)evictUbiquitousItemAtURL:(NSURL *)url error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:shdw_restriction_write_options()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    return %orig;
}

- (NSURL *)URLForPublishingUbiquitousItemAtURL:(NSURL *)url expirationDate:(NSDate * _Nullable *)outDate error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:shdw_restriction_write_options()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return nil;
    }

    return %orig;
}

- (BOOL)createSymbolicLinkAtURL:(NSURL *)url withDestinationURL:(NSURL *)destURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        // Link location: write intent — a probe creating a link at a
        // restricted path must be denied even when the target is absent.
        NSDictionary* writeOptions = @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};

        if([_shadow isURLRestricted:url options:writeOptions]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForURL:url];
            }

            return NO;
        }

        // Destination: read intent. Relative destinations resolve against
        // the directory containing the link (the link's parent).
        if(destURL) {
            NSURL* absDest = [destURL absoluteURL];
            NSString* destPath = [absDest path];

            if(![destPath isAbsolutePath]) {
                destPath = [[[url path] stringByDeletingLastPathComponent] stringByAppendingPathComponent:destPath];
            }

            if(destPath && [_shadow isPathRestricted:destPath options:nil]) {
                if(error) {
                    *error = [Shadow fileNoSuchFileErrorForURL:destURL];
                }

                return NO;
            }
        }
    }

    return %orig;
}

- (BOOL)createSymbolicLinkAtPath:(NSString *)path withDestinationPath:(NSString *)destPath error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        if([_shadow isPathRestricted:path options:_shdw_writeOptions(self, [path isAbsolutePath])]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:path];
            }

            return NO;
        }

        NSString* resolvedDest = _shdw_resolveLinkDestination(path, destPath);

        if(resolvedDest && [_shadow isPathRestricted:resolvedDest options:_shdw_optionsForAbsolute(self, [resolvedDest isAbsolutePath])]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:destPath];
            }

            return NO;
        }
    }

    return %orig;
}

- (BOOL)linkItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && (shdw_foundation_url_denied(srcURL, nil, YES) || shdw_foundation_url_denied(dstURL, _shdw_writeNoFollowOptions([NSFileManager defaultManager], YES), YES))) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:srcURL];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)linkItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        if(shdw_foundation_path_denied(self, srcPath, _shdw_optionsForNoFollow(self, [srcPath isAbsolutePath]), YES)
            || shdw_foundation_path_denied(self, dstPath, _shdw_writeNoFollowOptions(self, [dstPath isAbsolutePath]), YES)) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:srcPath];
            }

            return NO;
        }
    }

    return %orig;
}

- (BOOL)removeFileAtPath:(NSString *)path handler:(id)handler __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_foundation_path_denied(self, path, _shdw_writeNoFollowOptions(self, [path isAbsolutePath]), YES)) {
        return NO;
    }

    return %orig;
}

- (BOOL)changeFileAttributes:(NSDictionary *)attributes atPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_writeOptions(self, [path isAbsolutePath])]) {
        return NO;
    }

    return %orig;
}

- (BOOL)createDirectoryAtURL:(NSURL *)url withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_foundation_url_denied(url, _shdw_writeNoFollowOptions([NSFileManager defaultManager], YES), YES)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_foundation_path_denied(self, path, _shdw_writeNoFollowOptions(self, [path isAbsolutePath]), YES)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary<NSFileAttributeKey, id> *)attr __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_writeOptions(self, [path isAbsolutePath])]) {
        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtURL:(NSURL *)URL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_foundation_url_denied(URL, _shdw_writeNoFollowOptions([NSFileManager defaultManager], YES), YES)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:URL];
        }

        return NO;
    }

    // Subtree preflight: removing a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && [URL isFileURL]
        && shdw_has_restricted_descendant([URL path], _shdw_writeNoFollowOptions([NSFileManager defaultManager], YES), YES)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:URL];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_foundation_path_denied(self, path, _shdw_writeNoFollowOptions(self, [path isAbsolutePath]), YES)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return NO;
    }

    // Subtree preflight: removing a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && shdw_has_restricted_descendant(path, _shdw_writeNoFollowOptions(self, [path isAbsolutePath]), YES)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)trashItemAtURL:(NSURL *)url resultingItemURL:(NSURL * _Nullable *)outResultingURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_foundation_url_denied(url, _shdw_writeNoFollowOptions([NSFileManager defaultManager], YES), YES)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    // Subtree preflight: trashing a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && [url isFileURL]
        && shdw_has_restricted_descendant([url path], _shdw_writeNoFollowOptions([NSFileManager defaultManager], YES), YES)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)setAttributes:(NSDictionary<NSFileAttributeKey, id> *)attributes ofItemAtPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_writeOptions(self, [path isAbsolutePath])]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return NO;
    }

    return %orig;
}

- (NSArray<NSURL *> *)mountedVolumeURLsIncludingResourceValuesForKeys:(NSArray<NSURLResourceKey> *)propertyKeys options:(NSVolumeEnumerationOptions)options __attribute__((annotate("hookkit:allow_inherited"))) {
    if(!isCallerExternal()) {
        return %orig;
    }

    NSArray* result = %orig;

    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:nil];
    }

    return result;
}

- (NSURL *)URLForDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domain appropriateForURL:(NSURL *)url create:(BOOL)shouldCreate error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        // create:YES writes the directory (possibly creating it), so the
        // probe is classified with write intent; read intent otherwise.
        NSDictionary* options = shouldCreate ? @{kShadowRestrictionOperation : kShadowRestrictionOpWrite} : nil;

        if(url && [_shadow isURLRestricted:url options:options]) {
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

- (NSArray<NSURL *> *)URLsForDirectory:(NSSearchPathDirectory)directory inDomains:(NSSearchPathDomainMask)domainMask __attribute__((annotate("hookkit:allow_inherited"))) {
    if(!isCallerExternal()) {
        return %orig;
    }

    NSArray* result = %orig;

    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:nil];
    }

    return result;
}

- (NSURL *)containerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier __attribute__((annotate("hookkit:allow_inherited"))) {
    NSURL* result = %orig;

    if(result && isCallerExternal() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}
%end
%end

// Directory listings apply the same visibility policy regardless of the
// enumerator implementation that produces them.
@interface NSURLDirectoryEnumerator : NSDirectoryEnumerator
@end

%group shadowhook_NSURLDirectoryEnumerator
%hook NSURLDirectoryEnumerator
- (NSArray *)allObjects __attribute__((annotate("hookkit:allow_inherited"))) {
    NSString* base = shdw_enumerator_base(self);

    if([_shadow isPathRestricted:base]) {
        return @[];
    }

    NSArray* result = %orig;

    return shdw_enumerator_filter_all(result, base);
}

- (id)nextObject __attribute__((annotate("hookkit:allow_inherited"))) {
    NSString* base = shdw_enumerator_base(self);
    NSDictionary* childOptions = shdw_enumerator_child_options(self, base);

    if([_shadow isPathRestricted:base]) {
        return nil;
    }

    id result = %orig;

    while(result && shdw_enumerator_item_hidden(result, base, childOptions)) {
        result = %orig;
    }

    return result;
}

- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(id __unsafe_unretained *)stackbuf count:(NSUInteger)len __attribute__((annotate("hookkit:allow_inherited"))) {
    NSString* base = shdw_enumerator_base(self);
    NSDictionary* childOptions = shdw_enumerator_child_options(self, base);

    if([_shadow isPathRestricted:base]) {
        return 0;
    }

    NSUInteger filteredCount = 0;

    while(filteredCount == 0) {
        shdw_enumerator_batch_release(self, state);
        state->itemsPtr = stackbuf;
        NSUInteger fetched = %orig(state, stackbuf, len);

        if(fetched == 0) {
            return 0;
        }

        id __unsafe_unretained* batch = state->itemsPtr ? state->itemsPtr : stackbuf;

        if(fetched <= len) {
            filteredCount = shdw_enumerator_compact(batch, stackbuf, fetched, base, childOptions);
            state->itemsPtr = stackbuf;
        } else {
            NSMutableData* storage = shdw_enumerator_batch_alloc(fetched);

            if(!storage) {
                return 0;
            }

            id __unsafe_unretained* filtered = (id __unsafe_unretained*)storage.mutableBytes;
            filteredCount = shdw_enumerator_compact(batch, filtered, fetched, base, childOptions);

            if(filteredCount == 0) {
                continue;
            }

            if(filteredCount <= len) {
                memcpy(stackbuf, filtered, filteredCount * sizeof(id));
                state->itemsPtr = stackbuf;
            } else {
                shdw_enumerator_batch_store(self, state, storage);
                state->itemsPtr = filtered;
            }
        }
    }

    return filteredCount;
}
%end
%end

%group shadowhook_NSFileManagerSymbolicLinks
%hook NSFileManager
- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    BOOL ext = isCallerExternal();
    const char* inputPath = [path fileSystemRepresentation];
    if(ext
       && ((inputPath && shdw_path_is_external_hidden_nofollow(inputPath))
           || [_shadow isPathRestricted:path options:_shdw_optionsForNoFollow(self, [path isAbsolutePath])])) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    NSString* result = %orig;

    // The queried entry's visibility is the only external-hidden gate. A visible
    // symlink's stored target is caller-readable metadata even when that target
    // is hidden (or absent). For libc readlink parity, a resolved stored target
    // that is ruleset-restricted is still denied; external-hidden target text is
    // not.
    if(result && ext) {
        NSString* resolvedDest = _shdw_resolveLinkDestination(path, result);

        if(resolvedDest
           && [_shadow isPathRestricted:resolvedDest options:_shdw_optionsForAbsolute(self, [resolvedDest isAbsolutePath])]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:path];
            }

            return nil;
        }
    }

    return result;
}
%end
%end

void shdw_universal_feature_symbolic_links(SHDWHookSession* hooks) {
    static BOOL installed = NO;
    (void)hooks;

    if(!installed) {
        %init(shadowhook_NSFileManagerSymbolicLinks);
        installed = YES;
    }
}

%group shadowhook_NSFileManagerDeprecatedPaths
%hook NSFileManager
- (BOOL)copyPath:(NSString *)src toPath:(NSString *)dest handler:(id)handler __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        if([_shadow isPathRestricted:src options:_shdw_optionsForAbsolute(self, [src isAbsolutePath])]
            || [_shadow isPathRestricted:dest options:_shdw_writeOptions(self, [dest isAbsolutePath])]) {
            return NO;
        }
    }

    return %orig;
}

- (BOOL)movePath:(NSString *)src toPath:(NSString *)dest handler:(id)handler __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        if([_shadow isPathRestricted:src options:_shdw_writeOptions(self, [src isAbsolutePath])]
            || [_shadow isPathRestricted:dest options:_shdw_writeOptions(self, [dest isAbsolutePath])]) {
            return NO;
        }
    }

    return %orig;
}

- (BOOL)linkPath:(NSString *)src toPath:(NSString *)dest handler:(id)handler __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        if([_shadow isPathRestricted:src options:_shdw_optionsForAbsolute(self, [src isAbsolutePath])]
            || [_shadow isPathRestricted:dest options:_shdw_writeOptions(self, [dest isAbsolutePath])]) {
            return NO;
        }
    }

    return %orig;
}
%end
%end

static void *gShadowFileExistsOrig = NULL;
static void *gShadowFileExistsHook = NULL;
void* shdw_universal_file_exists_original(void) { return gShadowFileExistsOrig; }
void* shdw_universal_file_exists_replacement(void) { return gShadowFileExistsHook; }

static void *gShadowReadableOrig = NULL;
void* shdw_universal_readable_file_original(void) { return gShadowReadableOrig; }

void shdw_universal_filesystem_objc(SHDWHookSession* hooks) {
    Class fmCls = objc_getClass("NSFileManager");
    SEL fmSel = sel_registerName("fileExistsAtPath:");
    Method fm = class_getInstanceMethod(fmCls, fmSel);
    if (fm) gShadowFileExistsOrig = (void*)method_getImplementation(fm);
    SEL rdSel = sel_registerName("isReadableFileAtPath:");
    Method rd = class_getInstanceMethod(fmCls, rdSel);
    if (rd) gShadowReadableOrig = (void*)method_getImplementation(rd);
    %init(shadowhook_NSFileManager);
    // Apply the same directory-visibility policy to the URL enumerator lane
    // when the platform provides it.
    if(objc_getClass("NSURLDirectoryEnumerator")) {
        %init(shadowhook_NSURLDirectoryEnumerator);
    }
    if (fm) gShadowFileExistsHook = (void*)method_getImplementation(fm);
    if (!gShadowFileExistsOrig) {
        IMP orig = SHDWOriginalImplementationForMethod(fm);
        if (orig) gShadowFileExistsOrig = (void*)orig;
    }
    if (!gShadowReadableOrig && rd) {
        IMP orig = SHDWOriginalImplementationForMethod(rd);
        if (orig) gShadowReadableOrig = (void*)orig;
    }
    shdw_universal_feature_symbolic_links(hooks);

    Class fileManager = [NSFileManager class];
    if(class_getInstanceMethod(fileManager, @selector(copyPath:toPath:handler:))
    && class_getInstanceMethod(fileManager, @selector(movePath:toPath:handler:))
    && class_getInstanceMethod(fileManager, @selector(linkPath:toPath:handler:))) {
        %init(shadowhook_NSFileManagerDeprecatedPaths);
    }
}
