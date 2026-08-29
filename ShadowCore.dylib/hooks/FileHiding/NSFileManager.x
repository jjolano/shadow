#import "hooks.h"

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

// Subtree preflight: a directory that contains a restricted descendant is
// denied even when the root itself is allowed — copying, moving, removing or
// replacing such a tree would carry or destroy restricted content. The walk
// runs inside the internal scope so Shadow's own opendir/readdir hooks pass
// it through unfiltered. Depth-capped; fails open (NO) on any error, since
// the site's root check already denied the directly-restricted case.
static BOOL shdw_has_restricted_descendant_internal(NSString* path, NSDictionary* options, int depth) {
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

                NSString* child = [path stringByAppendingPathComponent:@(entry->d_name)];

                // Any restricted descendant — a file or a directory — denies.
                if([_shadow isPathRestricted:child options:options]) {
                    restricted = YES;
                    break;
                }

                if(lstat(child.UTF8String, &st) == 0 && S_ISDIR(st.st_mode)
                    && shdw_has_restricted_descendant_internal(child, options, depth + 1)) {
                    restricted = YES;
                    break;
                }
            }

            closedir(dir);
        }
    }

    shdw_exit_internal();

    return restricted;
}

static BOOL shdw_has_restricted_descendant(NSString* path, NSDictionary* options) {
    return shdw_has_restricted_descendant_internal(path, options, 0);
}

%group shadowhook_NSFileManager
%hook NSDirectoryEnumerator
- (NSArray *)allObjects __attribute__((annotate("hookkit:allow_inherited"))) {
    // C0-2: filter unconditionally — app, detector, and system-framework
    // callers (Foundation forwarding, for-in mediation) all get the same
    // filtered stream; only Shadow-internal scopes see truth, and Shadow
    // does not enumerate through NSDirectoryEnumerator.
    NSString* base = objc_getAssociatedObject(self, _NSDirectoryEnumerator_shdw_key);

    if(!base) {
        NSLog(@"NSDirectoryEnumerator base not found");
        base = @"";
    }

    if([_shadow isPathRestricted:base]) {
        return @[];
    }

    NSArray* result = %orig; 

    if(result) {
        result = [Shadow filterPathArray:result restricted:NO options:@{kShadowRestrictionWorkingDir : base}];
    }

    return result;
}

- (id)nextObject __attribute__((annotate("hookkit:allow_inherited"))) {
    NSString* base = objc_getAssociatedObject(self, _NSDirectoryEnumerator_shdw_key);

    if(!base) {
        NSLog(@"NSDirectoryEnumerator base not found");
        base = @"";
    }

    // The child options dict is invariant for the life of the enumerator, so cache it
    // (avoids per-item allocation); the base restriction decision itself is rechecked
    // on every item so ruleset reloads / filesystem changes stay effective (Core.m's
    // bounded decision cache keeps that recheck cheap in steady state).
    NSDictionary* childOptions = objc_getAssociatedObject(self, _NSDirectoryEnumerator_shdw_state_key);

    if(!childOptions) {
        childOptions = @{kShadowRestrictionWorkingDir : base};
        objc_setAssociatedObject(self, _NSDirectoryEnumerator_shdw_state_key, childOptions, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }

    if([_shadow isPathRestricted:base]) {
        return nil;
    }

    id result = %orig;

    // keep looping until we get something unrestricted or nil
    while(result) {
        NSString* path = nil;

        if([result isKindOfClass:[NSURL class]]) {
            path = [result path];
        } else if([result isKindOfClass:[NSString class]]) {
            path = result;
        }

        if([_shadow isPathRestricted:path options:childOptions]) {
            result = %orig;
        } else {
            break;
        }
    }

    return result;
}

// Fast enumeration (for…in) bypasses nextObject, so it needs its own filter.
// ABI notes: the runtime zeroes the NSFastEnumerationState before the first
// call and reads itemsPtr/mutationsPtr after each call; %orig advances
// state->state (an opaque cursor) with every batch. We reuse the caller's
// buffer in place (fetch into stackbuf via %orig, compact out restricted
// entries, point itemsPtr at the compacted head). A batch that filters to
// zero must NOT return 0 (that terminates enumeration), so we loop: fetch
// again — %orig continues from the cursor it just advanced — until we have
// at least one item or %orig reports end-of-stream.
// The buffer type mirrors the SDK's NSFastEnumeration declaration
// (id __unsafe_unretained): the enumerator's objects are borrowed, not
// owned, and __unsafe_unenumerated is not a keyword in this toolchain.
- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(id __unsafe_unretained *)stackbuf count:(NSUInteger)len __attribute__((annotate("hookkit:allow_inherited"))) {
    NSString* base = objc_getAssociatedObject(self, _NSDirectoryEnumerator_shdw_key);

    if(!base) {
        NSLog(@"NSDirectoryEnumerator base not found");
        base = @"";
    }

    NSDictionary* childOptions = objc_getAssociatedObject(self, _NSDirectoryEnumerator_shdw_state_key);

    if(!childOptions) {
        childOptions = @{kShadowRestrictionWorkingDir : base};
        objc_setAssociatedObject(self, _NSDirectoryEnumerator_shdw_state_key, childOptions, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }

    if([_shadow isPathRestricted:base]) {
        return 0;
    }

    NSUInteger filteredCount = 0;

    while(filteredCount == 0) {
        NSUInteger fetched = %orig(state, stackbuf, len);

        if(fetched == 0) {
            return 0;
        }

        NSUInteger kept = 0;

        for(NSUInteger i = 0; i < fetched; i++) {
            id obj = stackbuf[i];

            if(!obj) {
                continue;
            }

            NSString* path = nil;

            if([obj isKindOfClass:[NSURL class]]) {
                path = [obj path];
            } else if([obj isKindOfClass:[NSString class]]) {
                path = obj;
            }

            if(path && [_shadow isPathRestricted:path options:childOptions]) {
                continue;
            }

            stackbuf[kept++] = obj;
        }

        filteredCount = kept;
    }

    state->itemsPtr = stackbuf;

    return filteredCount;
}
%end

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && (shadowhook_FreeRASP_shouldHideExistencePath(path) ||
       [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])])) {
        return NO;
    }

    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && (shadowhook_FreeRASP_shouldHideExistencePath(path) ||
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
    // TODO: stock-path rootful writeability hiding is out of scope — on a
    // rootful jailbreak stock (non-jb) paths are legitimately writable and we
    // do not claim otherwise. Write intent is passed so restricted paths are
    // denied even when the probe target does not exist yet.
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
    }

    return result;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
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
    }

    return result;
}

- (NSDirectoryEnumerator<NSURL *> *)enumeratorAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask errorHandler:(BOOL (^)(NSURL *url, NSError *error))handler __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:nil]) {
        return nil;
    }

    // roothide logos cannot parse block literals inside %orig(...) args.
    BOOL (^filteredHandler)(NSURL *, NSError *) = ^BOOL(NSURL *childURL, NSError *childError) {
        // Suppress errors for restricted entries: the app handler must not
        // learn about (or be able to react to) hidden subtrees.
        if([_shadow isURLRestricted:childURL options:nil]) {
            return NO;  // continue enumeration, do not call the app handler
        }

        if(handler) {
            return handler(childURL, childError);
        }

        return NO;
    };
    NSDirectoryEnumerator* result = %orig(url, keys, mask, filteredHandler);
    
    if(result) {
        objc_setAssociatedObject(result, _NSDirectoryEnumerator_shdw_key, [url path], OBJC_ASSOCIATION_RETAIN_NONATOMIC);

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
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfFileSystemForPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
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
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        return nil;
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
    if(isCallerExternal() && ([_shadow isURLRestricted:originalItemURL options:shdw_restriction_write_options()] || [_shadow isURLRestricted:newItemURL options:shdw_restriction_write_options()])) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:originalItemURL];
        }

        return NO;
    }

    // Subtree preflight: replacing a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && [originalItemURL isFileURL]
        && shdw_has_restricted_descendant([originalItemURL path], shdw_restriction_write_options())) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:originalItemURL];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && ([_shadow isURLRestricted:srcURL options:nil] || [_shadow isURLRestricted:dstURL options:shdw_restriction_write_options()])) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:srcURL];
        }

        return NO;
    }

    // Subtree preflight: copying a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && [srcURL isFileURL]
        && shdw_has_restricted_descendant([srcURL path], nil)) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:srcURL];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        if([_shadow isPathRestricted:srcPath options:_shdw_optionsForAbsolute(self, [srcPath isAbsolutePath])]
            || [_shadow isPathRestricted:dstPath options:_shdw_writeOptions(self, [dstPath isAbsolutePath])]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:srcPath];
            }

            return NO;
        }

        // Subtree preflight: copying a directory that contains a restricted
        // descendant must be denied even when the root itself is allowed.
        if(shdw_has_restricted_descendant(srcPath, _shdw_optionsForAbsolute(self, [srcPath isAbsolutePath]))) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:srcPath];
            }

            return NO;
        }
    }

    return %orig;
}

- (BOOL)moveItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && ([_shadow isURLRestricted:srcURL options:shdw_restriction_write_options()] || [_shadow isURLRestricted:dstURL options:shdw_restriction_write_options()])) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:srcURL];
        }

        return NO;
    }

    // Subtree preflight: moving a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && [srcURL isFileURL]
        && shdw_has_restricted_descendant([srcURL path], shdw_restriction_write_options())) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:srcURL];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        if([_shadow isPathRestricted:srcPath options:_shdw_writeOptions(self, [srcPath isAbsolutePath])]
            || [_shadow isPathRestricted:dstPath options:_shdw_writeOptions(self, [dstPath isAbsolutePath])]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:srcPath];
            }

            return NO;
        }

        // Subtree preflight: moving a directory that contains a restricted
        // descendant must be denied even when the root itself is allowed.
        if(shdw_has_restricted_descendant(srcPath, _shdw_writeOptions(self, [srcPath isAbsolutePath]))) {
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
    if(isCallerExternal() && ([_shadow isURLRestricted:srcURL options:nil] || [_shadow isURLRestricted:dstURL options:shdw_restriction_write_options()])) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:srcURL];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)linkItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal()) {
        if([_shadow isPathRestricted:srcPath options:_shdw_optionsForAbsolute(self, [srcPath isAbsolutePath])]
            || [_shadow isPathRestricted:dstPath options:_shdw_writeOptions(self, [dstPath isAbsolutePath])]) {
            if(error) {
                *error = [Shadow fileNoSuchFileErrorForPath:srcPath];
            }

            return NO;
        }
    }

    return %orig;
}

- (BOOL)removeFileAtPath:(NSString *)path handler:(id)handler __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_writeOptions(self, [path isAbsolutePath])]) {
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
    if(isCallerExternal() && [_shadow isURLRestricted:url options:shdw_restriction_write_options()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_writeOptions(self, [path isAbsolutePath])]) {
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
    if(isCallerExternal() && [_shadow isURLRestricted:URL options:shdw_restriction_write_options()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:URL];
        }

        return NO;
    }

    // Subtree preflight: removing a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && [URL isFileURL]
        && shdw_has_restricted_descendant([URL path], shdw_restriction_write_options())) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:URL];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_writeOptions(self, [path isAbsolutePath])]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return NO;
    }

    // Subtree preflight: removing a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && shdw_has_restricted_descendant(path, _shdw_writeOptions(self, [path isAbsolutePath]))) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)trashItemAtURL:(NSURL *)url resultingItemURL:(NSURL * _Nullable *)outResultingURL error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:shdw_restriction_write_options()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }

        return NO;
    }

    // Subtree preflight: trashing a directory that contains a restricted
    // descendant must be denied even when the root itself is allowed.
    if(isCallerExternal() && [url isFileURL]
        && shdw_has_restricted_descendant([url path], shdw_restriction_write_options())) {
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

%group shadowhook_NSFileManagerSymbolicLinks
%hook NSFileManager
- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path error:(NSError * _Nullable *)error __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_optionsForAbsolute(self, [path isAbsolutePath])]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:path];
        }

        return nil;
    }

    NSString* result = %orig;

    // Both-sides validation: the link is allowed but its destination may
    // point into a restricted tree. Error names the caller-supplied link.
    if(result && isCallerExternal()) {
        NSString* resolvedDest = _shdw_resolveLinkDestination(path, result);

        if(resolvedDest && [_shadow isPathRestricted:resolvedDest options:_shdw_optionsForAbsolute(self, [resolvedDest isAbsolutePath])]) {
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

void shadowhook_NSFileManagerSymbolicLinks(SHDWHookSession* hooks) {
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
void* shdw_NSFileManagerFileExistsOriginal(void) { return gShadowFileExistsOrig; }
void* shdw_NSFileManagerFileExistsHook(void) { return gShadowFileExistsHook; }

void shadowhook_NSFileManager(SHDWHookSession* hooks) {
    Class fmCls = objc_getClass("NSFileManager");
    SEL fmSel = sel_registerName("fileExistsAtPath:");
    Method fm = class_getInstanceMethod(fmCls, fmSel);
    if (fm) gShadowFileExistsOrig = (void*)method_getImplementation(fm);
    %init(shadowhook_NSFileManager);
    if (fm) gShadowFileExistsHook = (void*)method_getImplementation(fm);
    if (!gShadowFileExistsOrig) {
        IMP orig = SHDWOriginalImplementationForMethod(fm);
        if (orig) gShadowFileExistsOrig = (void*)orig;
    }
    shadowhook_NSFileManagerSymbolicLinks(hooks);

    Class fileManager = [NSFileManager class];
    if(class_getInstanceMethod(fileManager, @selector(copyPath:toPath:handler:))
    && class_getInstanceMethod(fileManager, @selector(movePath:toPath:handler:))
    && class_getInstanceMethod(fileManager, @selector(linkPath:toPath:handler:))) {
        %init(shadowhook_NSFileManagerDeprecatedPaths);
    }
}
