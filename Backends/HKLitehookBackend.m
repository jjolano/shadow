#import "Internal/HKBackendInternal.h"

#import <errno.h>

#if __has_include(<ptrauth.h>)
#import <ptrauth.h>
#endif

#import "native/hk_arm64.h"
#import "vendor/litehook/litehook.h"

#pragma mark - HKLitehookBackend

@implementation HKLitehookBackend
- (void)setStrategy:(HKStrategy)strategy {
#if !defined(__arm64__) && !defined(__arm64e__)
    if(strategy == HKStrategyInline) {
        // litehook's inline trampolines emit AArch64 instructions only, so
        // inline is unavailable on 32-bit archs: refuse it and keep the
        // vendor default (rebind) rather than corrupting the prologue.
        _lastErrno = ENOTSUP;
        return;
    }
#endif
    _strategy = strategy;
}

// Shared by hookFunction:'s inline branch and preflightFunction: so the
// router and the direct path decline exactly the same targets. Reads only
// the overwrite window and never writes; a reject leaves the target intact.
- (hookkit_status_t)hk_litehook_inline_preflight:(void *)function replacement:(void *)replacement {
    if(((uintptr_t)function & 0x3) != 0) {
        _lastErrno = EINVAL;
        return HK_ERR_NOT_SUPPORTED;
    }

    if(function == replacement) {
        _lastErrno = EINVAL;
        return HK_ERR_NOT_SUPPORTED;
    }

    if(hk_arm64_has_early_terminator(function, 20)) {
        // Function ends inside the 20-byte overwrite window: patching would
        // smash a neighbor's bytes.
        _lastErrno = EOPNOTSUPP;
        return HK_ERR_NOT_SUPPORTED;
    }

    if(hk_arm64_has_aarch64_literal_load(function, 20)) {
        // Literal load / ADR(Ps) in the overwrite window: litehook copies the
        // window to the trampoline verbatim, smashing the pool or address the
        // instruction points at.
        _lastErrno = EOPNOTSUPP;
        return HK_ERR_NOT_SUPPORTED;
    }

    return HK_OK;
}

- (hookkit_status_t)preflightFunction:(void *)function withReplacement:(void *)replacement {
    // Rebind/memory techniques have no prologue constraints; only the inline
    // trampoline overwrites the target's bytes.
    if(_strategy != HKStrategyInline) {
        return HK_OK;
    }

    return [self hk_litehook_inline_preflight:function replacement:replacement];
}

- (BOOL)batchingSupported {
    return NO;
}

- (BOOL)supportsHookKind:(HKHookKind)kind {
    return kind == HKHookKindFunction || kind == HKHookKindMemory;
}

- (int)lastErrno {
    return _lastErrno;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    _lastErrno = 0;

#if __has_feature(ptrauth_calls)
    // Strip PAC so the raw address matches GOT slots (arm64e). Replacement is
    // stripped too so the self-hook check below compares raw addresses.
    function = ptrauth_strip(function, ptrauth_key_asia);
    replacement = ptrauth_strip(replacement, ptrauth_key_asia);
#endif

    if(_strategy == HKStrategyInline) {
#if !defined(__arm64__) && !defined(__arm64e__)
        // litehook's inline trampoline emits AArch64 opcodes unconditionally
        // (4x MOVK + BR), so on 32-bit archs it would write ARM64 garbage into
        // an ARMv7 prologue. Refuse explicitly — never fall back to rebinding,
        // which the caller did not ask for.
        _lastErrno = EOPNOTSUPP;
        return HK_ERR_NOT_SUPPORTED;
#endif
        // Prologue inline trampoline variant (denyFishHook-immune). litehook
        // has no original-call trampoline, so the original body is gone once
        // hooked: old_ptr stays NULL when requested.
        hookkit_status_t preflight = [self hk_litehook_inline_preflight:function replacement:replacement];

        if(preflight != HK_OK) {
            // Refused before any write: the target's prologue cannot be
            // overwritten safely (see hk_litehook_inline_preflight).
            return preflight;
        }

        kern_return_t kr = litehook_hook_function(function, replacement);
        _lastErrno = kr;

        if(old_ptr) {
            *old_ptr = NULL;
        }

        return kr == KERN_SUCCESS ? HK_OK : HK_ERR;
    }

    // Address/exported-symbol based: rebinds all images' GOT/import slots
    // whose value equals `function`. No original-call trampoline — the
    // function body at `function` is untouched, so `function` is still the
    // original implementation (same semantic as fishhook's old_ptr).
    unsigned int matched = 0;
    kern_return_t kr = litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, function, replacement, NULL, &matched);

    if(kr != KERN_SUCCESS) {
        _lastErrno = kr;
        return HK_ERR;
    }

    // The tally is captured under the same lock as the apply. Zero rewritten
    // slots means no loaded image references the function through a GOT/import
    // slot — a silent no-op, so report it as an error instead of a false HK_OK.
    if(matched == 0) {
        _lastErrno = ENOENT;  // no GOT slot referenced this function
        return HK_ERR;
    }

    if(old_ptr) {
        *old_ptr = function;
    }

    return HK_OK;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    kern_return_t kr = litehook_hook_memory(target, (void *)data, size);
    _lastErrno = kr;
    return kr == KERN_SUCCESS ? HK_OK : HK_ERR;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    // nothing pending: function hooks and memory patches apply at hook time
    return HK_OK;
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    // DSC/private-symbol resolution is path-keyed, and HKDlfcnBackend's image
    // handle carries no path, so a handle-based lookup has nothing to search
    // and falls straight through to super.
    // ponytail: litehook's DSC lookup strcmps the path, so its nil-path
    // variant would crash — instead, enumerate the loaded images' paths,
    // which mirrors super's no-handle scan anyway.
    if(_strategy == HKStrategyPrivateSymbol && !image) {
        const char *plain = [symbolName UTF8String];
        // DSC nlist names keep the leading underscore; dlsym-style names
        // (what callers pass) do not — try both
        NSString *underscored = [symbolName hasPrefix:@"_"] ? nil : [@"_" stringByAppendingString:symbolName];

        void *found = hk_search_loaded_images(^void *(const char *image_name) {
            void *result = litehook_find_dsc_symbol(image_name, plain);

            if(!result && underscored) {
                result = litehook_find_dsc_symbol(image_name, [underscored UTF8String]);
            }

            return result;
        });

        if(found) {
            return found;
        }
    }

    return [super findSymbolInImage:image symbolName:symbolName];
}
@end