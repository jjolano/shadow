# HookKit

A slim iOS developer framework that unifies four hooking backends behind one API.

## Backends

The best backend available on the device is picked at runtime, in priority order: ElleKit > Cydia Substrate > Substitute > fishhook. fishhook is compiled in and always present, making it the fallback floor. Backends are not packaged separately: the single package `me.jjolano.fmwk.hookkit` works on every jailbreak. (This replaces the v1 Modulous plugin-bundle architecture.)

| Backend         | Message | Function | Memory | Batching |
|-----------------|---------|----------|--------|----------|
| ElleKit         | yes     | yes      | yes    | yes      |
| Cydia Substrate | yes     | yes      | no     | no       |
| Substitute      | yes     | yes      | no     | no       |
| fishhook        | no      | yes*     | no     | no       |

\* Exported symbols only, rebinding by symbol name (see the fishhook caveat below).

## Usage

```objc
HKSubstitutor *sub = [HKSubstitutor defaultSubstitutor]; // or substitutorWithTypes:

// Batching defers all hooks until executeHooks.
HKEnableBatching();

void (*orig_malloc)(void *);
HKHookFunction(&malloc, &my_malloc, &orig_malloc);

[sub hookMessageInClass:[NSString class]
           withSelector:@selector(length)
         withReplacement:&my_length
               outOldPtr:&orig_length];

HKExecuteBatch();
```

`HKHookMessage`, `HKHookMemory`, `HKOpenImage`, and `HKFindSymbol` macros are also available.

## Semantics

- Symbol names are Substrate-style: C symbols carry no leading underscore (`"malloc"`); C++ mangled names keep theirs. ElleKit accepts both forms; the Substrate/MS and fishhook backends pass names through unchanged.
- Status codes: `HK_OK`, `HK_ERR`, `HK_ERR_NOT_SUPPORTED`, `HK_ERR_INVALID_ARGUMENT`, `HK_ERR_PARTIAL`. Batch and `findSymbolsInImage:` can return `HK_ERR_PARTIAL`.
- fishhook caveat: rebinding is by symbol name, so private/interior addresses are not rebindable; there is no arm64e PAC handling; `old_ptr` reflects the state at hook time (fishhook retains the rebinding for all future image loads).
- Requested but unavailable backends are not silently substituted: hook calls return `HK_ERR_NOT_SUPPORTED` and `activeType` is `HK_LIB_NONE`. Check `activeType` before relying on a backend.
- Threading: the batch queue is not thread-safe (enqueue and `executeHooks` must not race); the native Substitute API additionally requires the main thread.
- Batch storage lifetime: while batching, `old_ptr` is only written by `executeHooks` and is never retained past it.

## Building

Requires [Theos](https://theos.dev). RootBridge.framework is checked in under `vendor/` for linking; the package depends on `me.jjolano.fmwk.rootbridge` at runtime, which is built separately (build the RootBridge repo and install the framework to `$THEOS/lib`).

```
./build.sh all|rootless|rooted|legacy
```

- `rootless` — iphoneos-arm64 deb.
- `rooted` — iphoneos-arm deb.
- `legacy` — 32-bit armv7/armv7s, iOS 9+, deb renamed with a `-legacy` suffix.

Deployment floor is iOS 12. On that floor Theos bumps the arm64e slice minos to 14.0; a build-time warning about this is expected and known.

## Advantages and Disadvantages

Advantages:

- Improved performance through use of batch hooking (if available).
- Ability to utilize different hooking libraries from your tweak. [Shadow](https://github.com/jjolano/shadow) is the primary consumer and provides this functionality.

Disadvantages:

- Library-specific functionality is not implemented: the Substrate-compatible backends offer no memory patching or batching, and fishhook only hooks exported C symbols.
- Existing tweaks will need to be rewritten/recompiled to use HookKit.

## Credits

- [fishhook](https://github.com/facebook/fishhook)
- [libhooker](https://github.com/coolstar/libhooker) / [ElleKit](https://github.com/evelyneee/ellekit)
- [Substitute](https://github.com/sbingner/substitute)
- [Cydia Substrate](http://www.cydiasubstrate.com)
- [RootBridge](https://github.com/jjolano/RootBridge)
