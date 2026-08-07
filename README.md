# HookKit

A slim iOS developer framework that unifies seven hooking backends behind one API.

## Backends

The best backend available on the device is picked at runtime, in priority order: ElleKit > Cydia Substrate > Substitute > Dobby > fishhook. fishhook and Dobby are compiled in and always present on their architectures, making them the fallback floors: Dobby is the floor on arm64/arm64e, fishhook the floor on armv7. Frida is never picked automatically — opt in with `HK_LIB_FRIDA`. Backends are not packaged separately: the single package `me.jjolano.fmwk.hookkit` works on every jailbreak. (This replaces the v1 Modulous plugin-bundle architecture.)

To override the priority order, pass an explicit list with `substitutorWithOrderedTypes:` — the first available entry wins:

```objc
HKSubstitutor *sub = [HKSubstitutor substitutorWithOrderedTypes:@[@(HK_LIB_SUBSTRATE), @(HK_LIB_FISHHOOK), @(HK_LIB_ELLEKIT)]];
```

`native` is HookKit's own engine and is **never picked automatically** — opt in with `[HKSubstitutor substitutorWithTypes:HK_LIB_NATIVE]`.

`Frida` (via the HKGum wrapper dylib) is likewise **never picked automatically** — opt in with `[HKSubstitutor substitutorWithTypes:HK_LIB_FRIDA]`.

| Backend         | Message | Function | Memory | Batching |
|-----------------|---------|----------|--------|----------|
| ElleKit         | yes     | yes      | yes    | yes      |
| Cydia Substrate | yes     | yes      | no     | no       |
| Substitute      | yes     | yes      | no     | no       |
| native          | yes     | yes**    | yes    | yes      |
| Dobby           | no      | yes***   | yes    | no       |
| Frida           | no      | yes****  | no     | yes      |
| fishhook        | no      | yes*     | no     | no       |

\* Exported symbols only, rebinding by symbol name (see the fishhook caveat below).

\*\* arm64/arm64e only (see the native caveat below).

\*\*\* arm64/arm64e only; inline patching needs relaxed codesigning (see the Dobby caveat below).

\*\*\*\* iOS 14+ and arm64/arm64e only; inline patching needs relaxed codesigning (see the Frida caveat below).

### native

HookKit's own hooking engine, requiring no hooking library to be installed on the device. It implements inline function hooking with an ARM64 instruction relocator, memory patching, ObjC message hooking through the runtime, and symbol lookup that reads private symbols out of the dyld shared cache's local symbol table.

It is opt-in rather than the default so that devices with a battle-tested engine installed keep using it. Use it when you need HookKit to stand alone, or to dogfood it before promoting it.

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
- fishhook caveat: rebinding is by symbol name, so private/interior addresses are not rebindable; `old_ptr` reflects the state at hook time (fishhook retains the rebinding for all future image loads). arm64e PAC is handled: `__auth_got` slots are resigned with the asia key and slot-address discriminator, and `old_ptr` is resigned to the plain function-pointer scheme. A hook whose symbol no loaded image references is refused (`HK_ERR_NOT_SUPPORTED`) instead of silently succeeding. The rebinding list is thread-safe.
- native caveat: arm64/arm64e only — on armv7 it reports unavailable, since those devices always have Substrate. Inline patching needs relaxed codesigning, which holds in a tweak-injected process but not in an unmodified one. Function hooks are refused (`HK_ERR`, `errno` `-2`) on targets too short to patch without clobbering the function that follows them. Hooks must be installed at load time: the patch is not atomic and so is not safe against code already running on another thread. Shared cache symbol parsing depends on the cache layout and should be re-verified each major iOS release.
- Dobby caveat: inline patching needs relaxed codesigning (same constraint as native). arm64/arm64e only — on armv7 it reports unavailable. Interior/private C functions are hookable by address (beyond fishhook's exported-symbols-only limit). No ObjC message hooking.
- Frida caveat: hooks through the `HKGum.dylib` wrapper (frida-gum devkit, LGPL-2.1 with wxWindows exception) dlopen'd at runtime — the framework never links gum directly. The devkit's minos=14.0 means iOS 14+ only; on iOS 12/13 dyld refuses to load the wrapper, so dlopen failure gates it. arm64/arm64e only (no armv7 gum devkit). Inline patching needs relaxed codesigning (same as native/Dobby). Hooks must be installed at load time: the prologue patch is not atomic and so is not safe against code already running on another thread. No ObjC message hooking.
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
- [Dobby](https://github.com/jmpews/Dobby)
- [frida-gum](https://github.com/frida/frida-gum)
- [libhooker](https://github.com/coolstar/libhooker) / [ElleKit](https://github.com/evelyneee/ellekit)
- [Substitute](https://github.com/sbingner/substitute)
- [Cydia Substrate](http://www.cydiasubstrate.com)
- [RootBridge](https://github.com/jjolano/RootBridge)
