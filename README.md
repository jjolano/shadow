# HookKit

A slim iOS developer framework that unifies eight hooking backends behind one API.

## Backends

The best backend available on the device is picked at runtime, in priority order: ElleKit > Cydia Substrate > Substitute > Dobby > fishhook. fishhook and Dobby are compiled in and always present on their architectures, making them the fallback floors: Dobby is the floor on arm64/arm64e, fishhook the floor on armv7. Frida is never picked automatically — opt in with `HK_LIB_FRIDA`. Swift vtables (opt-in, `HK_LIB_SWIFT`) hook Swift class methods through the class metadata vtable — a separate API, not a message/function hooking engine. Backends are not packaged separately: the single package `me.jjolano.fmwk.hookkit` works on every jailbreak. (This replaces the v1 Modulous plugin-bundle architecture.)

To override the priority order, pass an explicit list with `substitutorWithOrderedTypes:` — the first available entry wins:

```objc
HKSubstitutor *sub = [HKSubstitutor substitutorWithOrderedTypes:@[@(HK_LIB_SUBSTRATE), @(HK_LIB_FISHHOOK), @(HK_LIB_ELLEKIT)]];
```

`native` is HookKit's own engine and is **never picked automatically** — opt in with `[HKSubstitutor substitutorWithTypes:HK_LIB_NATIVE]`.

`Frida` (via the HKGum wrapper dylib) is likewise **never picked automatically** — opt in with `[HKSubstitutor substitutorWithTypes:HK_LIB_FRIDA]`.

`Swift` (vtable hooking) is likewise **never picked automatically** — opt in with `[HKSubstitutor substitutorWithTypes:HK_LIB_SWIFT]` and use the `hookSwiftMethodInClass:withName:...` / `hookSwiftVtableSlotInClass:withIndex:...` API.

| Backend         | Message | Function | Memory | Batching |
|-----------------|---------|----------|--------|----------|
| ElleKit         | yes     | yes      | yes    | yes      |
| Cydia Substrate | yes     | yes      | no     | no       |
| Substitute      | yes     | yes      | no     | no       |
| native          | yes     | yes**    | yes    | yes      |
| Dobby           | no      | yes***   | yes    | no       |
| Frida           | no      | yes****  | no     | yes      |
| fishhook        | no      | yes*     | no     | no       |
| Swift           | no      | no*****  | no     | no       |

\* Exported symbols only, rebinding by symbol name (see the fishhook caveat below).

\*\* arm64/arm64e only (see the native caveat below).

\*\*\* arm64/arm64e only; inline patching needs relaxed codesigning (see the Dobby caveat below).

\*\*\*\* iOS 14+ and arm64/arm64e only; inline patching needs relaxed codesigning (see the Frida caveat below).

\*\*\*\*\* Swift vtable hooking is a separate API (`hookSwiftMethodInClass:withName:...` / `hookSwiftVtableSlotInClass:withIndex:...`), not the message/function columns (see the Swift caveat below).

### native

HookKit's own hooking engine, requiring no hooking library to be installed on the device. It implements inline function hooking with an ARM64 instruction relocator, memory patching, ObjC message hooking through the runtime, and symbol lookup that reads private symbols out of the dyld shared cache's local symbol table.

It is opt-in rather than the default so that devices with a battle-tested engine installed keep using it. Use it when you need HookKit to stand alone, or to dogfood it before promoting it.

### Swift

HookKit's own Swift vtable engine, sharing the native backend's memory-patching machinery. It rewrites the target method's slot in the class metadata vtable, so Swift callers of the method dispatch to the replacement. Hooks are installed by method name (`$s...`/`_$s...` exact mangled match, or a case-sensitive substring of the demangled name; the match must be unique — ambiguity fails loudly with every candidate logged) or by declaration-order slot index (stable per build, survives symbol stripping). v1 scope: the class's own methods only, non-generic classes, no resilient superclass, no async methods, no class methods, no extensions; `@objc dynamic` methods are hookable the same way (affects Swift callers only). The replacement must be a raw function pointer with the Swift calling convention (self in x20, heap context in x21 on arm64) — an `objc_msgSend`-convention IMP will misbehave. Swift 5 ABI (iOS 12.2+) and arm64/arm64e only.

## Usage

```objc
HKSubstitutor *sub = [HKSubstitutor defaultSubstitutor]; // or substitutorWithTypes:

// Batching defers hooks until executeHooks (batching-capable backends only; others execute immediately).
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
- Swift caveat: vtable hooking via `HK_LIB_SWIFT` (opt-in, never selected automatically). The slot write is a single aligned pointer store (≈ atomic) with no code patching, so no relaxed codesigning is required for the write itself. Devirtualization and inlining can silently bypass vtable dispatch, and KVO-swizzled instances are unaffected. On arm64e the engine validates its signing recipe against the live slot before writing (PAC pre-write self-check): a mismatch fails the hook cleanly instead of corrupting memory. For stripped binaries, use the index API (declaration order, stable per build); name lookup cannot work without symbols. v1 limits: own methods only, non-generic, no resilient superclass, no async, no class methods, no extensions; Swift calling convention required for replacements. Swift 5 ABI (iOS 12.2+) and arm64/arm64e only.
- Requested but unavailable backends are not silently substituted: hook calls return `HK_ERR_NOT_SUPPORTED` and `activeType` is `HK_LIB_NONE`. Check `activeType` before relying on a backend.
- Threading: the batch queue is thread-safe — enqueue may race `executeHooks`, which drains a snapshot under the same lock, so every queued hook runs exactly once. Not synchronized: last-error state (`getLibErrno:` reports the last hook call on that substitutor, from whichever thread made it) and backend selection — settle `types` / `initLibraries` before hooking starts. The native Substitute API additionally requires the main thread.
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
- [apple/swift](https://github.com/apple/swift) — Swift 5 ABI documentation (`include/swift/ABI/Metadata.h`, `MetadataValues.h`, `stdlib/public/runtime/Metadata.cpp`, `lib/IRGen/GenMeta.cpp`), which the Swift vtable backend's offsets and pointer-authentication recipe were verified against
