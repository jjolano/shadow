# HookKit

A slim iOS developer framework that unifies nine hooking backends behind one API.

## Backends

The best backend available on the device is picked at runtime, in priority order: ElleKit > Cydia Substrate > Substitute > Dobby > fishhook — with litehook, native, Frida, and Swift vtables available on request but never picked automatically. fishhook, litehook, and Dobby are compiled in and always present on their architectures, making them the fallback floors: Dobby is the floor on arm64/arm64e, fishhook the floor on armv7. Backends are not packaged separately: the single package `me.jjolano.fmwk.hookkit` works on every jailbreak. (This replaces the v1 Modulous plugin-bundle architecture.)

### Selection

Backends are selected by name, by priority list, or by capability:

- `substitutorWithTypes:` names specific backends; the first available one wins, in the fixed table priority above. `native`, Frida, Swift, and litehook are **never picked automatically** — they only resolve when explicitly named (`substitutorWithTypes:`) or reached through a category.
- To override the priority order, pass an explicit list with `substitutorWithOrderedTypes:` — the first available entry wins:

```objc
HKSubstitutor *sub = [HKSubstitutor substitutorWithOrderedTypes:@[@(HK_LIB_SUBSTRATE), @(HK_LIB_FISHHOOK), @(HK_LIB_ELLEKIT)]];
```

- `substitutorWithCategory:` (`HK_CAT_MESSAGE`, `HK_CAT_FUNCTION_REBIND`, `HK_CAT_FUNCTION_INLINE`, `HK_CAT_PRIVATE_SYMBOL`) picks the first available backend in that category's priority order — callers request a capability, not a library. `substitutorWithOrderedCategories:` tries a list of categories top to bottom, stopping at the first that resolves. The per-category picker orders are:

  - `HK_CAT_MESSAGE` — ElleKit > Cydia Substrate > Substitute > native
  - `HK_CAT_FUNCTION_REBIND` — fishhook > litehook
  - `HK_CAT_FUNCTION_INLINE` — ElleKit > Dobby > Frida > litehook
  - `HK_CAT_PRIVATE_SYMBOL` — ElleKit > Cydia Substrate > Substitute > litehook

- The readonly `activeStrategy` property (one of `HKStrategyDefault`/`HKStrategyRebind`/`HKStrategyInline`/`HKStrategyPrivateSymbol`) reports how the winning backend resolves and applies function hooks — a hooking technique (rebind or inline, or the vendor default), or a resolution mode (`HKStrategyPrivateSymbol`: the backend locates the private/DSC symbol first, then hooks it via rebinding). It is the resolution result, not a request. One vendor can serve several categories: litehook covers rebind, inline, and private-symbol lookups. Swift vtables have no category (`HK_CAT_NONE`) — it is a separate API, not a message/function/memory engine.
- Resolution order: `orderedTypes` > `orderedCategories` > `types`/default. A requested-but-unavailable backend is **not** silently substituted: hook calls return `HK_ERR_NOT_SUPPORTED` and `activeType` is `HK_LIB_NONE`. Check `activeType` before relying on a backend.
- The framework's default set differs from an explicit request: with no types set, only the *automatic* backends are eligible — ElleKit, Cydia Substrate, Substitute, Dobby, or fishhook, in that order, first available wins. The opt-in backends (native, Frida, Swift, litehook) are never eligible for the automatic pick, even when available; explicit `types` can name any of them.
- `getSubstitutorTypeInfo:` returns per-backend metadata including a `selectable` flag for settings-style pickers: substrate, substitute, and swift are excluded from user-facing selection.

### Capability matrix

| Backend         | Message | Function | Memory | Batching |
|-----------------|---------|----------|--------|----------|
| ElleKit         | yes     | yes†     | yes    | yes      |
| Cydia Substrate | yes     | yes      | yes‡   | no       |
| Substitute      | yes     | yes      | yes‡   | no       |
| native          | yes     | yes†     | yes    | yes      |
| Dobby           | no      | yes†     | yes    | no       |
| Frida           | no      | yes†     | no     | yes      |
| fishhook        | no      | yes¶     | no     | no       |
| Swift           | no      | no*      | no     | no       |
| litehook        | no      | yes§     | yes    | no       |

† Function hooking is arm64/arm64e only — these backends report unavailable on armv7 (see the native, Dobby, and Frida caveats).

‡ Via `MSHookMemory` when the installed Cydia Substrate exports it, and via the MS-compatible `SubHookMemory` shim on Substitute — unavailable when the installed library doesn't export it (see the memory caveat).

§ Exported-symbol or GOT-referenced C functions, rebinding by address; the inline variant (`HK_CAT_FUNCTION_INLINE`) has no original-call trampoline (see the litehook caveat).

¶ Exported symbols only, rebinding by symbol name (see the fishhook caveat).

\* Swift vtable hooking is a separate API — `hookSwiftMethodInClass:withName:...` / `hookSwiftVtableSlotInClass:withIndex:...` — not the message/function columns (see the Swift caveat).

### native

HookKit's own hooking engine, requiring no hooking library to be installed on the device. It implements inline function hooking with an ARM64 instruction relocator, memory patching, ObjC message hooking through the runtime, and symbol lookup that reads private symbols out of the dyld shared cache's local symbol table.

It is opt-in rather than the default so that devices with a battle-tested engine installed keep using it. Use it when you need HookKit to stand alone, or to dogfood it before promoting it.

Constraints: arm64/arm64e only — on armv7 it reports unavailable, since those devices always have Substrate. Inline patching needs relaxed codesigning, which holds in a tweak-injected process but not in an unmodified one. Function hooks are refused (`HK_ERR`, `errno` `-2`) on targets too short to patch without clobbering the function that follows them. Hooks must be installed at load time: the patch is not atomic and so is not safe against code already running on another thread. Shared cache symbol parsing depends on the cache layout and should be re-verified each major iOS release.

### Dobby

Vendored static library hooking inline by address, so interior/private C functions are hookable (beyond fishhook's exported-symbols-only limit). arm64/arm64e only — on armv7 it reports unavailable. Inline patching needs relaxed codesigning (same constraint as native). Memory patching is supported; no ObjC message hooking, no batching (hooks apply immediately at hook time).

### Frida

Hooks through the `HKGum.dylib` wrapper (frida-gum devkit, LGPL-2.1 with wxWindows exception) dlopen'd at runtime — the framework never links gum directly, keeping LGPL code out of the framework binary. The wrapper product ships arm64/arm64e only (no armv7 gum devkit), and batching is supported via gum interceptor transactions — `executeHooks` publishes the batch atomically, and partial failures are not rolled back. No memory patching, no ObjC message hooking. Opt-in (`HK_LIB_FRIDA`) — Dobby is compiled in and lighter, so Frida is only picked when explicitly requested.

The wrapper is built with a 9.0/12.0 arm64 floor, so the arm64 slice loads on iOS 12/13; only the arm64e slice carries the 14.0 minos (theos's clang forces arm64e to ≥ 14.0) — see "Building". Inline patching needs relaxed codesigning (same as native/Dobby). Hooks must be installed at load time: the prologue patch is not atomic and so is not safe against code already running on another thread.

### fishhook

Rebinding by exported symbol name: private/interior addresses are not rebindable (`HK_ERR_NOT_SUPPORTED`). `old_ptr` reflects the state at hook time — fishhook retains the rebinding for all future image loads. arm64e PAC is handled: `__auth_got` slots are resigned with the asia key and slot-address discriminator, and `old_ptr` is resigned to the plain function-pointer scheme. A hook whose symbol no loaded image references is refused (`HK_ERR_NOT_SUPPORTED`) instead of silently succeeding — no-op detection via the vendored fork's `rebind_symbols_checked`. The rebinding list is thread-safe. Compiled in on all archs; the floor on armv7.

### litehook

Opt-in (`HK_LIB_LITEHOOK`), never selected automatically, but compiled in and available on every arch. It is strategy-aware via the category system — one backend, three strategies:

- default (`HKStrategyRebind`, `HK_CAT_FUNCTION_REBIND`): GOT/import slot rebinding by address (`litehook_rebind_symbol`), so exported and GOT-referenced C functions are hookable; `old_ptr` is the original function address, which is untouched (no original-call trampoline — same semantic as fishhook's `old_ptr`). A hook whose address no loaded image references through a GOT/import slot is reported as `HK_ERR` instead of a silent no-op.
- `HK_CAT_FUNCTION_INLINE` (`HKStrategyInline`): prologue inline trampolines via `litehook_hook_function`. There is no original-call trampoline — the original body is gone once hooked, so `old_ptr` stays NULL.
- `HK_CAT_PRIVATE_SYMBOL` (`HKStrategyPrivateSymbol`): DSC private-symbol resolution (`litehook_find_dsc_symbol`).
- Memory patching works on every supported arch (arm64e/arm64/armv7s/armv7, iOS 10+) — this is the only compiled-in backend that patches memory on armv7.
- The inline (`HK_CAT_FUNCTION_INLINE`) and private-symbol/DSC (`HK_CAT_PRIVATE_SYMBOL`) strategies are arm64/arm64e only — on armv7/armv7s only the rebind strategy and memory patching remain.

No ObjC message hooking, no batching. MIT-licensed, no runtime dependency beyond libsystem.

### Swift

HookKit's own Swift vtable engine, sharing the native backend's memory-patching machinery. It rewrites the target method's slot in the class metadata vtable, so Swift callers of the method dispatch to the replacement. Hooks are installed by method name (`$s...`/`_$s...` exact mangled match, or a case-sensitive substring of the demangled name; the match must be unique — ambiguity fails loudly with every candidate logged) or by declaration-order slot index (stable per build, survives symbol stripping). v1 scope: the class's own methods only, non-generic classes, no resilient superclass, no async methods, no class methods, no extensions; `@objc dynamic` methods are hookable the same way (affects Swift callers only). The replacement must be a raw function pointer with the Swift calling convention (self in x20, heap context in x21 on arm64) — an `objc_msgSend`-convention IMP will misbehave.

The slot write is a single aligned pointer store (≈ atomic) with no code patching, so no relaxed codesigning is required for the write itself. Devirtualization and inlining can silently bypass vtable dispatch, and KVO-swizzled instances are unaffected. On arm64e the engine validates its signing recipe against the live slot before writing (PAC pre-write self-check): a mismatch fails the hook cleanly instead of corrupting memory. For stripped binaries, use the index API (declaration order, stable per build); name lookup cannot work without symbols. Swift 5 ABI (iOS 12.2+) and arm64/arm64e only. Opt-in (`HK_LIB_SWIFT`), separate API, no category membership.

### memory

`hookMemory:` works via `MSHookMemory` on Cydia Substrate — but only when the installed Substrate exports it (unc0ver-class Substrate does). On Substitute it works via the MS-compatible shim (`MSHookMemory`, which libsubstitute maps to `SubHookMemory`) — not via the native path, which has no separate memory hook; when the shim is absent, `hookMemory:` reports `HK_ERR_NOT_SUPPORTED`. Substitute's function and message hooks go through the native libsubstitute API (`substitute_hook_functions` / `substitute_hook_objc_message`) when available, falling back to the MS-compatible path otherwise, with native-API failures returning `HK_ERR`; neither path is used for raw-address `hookMemory:`.

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
- Status codes: `HK_OK`, `HK_ERR`, `HK_ERR_NOT_SUPPORTED`, `HK_ERR_INVALID_ARGUMENT`, `HK_ERR_PARTIAL`. `HK_ERR_PARTIAL` from `executeHooks` or `findSymbolsInImage:` means some-but-not-all succeeded; per-operation success is visible in the outputs — `executeHooks` writes `old_ptr` only for the operations that succeeded, and `findSymbolsInImage:` reports misses as NULL entries.
- `getLibErrno:` is an opaque backend-specific code — not a plain errno and not a normalized error enum, so do not compare values across backends: for ElleKit it can be a libhooker message-error enum (LBHookMessage's `LIBHOOKER_ERR`) or libhooker's errno (from `LHHookFunctions` / `LHPatchMemory`), for the Substrate/MS APIs it reflects errno observed at submit time (those entry points are void, so success is unverifiable), for native/Dobby/Frida it can be a mach/driver return, and private negative codes are native/Swift engine errors. A rebinding hook that applies to future image loads can report success while no image currently references the symbol (fishhook refuses that case with `HK_ERR_NOT_SUPPORTED`; litehook reports `HK_ERR`). The value is set by the last failing hook call, cleared on success, on argument errors, and on unsupported operations, and must be read immediately on the same thread.
- Threading: configure first — settle `types` / `initLibraries` and the batching mode before any hook call; backend selection is one-shot, the first resolution that finds a backend wins and later calls are no-ops. Hooks install on exactly one thread, normally the main/load thread. Enqueueing may happen from multiple threads (the batch queue is thread-safe — enqueue may race `executeHooks`, which drains a snapshot under the same lock, so every queued hook runs exactly once), but only as long as exactly one thread calls `executeHooks` — concurrent `executeHooks` calls are not serialized. Not synchronized: last-error state — `getLibErrno:` reports the last hook call's per-backend detail; read it immediately, on the same thread that made the call, it is not safe cross-thread. The native Substitute API additionally requires the main thread.
- Batch storage lifetime: while batching, enqueue-time `HK_OK` means "accepted into the queue", not "installed" — only `executeHooks` installs and writes `old_ptr`. The caller's `old_ptr` storage is borrowed: it must stay alive until `executeHooks` returns (it is never retained past it). Disabling batching while operations are queued leaves them queued — they still run at the next `executeHooks` — while new hook calls execute immediately. Batching backends may not preserve submission order across hook kinds (ElleKit partitions operations per kind — messages/functions/memory; a Frida transaction is an atomic publication of the batch, not a rollback on partial failure). Backends without batching ignore the queue: they apply hooks immediately even while batching is on.
- Availability probing: results are cached per process at the first probe — the ElleKit/Substrate/Substitute/Frida probes cache only positive results (a failed probe is retried on a later call), while the Swift probe caches both success and failure.

## Building

Requires [Theos](https://theos.dev). RootBridge.framework is checked in under `vendor/` for linking; the rooted and rootless packages depend on `me.jjolano.fmwk.rootbridge` at runtime, which is built separately (build the RootBridge repo and install the framework to `$THEOS/lib`). The roothide target drops RootBridge (there is no `/var/jb` on roothide) and uses libroothide's `jbroot()` instead.

```
./build.sh all|rootless|rooted|roothide
```

- `rootless` — iphoneos-arm64 deb (arm64/arm64e), iOS 12+.
- `rooted` — one fat iphoneos-arm deb spanning armv7 through arm64e, iOS 9+.
- `roothide` — iOS 15–17 with a random-named jbroot; requires the roothide Theos fork (`THEOS_PACKAGE_SCHEME=roothide`) and libroothide; drops RootBridge.

Theos bumps the arm64e slice minos to 14.0; a build-time warning about this is expected and known.

## Advantages and Disadvantages

Advantages:

- Improved performance through use of batch hooking (if available).
- Ability to utilize different hooking libraries from your tweak. [Shadow](https://github.com/jjolano/shadow) is the primary consumer and provides this functionality.

Disadvantages:

- Library-specific functionality is not implemented uniformly: the Substrate-compatible backends (Cydia Substrate, Substitute) offer no batching, fishhook only hooks exported C symbols, Frida has no memory patching — check `activeType` and the capability matrix before relying on a capability.
- Existing tweaks will need to be rewritten/recompiled to use HookKit.

## Credits

- [fishhook](https://github.com/facebook/fishhook)
- [Dobby](https://github.com/jmpews/Dobby)
- [frida-gum](https://github.com/frida/frida-gum)
- [libhooker](https://github.com/coolstar/libhooker) / [ElleKit](https://github.com/evelyneee/ellekit)
- [litehook](https://github.com/opa334/litehook)
- [Substitute](https://github.com/sbingner/substitute)
- [Cydia Substrate](http://www.cydiasubstrate.com)
- [RootBridge](https://github.com/jjolano/RootBridge)
- [apple/swift](https://github.com/apple/swift) — Swift 5 ABI documentation (`include/swift/ABI/Metadata.h`, `MetadataValues.h`, `stdlib/public/runtime/Metadata.cpp`, `lib/IRGen/GenMeta.cpp`), which the Swift vtable backend's offsets and pointer-authentication recipe were verified against