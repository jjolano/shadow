# Shadow v5 — Plan

Next major version of Shadow. Rootless-first architecture with equal-weight dual (rootless + rootful) support. AI-assisted development.

## Context (research, 2026-08-06)

- iOS 16+ on arm64e (A12+) is **rootless-only** (Dopamine 15.0-16.6.1, XinaA15 dead). Rootful still exists via palera1n (checkm8, iOS 15-18.x, full-root mode) and roothide Bootstrap (15-17).
- iOS 18 A12+ has **no public jailbreak** (DarkSword chain patched; no PPL/SPTM bypass public as of mid-2026).
- **Target matrix**: Dopamine (15-16.6.1) + palera1n (15-18.x), both rootless and rootful flavors. Design must not block future A12+ iOS 17/18 jailbreaks.
- ElleKit is the standard hooking library (Dopamine/palera1n, maintained, Substrate/libhooker-compatible). Substitute is effectively dead on iOS 16+ (C-function hooking broken). fishhook = fallback.
- Shadow upstream is abandoned (last release v3.7.6, May 2023). Known rootless issues: #171 (Dynamic Libraries works only on rootful), #146 (partial bypass palera1n 16.3.1), crashes in Dynamic Libraries / File System / Enhanced Path Processing.
- **New detection technique**: apps read `dyld_all_image_infos` directly from memory (bypasses dyld API hooks entirely). Current Shadow does not cover this.

## Decisions

1. **Dual support, equal weight**: rootless + rootful both fully supported, one codebase.
2. **Rootless-first architecture**: every restriction decision flows through a canonical-path resolver that checks both rooted and `/var/jb`-expanded forms.
3. **Dependency reduction (W0)**: RootBridge stays (38 lines, correct). HookKit collapsed to a slim direct-hooking layer (ElleKit + fishhook, no plugin system). Modulous deleted.
4. ElleKit default backend, fishhook fallback, Substitute removed from options.
5. Build floor iOS 15.0; archs arm64 + arm64e only.

## Architecture

```
app query (path/URL/scheme)
        │
        ▼
hooks (filesystem, foundation, dyld, ...) ──► Shadow Core
                                                   │
                                                   ▼
                                   canonical-path resolver (rootless-aware)
                                                   │
                                                   ▼
                                        rulesets (flavor-agnostic plists)
                                                   │
        ┌──────────────────────────────────────────┘
        ▼
rootless:  /var/jb/<path> + /private/preboot/<hash>  expanded forms
rootful:   <path> as-is
```

- Rulesets stay rooted-flavored and readable; the resolver expands concrete queries against both forms.
- Hooking via HKSubstitutor API (preserved): ElleKit (libhooker API) + fishhook compiled in; per-app selection from prefs (`auto` → ElleKit if libhooker loadable, else fishhook).

## Workstreams

### W0 — Dependency reduction
- **HookKit v2**: same public API (`HKSubstitutor`, macros, `hookkit_h` guard, types); backends ElleKit + fishhook compiled in directly; runtime backend availability via `dlopen([RootBridge getJBPath:@"/usr/lib/libhooker.dylib"])`; explicit `hookkit_lib_t` bits; ids preserved from existing module identifiers for pref compatibility; batching semantics preserved (ElleKit batches, fishhook immediate). Delete: Modulous, bundles, Substrate/Substitute/Dobby/libhooker-standalone modules.
- **Shadow repo**: remove Modulous submodule, update HookKit pointer/vendoring, strip Modulous refs from Makefiles/control.
- Verify: `make` with Linux theos (iPhoneOS 16.5 SDK, arm64/arm64e).

### W1 — Restriction engine rewrite
- Replace `Core.m` rootless fast-path (119-128) with canonical-path resolution: query checked as-is + `/var/jb`-expanded; fix `/usr/lib` existence check (Core.m:133) to probe prefixed path on rootless.
- Rulesets: add `/var/jb/*` + `/private/preboot/*` entries to `JailbreakMisc.plist`; `StandardRules.plist` stays rootfs-structure (flavor-agnostic by design).
- Keep `shdw -g` regeneration (already rootless-aware via getJBPath).

### W2 — dyld layer
- **Memory-level hiding**: patch `dyld_all_image_infos` so injected dylibs are invisible to direct memory reads. Feature-flagged, rootless-first, highest risk.
- Fix relative-`dlopen` resolution (dyld.x:61/84/107) to be rootless-aware.
- Keep API-level hooks as cheap layer.

### W3 — Crash fixes + hook library
- Fix #171 (Dynamic Libraries on rootless), #146 partial bypass, crash groups (Dynamic Libraries / File System / Enhanced Path Processing).
- `HK_Library` default `auto` → ElleKit; drop Substitute from Settings options.

### W4 — Build system + settings
- Keep dual build (build.sh both passes). `ARCHS = arm64 arm64e`, `TARGET ...:15.0`.
- Delete dead `ROOTLESS_MODE` localization strings (zh-Hans/zh-Hant Hooks.strings).
- No rootless toggle — flavor auto-detected.

### W5 — Verification matrix (needs hardware)
- Devices: Dopamine rootless + palera1n (rootless and rootful).
- Test apps: freeRASP, iOS Security Suite, custom dyld-all-image-infos probe.
- Per-wave device tests; `.debs` produced by build.sh.

## AR — IOSSecuritySuite arms race (2026-08-06)

Audited IOSSecuritySuite master (v2.2.0, HEAD 7436aea) against this repo. It has five
shadow-specific detectors: dyld image scan (`"shadow"` substring), `ShadowRuleset`+
`internalDictionary` ObjC probe, `me.jjolano.shadow.plist` + `ShadowPreferences.bundle`
paths, `amIRuntimeHooked` (auto-runs `denyFishHook("dladdr")`), `amIMSHooked` (prologue
signature scan — only catches inline hooks, not fishhook GOT rebinding).

- **AR1 — Identity hygiene (REVERTED 2026-08-06)**: the artifact/string rename was
  reversed — shipped names are back to v3: `Shadow.dylib` + `Shadow.plist`,
  `Shadow.framework`, `ShadowSettings.bundle`, BUNDLE_ID `me.jjolano.shadow`,
  `ShadowSettings` class. Kept from that batch: `RulesetEngine` class +
  `payloadDictionary` method, `SystemRulesGenerator` + tbd class entries. Built deb verified:
  zero hits for all five probe signatures. Only `Shadow`/`ShadowBackend` class names and
  `kShadowRestriction*` constants remain (not probed; renaming ShadowRuleset was the
  suite-tracked API, `Shadow` itself is not).
- **AR2 — dyld memory hiding (DONE, feature-flagged)**: filtered `dyld_all_image_infos`
  mirror (vm_allocate'd `dyld_image_info[]` rebuilt on add/remove callbacks, os_unfair_lock,
  live-struct patch via vm_protect with protection restore, fail-soft). Flag: `MemoryLevelHiding`
  prefs key, default OFF; forced ON when a detector is present. task_info hack kept for
  pre-modern iOS. Fix relative-`dlopen` rootless resolution still pending.
- **AR3 — Hook stealth (DONE)**: three substitutors — `subMain` (user pref), `subFish`
  (fishhook, C-function groups), `subInline` (ElleKit, pinned for dladdr/dlsym/dlopen_internal
  so `denyFishHook("dladdr")` can't revert them). C groups route to fishhook when available;
  ObjC groups stay ElleKit. Per-instance batching.
- **AR4 — Detector escalation (DONE)**: `%ctor` scans loaded images for `iossecuritysuite`/
  `freerasp` (case-insensitive) before hooks install; when present, memory hiding forces ON
  and C groups pin to fishhook regardless of `HK_Library` pref.
- **AR5 — Remaining gaps (2026-08-06, deep-dive + ruleset fix)**: Deep-dive of suite master
  (MSHookFunctionChecker/FishHookChecker/RuntimeHookChecker/JailbreakChecker source) confirms:
  **all hook-detection is strictly opt-in** — `amIJailbroken()`/`WithFailedChecks` never call
  `amIMSHooked`/`amIRuntimeHooked`/`denyMSHook`/`denyFishHook`/`denySymbolHook`. The only
  automatic anti-evasion is `checkDYLD` (uses `_dyld_image_count`/`_dyld_get_image_name` —
  both hooked by shadow) + the `ShadowRuleset`/`internalDictionary` ObjC probe (class+method
  renamed). `denyMSHook` does NOT unpatch hooks — it only locates the original stub (returns
  nil for fishhook hooks); `denyFishHook` reverts GOT slots only (inline ElleKit dladdr/dlsym
  hooks are immune — subInline routing is correct). The suite NEVER reads `dyld_all_image_infos`
  directly (no `_dyld_get_all_image_infos`, no `task_info`, no `dyld_process_info_create`) —
  W2 memory hiding is defense-in-depth for freeRASP-style readers, not required by the suite.
  Residual accepted: an app that explicitly calls `amIMSHooked`/`denyMSHook` on exactly the
  inline-hooked functions (dladdr/dlsym/dlopen_internal, objc runtime C hooks) can see/locate
  those templates; `getMachOFileHashValue` (SHA256 of `__TEXT.__text`) detects inline patches
  but is opt-in + needs pinned values. **G3 fix applied**: names were reverted to original
  (Shadow.*/me.jjolano.shadow), so added `/Library/MobileSubstrate/` to JailbreakMisc
  BlacklistPaths (rootful `Shadow.dylib` + `MobileSubstrate.dylib` file checks; rootless
  already covered by `/var/jb` fast-path; `me.jjolano.shadow.plist` covered by FileSystemStructure
  compliance veto; `ShadowPreferences.bundle` is a name mismatch — bundle ships as
  `ShadowSettings.bundle`). Rotation is now ruleset-driven, not name-driven.

## Risks

- W2 memory-level hiding: hard (arm64e PAC, per-jailbreak layout) — feature-flagged so failure doesn't sink release.
- No A12+ iOS 17/18 jailbreak to test on — avoid version-specific assumptions where possible.
- Device testing is the bottleneck; software builds verify locally via Linux theos, but nothing is verified until on-device.

## Status

- [x] Research + decisions
- [x] W0 dependency reduction (HookKit v2: ElleKit/Substrate/Substitute/fishhook backends; Modulous deleted; control cleaned)
- [x] W1 restriction engine (jbroot-aware canonical evaluation, existence gating, /var/jb ruleset coverage)
- [x] W2 dyld layer (dyld_all_image_infos memory-level hiding + rootless dlopen working-dir fix)
- [ ] W3 crash fixes + hook lib (on-device diagnosis pending; detector-escalation routing landed as AR4)
- [x] AR1 identity hygiene
- [x] AR2 dyld memory hiding (feature-flagged, on-device verification pending)
- [x] AR3 hook stealth backends
- [x] AR4 detector escalation
- [x] W4 build system (3-pass: rootless/rooted/legacy; floors 15/12/9; framework export list; all packages build green)
- [ ] W5 device verification (kit ready: dyldprobe app + debug builds + matrix below)

## W5 — Device verification

**Debug package (NSLog enabled) for diagnosis:** `make package debug=1` (rootless: `THEOS_PACKAGE_SCHEME=rootless` + TARGET 15.0). theos adds `-DDEBUG -O0`; production debs compile NSLog out (common.h).

**Probe app:** `tools/dyldprobe` — debs in `tools/dyldprobe/build/` (rooted + rootless). Shows the jailbreak from 4 angles: direct `dyld_all_image_infos` memory read (W2's target), dyld API view, JB path existence, URL scheme openability. Run with Shadow disabled for the app (baseline) then enabled-all-hooks (test) and diff the two reports.

**Matrix** (per device: baseline vs Shadow-on, compare):

| Device | Jailbreak | Package |
|---|---|---|
| A12+ | Dopamine (rootless) | `..._iphoneos-arm64.deb` |
| A8–A11 | palera1n rootless | `..._iphoneos-arm64.deb` |
| A8–A11 | palera1n rootful | `..._iphoneos-arm.deb` |
| 32-bit | h3lix-era | `...-legacy.deb` |

**Checks per device:**
1. dyldprobe entries 1–4 all clean with Shadow on (no non-system images, no JB paths, schemes not openable)
2. freeRASP sample app (Talsec) passes
3. IOSSecuritySuite demo passes (amIJailbroken etc.)
4. #171/#146 regression: Dynamic Libraries hook on rootless — no crash, injected dylibs hidden
5. Ruleset rotation: install a package → rulesets reload via mtime watch without respring
