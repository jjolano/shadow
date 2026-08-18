# Pseudo-sandbox — implementation plan

> Restores a per-app pseudo-sandbox for the injected process: the app sees its stock sandbox view (container + stock system + finite shared carve-outs), everything else → ENOENT/EPERM. Fixes the static-zone escape-hatch tension by making visibility per-process instead of global.

Status: landed — Phase 0-4. Pseudo additive, feature-flagged `OFF`.

## 0. Decision and non-goals

**Why not parse compiled `.sb`:** binary versioned per `SANDBOX_BUILD_ID`, `libsandbox` compiler source removed after 10.8 (shims only), profiles on 16/17 in `kernelcache`+`Sandbox.kext` not `/usr/lib/sandbox/profiles/`, `sandbox_apply()` one-way, deny-stack rejected (`PER-PROCESS-VFS-HIDING.md:115`), Dopamine grant-only. Public parsers (`jtool --sandbox`, SandBlaster) heuristics. Shadow already fakes `sandbox_check→1`.

**Why not kernel vnode (CAP-01):** `VISSHADOW/VNOP_READDIR` per-jailbreak PAC/KTRR — deferred.

**Scope:** userspace hook layer only. Reuses `SystemRulesGenerator` snapshot as stock oracle.

## 1. Architecture (as landed)

```
allow = container (MCM live) + stock system (kSystemZones prefix) + 4 carve-outs
overlay = diff blacklist inside allow
default = ENOENT/EPERM  // fail-closed when strict
```

* Container: `Core.m` MCM scan (`.com.apple.mobile_container_manager.metadata.plist` exactly-one → homePath) + appex `.app/` + group containers from `/private/var/mobile/Containers/Shared/AppGroup`, all `SHADOW_INTERNAL_SCOPE`. `groupContainerPaths` in `ShadowRestrictionContext`.
* Stock: `kSystemZones` prefix in `PseudoSandboxPolicy.m`.
* Carve-outs: `.GlobalPreferences.plist, Preferences/com.apple.*, SplashBoard/com.apple, /tmp/com.apple`.
* Gating: `isCallerExternal()` grants truth to Shadow spans + `SHADOW_INTERNAL_SCOPE`. `hasAppSandbox` appex-aware.
* Enforcement (central, Phase 2): `RestrictionEngine.m:_pathRestrictedQuery` early `shdwPseudoEnforceShouldDeny(craw)` before tilde/workdir, covers absolute + dirfd-joined relative, `resolve-before-exempt` handles container symlink alias `/var/jb`. `dlsym(RTLD_DEFAULT)` + `_shdw_inPseudoEnforce` TLS guard. Per-hook audit only in `PathPolicy.m`/`sandbox.x`.
* Flags: `PseudoSandboxEnabled` (audit) + `PseudoSandboxStrict` (deny), both `NO` default. `dylib.x %ctor` after `shdw_own_ranges_refresh()`.

## 2. Phased build

* Phase 0 audit spike (landed): `PseudoSandboxPolicy.{h,m}` + `PathPolicy/sandbox.x` audit + `dylib.x` init.
* Phase 1 container fallback (landed): `Core.m`, `JBPath.{h,m}`, `RestrictionEngine`, `Shadow.tbd`.
* Phase 2 central enforce `OFF` (landed)
* Phase 3 harness/device (landed): MCM mock + group fixture, symlink-alias test, `hookprobe` divergence (krw VCHR probe fix).
* Phase 4 HIGH/MEDIUM (landed): shadowd version gate + krw offsets, JBPath runtime 1s TTL, 5000 cap removed, RulesetCompiler v3 ns + prune, Makefile/roothide/dyld polish.

## 3. Verification

`docker run shadow-harness sh build-linux.sh` → `tests/harness` — `rootless 129 passed, rooted 159 passed` with strict OFF.

## 4. What stays

Full-depth zones, `/var/tmp` key (if present), 47 shipped probes — pseudo additive, feature-flagged `OFF`.
