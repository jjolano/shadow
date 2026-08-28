---
name: shadow-build
description: Build and verify the Shadow tweak (theos, 4-lane packaging). Use when compiling any subproject, iterating on hook/framework code, packaging rootless/rootful debs, or when a build fails with dep/link errors (missing architecture slices, vendor staging).
---

# Build & verify Shadow

## Layout

- Subprojects (root `Makefile` aggregate): `Shadow.framework`, `Shadow.dylib` (the tweak hooks), `ShadowCore.dylib` (dlopen'd payload), `ShadowSettings.bundle`, `shdw`, `shadowd` (arm64/arm64e only — krw backends are 64-bit-kernel code; `override ARCHS` pins it even in the rootful pass)
- Lanes (`lanes.sh` is the single source of truth for ARCHS/TARGET/FLOOR/PACKAGE): `rootful-legacy` (armv7+armv7s+arm64+arm64e, iOS 9.0–14.0, ships `me.jjolano.shadow.legacy`), `rootful-modern` (arm64+arm64e, >= 14.0), `rootless` (>= 15.0), `roothide` (15.0–18.0). The last three all ship `me.jjolano.shadow`.
- Deps staged per lane from `../prebuilt/{hookkit,altlist,sandy}/<lane>/` into `vendor/` + `$THEOS/lib` — **shared, mutable, clobberable**. Each lane builds its own set; nothing is lipo'd across lanes.
- Each lane packages from its own `control.<lane>`, passed as `_THEOS_DEB_PACKAGE_CONTROL_PATH` — the root `control` is never mutated.
- HookKit is pinned by `HOOKKIT=<sha>` in `.github/scripts/build-deps.sh` — the **only** HookKit reference. `vendor/HookKit.framework` is a build output (theos links `-framework HookKit` out of it via ShadowCore's `_THEOS_INTERNAL_SEARCHPATHS`), gitignored, never a submodule or a pin.
- Outputs: `build/*.deb` (one per lane), `packages/`

## Commands

| Command | What it does |
|---|---|
| `./build.sh all` | every lane: rootless, rootful-legacy, rootful-modern, roothide + the rootless/rootful-modern harnesses |
| `./build.sh <lane>` | single lane (full package). `rootful` is an alias for both rootful lanes + harness |
| `./build.sh quick` | **agent iteration**: stage `rootful-modern` deps, `make -C` Shadow.framework + Shadow.dylib + ShadowCore.dylib, no packaging |
| `./build.sh deps [lane]` | stage + slice-validate deps only (`rootful-modern` default) |
| `make` (repo root) | aggregate compile of all subprojects (no package) — the final gate |
| `bash .github/scripts/build-deps.sh <lane>` | rebuild that lane's deps (needed before its first `build.sh` on a fresh machine). Takes a full lane name only — bare `rootful` exits 2 with `unknown lane 'rootful'` |

## Verification rules

- Per-edit check: `./build.sh quick` (or per-subproject `make -C Shadow.dylib`).
- Final gate before packaging: `make` from the repo root — must exit 0 with **0 errors**.
- `ld: warning: ... built with an incompatible arm64e ABI compiler` = known toolchain noise (clang-13 lacks arm64e ABI support). Not a regression; present in untouched files too.
- Exit 2 at link with "missing required architecture"/undefined `ATL*`/`HKSubstitutor`/`libSandy` symbols = dep slices wrong → `./build.sh deps <lane>` re-stages and validates.
- `$THEOS/lib` holds whichever lane's HookKit was staged last — `stage_deps <lane>` re-installs that lane's framework, so always re-stage before linking a different lane.
- Bumping `HOOKKIT=` is never a drop-in: read the commit range first (`git log <old>..<new>`) and validate on device. HookKit fetches its own Frida Gum devkit (`before-HKGum-all::` -> `scripts/fetch-gum.sh`, pinned in `vendor/gum/gum.lock`), so `build_hookkit` needs no archive staging — do not add one back.
- Never run `stage_deps`/`./build.sh` concurrently with another build or agent lane — staging overwrites shared deps (the rootless and legacy lanes lack each other's slices).
- `rootful-legacy` deb invariants (verify after build): every binary 4-slice except `usr/libexec/shadowd` (arm64/arm64e); arm64e slice minos 12.0; `control.rootful-legacy` pins `firmware (>= 9.0), firmware (<< 14.0)`; postinst strips daemon on 32-bit and injection on 64-bit iOS < 12.

## Workflow

1. Before coding: `./build.sh deps` — confirm dep staging is sound (defaults to `rootful-modern`).
2. After each logical change: `./build.sh quick`; fix errors before committing.
3. Before packaging/release: full `make` (exit 0, 0 errors), then `./build.sh <lane>`.
4. Publish debs from `build/` via the `publish-shadow-repo` skill.
