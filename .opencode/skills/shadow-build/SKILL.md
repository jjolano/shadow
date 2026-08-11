---
name: shadow-build
description: Build and verify the Shadow tweak (theos, 2-flavor packaging). Use when compiling any subproject, iterating on hook/framework code, packaging rootless/rootful debs, or when a build fails with dep/link errors (missing architecture slices, vendor staging).
---

# Build & verify Shadow

## Layout

- Subprojects (root `Makefile` aggregate): `Shadow.framework`, `Shadow.dylib` (the tweak hooks), `ShadowCore.dylib` (dlopen'd payload), `ShadowSettings.bundle`, `shdw`, `shadowd` (arm64/arm64e only — krw backends are 64-bit-kernel code; `override ARCHS` pins it even in the rootful pass)
- Dep flavors staged from `../prebuilt/{hookkit,altlist,sandy}/<flavor>/` into `vendor/` + `$THEOS/lib` — **shared, mutable, clobberable**. `rootful` = rooted + legacy slices lipo'd into one 4-arch set
- Outputs: `build/*.deb` (rootless + rootful), `packages/`

## Commands

| Command | What it does |
|---|---|
| `./build.sh all` | 3-pass: rootless + rootful + roothide debs |
| `./build.sh rootless\|rootful` | single flavor (full package) |
| `./build.sh quick` | **agent iteration**: verify rooted deps, `make -C Shadow.framework` + `make -C Shadow.dylib`, no packaging |
| `./build.sh deps <flavor>` | stage + slice-validate deps only (rooted default) |
| `make` (repo root) | aggregate compile of all subprojects (no package) — the final gate |
| `bash .github/scripts/build-deps.sh rootful` | rebuild 4-arch deps (needed before the first `build.sh rootful` on a fresh machine; `rootless`/`rooted`/`legacy` build single variants) |

## Verification rules

- Per-edit check: `./build.sh quick` (or per-subproject `make -C Shadow.dylib`).
- Final gate before packaging: `make` from the repo root — must exit 0 with **0 errors**.
- `ld: warning: ... built with an incompatible arm64e ABI compiler` = known toolchain noise (clang-13 lacks arm64e ABI support). Not a regression; present in untouched files too.
- Exit 2 at link with "missing required architecture"/undefined `ATL*`/`HKSubstitutor`/`libSandy` symbols = dep slices wrong → `./build.sh deps <flavor>` re-stages and validates.
- After `build-deps.sh rootful`, `$THEOS/lib` holds the last (legacy) variant's HookKit — `stage_deps rootful` re-installs the merged 4-slice framework there, so always re-stage before linking.
- Never run `stage_deps`/`./build.sh` concurrently with another build or agent lane — staging overwrites shared deps (rootless/legacy flavors lack arm64 slices).
- Rootful deb invariants (verify after build): every binary 4-slice except `usr/libexec/shadowd` (arm64/arm64e); arm64e slice minos 14.0 (so iOS 12/13 arm64e devices fall back to arm64); control `firmware (>= 9.0)`; postinst strips daemon on 32-bit and injection on 64-bit iOS < 12.

## Workflow

1. Before coding: `./build.sh deps` — confirm dep staging is sound.
2. After each logical change: `./build.sh quick`; fix errors before committing.
3. Before packaging/release: full `make` (exit 0, 0 errors), then `./build.sh <flavor>`.
4. The rootful pass mutates `control` (firmware >= 9.0) with a PID-unique backup + EXIT restore — never run two rootful builds in parallel.
5. Publish debs from `build/` via the `publish-shadow-repo` skill.
