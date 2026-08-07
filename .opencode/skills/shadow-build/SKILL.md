---
name: shadow-build
description: Build and verify the Shadow tweak (theos, 3-flavor packaging). Use when compiling any subproject, iterating on hook/framework code, packaging rootless/rooted/legacy debs, or when a build fails with dep/link errors (missing architecture slices, vendor staging).
---

# Build & verify Shadow

## Layout

- Subprojects (root `Makefile` aggregate): `Shadow.framework`, `Shadow.dylib` (the tweak hooks), `ShadowSettings.bundle`, `shdw`, `shadowd` (arm64-only; excluded from the legacy armv7 pass)
- Dep flavors staged from `../prebuilt/{hookkit,altlist,sandy}/<flavor>/` into `vendor/` + `$THEOS/lib` — **shared, mutable, clobberable**
- Outputs: `build/*.deb` (3 flavors), `packages/`

## Commands

| Command | What it does |
|---|---|
| `./build.sh all` | full 3-pass: rootless + rooted + legacy debs |
| `./build.sh rootless\|rooted\|legacy` | single flavor (full package) |
| `./build.sh quick` | **agent iteration**: verify rooted deps, `make -C Shadow.framework` + `make -C Shadow.dylib`, no packaging |
| `./build.sh deps <flavor>` | stage + slice-validate deps only (rooted default) |
| `make` (repo root) | aggregate compile of all subprojects (no package) — the final gate |

## Verification rules

- Per-edit check: `./build.sh quick` (or per-subproject `make -C Shadow.dylib`).
- Final gate before packaging: `make` from the repo root — must exit 0 with **0 errors**.
- `ld: warning: ... built with an incompatible arm64e ABI compiler` = known toolchain noise (clang-13 lacks arm64e ABI support). Not a regression; present in untouched files too.
- Exit 2 at link with "missing required architecture"/undefined `ATL*`/`HKSubstitutor`/`libSandy` symbols = dep slices wrong → `./build.sh deps <flavor>` re-stages and validates.
- Never run `stage_deps`/`./build.sh` concurrently with another build or agent lane — staging overwrites shared deps (rootless/legacy flavors lack arm64 slices).

## Workflow

1. Before coding: `./build.sh deps` — confirm dep staging is sound.
2. After each logical change: `./build.sh quick`; fix errors before committing.
3. Before packaging/release: full `make` (exit 0, 0 errors), then `./build.sh <flavor>`.
4. Legacy pass mutates `control` (firmware >= 9.0) with a PID-unique backup + EXIT restore — never run two legacy builds in parallel.
5. Publish debs from `build/` via the `publish-shadow-repo` skill.
