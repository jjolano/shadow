# Shadow — agent workflow (public repo)

## Build
- One lane at a time: `.github/scripts/build-deps.sh <lane>` then `./build.sh <lane>`.
- Lanes: `rootful-legacy|rootful-modern|rootless|roothide` (`rootful` = both rootful; `all` = everything — avoid).
- `./build.sh quick` = compile-only check (framework + dylibs, rootful-modern); no package, no compat checks.
- Requires `$THEOS`; HookKit preinstalled into `$THEOS/lib` (CI: `install-hookkit-theos.sh <lane>`).

## Test
- Public only: `make -C tests test` (pure-C checks + static contract scripts; see `tests/README.md`).
- `scripts/check-compat.sh` runs automatically per lane in `build.sh build_lane` (it invokes `check-binary-compat.sh`); rerun manually only to debug a packaged .deb.
- Full engine/detector/adversary/fuzz/device harness lives in the sibling private repo; run from its own checkout; never commit its path/URL here.

## Sources of truth
- Lane fields (ARCHS/TARGET/SCHEME/DEPLOY/FLOOR/CEILING/PACKAGE/PACKAGE_ARCH) ONLY from `build-support/lanes.sh` (`shadow_lane_field`); shared fields defer to `$THEOS/bin/lane.sh`. Never duplicate values into Makefiles/scripts.
- HookKit from `$THEOS/lib` per `build-support/hookkit.mk` (lane-mapped dir); never vendor. Pin is `HOOKKIT` env in `.github/workflows/build.yml`.
- Control files rendered by `scripts/gen-control.sh <lane>` from `packaging/controls/control.<lane>.in`; `build.sh` does this per lane.

## Boundaries (never do)
- Never commit: `private/`, `vendor/HookKit.framework/`, `.theos/`, `packages/`, `build/`, `artifacts/`, `.detector-deps/`, `*.deb`.
- Never add to source comments/docs: detector-bypass how-to, jbroot probe orders, hook-lane rationale, installer tables, NSLog oracles.
- Keep `-fvisibility=hidden` + `-Wl,-x` and `exported_symbols.txt` / `exported_symbols-roothide.txt` in sync.
- Preserve roothide `@loader_path/.jbroot` install-name (no fixed `/var/jb` links) and legacy no-`os_unfair_lock` (both enforced by `check-binary-compat.sh`).
- Lane matrix values (floors/arches/firmware) must not be duplicated into Makefiles/scripts.

## Fresh setup
- Clone public `shadow` + sibling private `shadow-private` side by side; private harness runs from its own checkout (mounts this repo, never the reverse).
