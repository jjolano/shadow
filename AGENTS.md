# Shadow — agent workflow (public repo)

## Locate the work
- Inspect the worktree and relevant source before choosing an implementation. Preserve existing user changes.
- For harness work, inspect `private/` directly, resolve any symlinks, and check `git worktree list`. Ignore-aware searches omit local private material; use an explicit ignored-file-inclusive search of likely checkout directories before reporting missing source.
- The full harness is maintained separately. A local `private/` directory may contain only notes; its existence does not establish a harness checkout. Confirm the source and revision before editing; historical worktrees are evidence, not the current implementation.
- Read the located checkout's own agent instructions and run its harness from there. Keep private checkout paths, URLs, and implementation details out of tracked public files.
- If current source remains unavailable, report the locations checked and ask for the checkout location. Complete independently actionable public work meanwhile.

## Execution and completion
- Carry authorized work through implementation and relevant verification. Ask only when missing information changes the result or blocks the remaining work.
- Delegate independent discovery or review when useful; keep edits to shared files coordinated.
- Treat skills as task guidance within the governing instructions. If a skill blocks progress, identify the exact file and instruction, and distinguish that requirement from your interpretation.
- Separate observed behavior, source-based hypotheses, and device-verified results. Static checks or historical source inspection do not establish that a live UI bug is fixed.
- Run checks appropriate to the changed behavior. For documentation-only edits, verify commands and claims against their sources and check the diff; builds and new tests are unnecessary. Broaden verification only for failures or unresolved concerns.
- Finish with changed files, checks and results, and any concrete blocker. Keep routine updates brief.

## Build
- One lane at a time: `.github/scripts/build-deps.sh <lane>` then `./build.sh <lane>`.
- Dependency provisioning requires macOS/Xcode 12+ except for `rootful-legacy`. If matching dependencies already exist under `PREBUILT_ROOT` (default `../prebuilt`), use `build.sh` directly; check `stage_deps` there for required artifacts.
- Lanes: `rootful-legacy|rootful-modern|rootless|roothide` (`rootful` = both rootful; `all` = everything — avoid).
- `./build.sh quick` = compile-only check (framework + dylibs, rootful-modern); no package, no compat checks.
- Requires `$THEOS` and HookKit in the lane-resolved location defined by `build-support/hookkit.mk` (CI provisioning: `.github/scripts/install-hookkit-theos.sh <lane>`).

## Test
- Public host checks: `make -C tests test`; maintainer-script checks separately: `sh tests/MaintainerScriptTests.sh`. Prerequisites, individual checks, and CI coverage are in `tests/README.md`.
- `scripts/check-compat.sh` runs automatically per lane in `build.sh build_lane` (it invokes `check-binary-compat.sh`); rerun manually only to debug a packaged .deb.

## Sources of truth
- Lane fields (ARCHS/TARGET/SCHEME/DEPLOY/FLOOR/CEILING/PACKAGE/PACKAGE_ARCH) ONLY from `build-support/lanes.sh` (`shadow_lane_field`); shared fields defer to `$THEOS/bin/lane.sh`. Never duplicate values into Makefiles/scripts.
- HookKit location comes from `build-support/hookkit.mk`; never vendor. Pin is `HOOKKIT` env in `.github/workflows/build.yml`.
- Control files rendered by `scripts/gen-control.sh <lane>` from `packaging/controls/control.<lane>.in`; `build.sh` does this per lane.

## Boundaries (never do)
- Never commit: `private/`, `vendor/HookKit.framework/`, `.theos/`, `packages/`, `build/`, `artifacts/`, `.detector-deps/`, `*.deb`.
- Never add to source comments/docs: detector-bypass how-to, jbroot probe orders, hook-lane rationale, installer tables, NSLog oracles.
- Keep `-fvisibility=hidden` + `-Wl,-x` and `exported_symbols.txt` / `exported_symbols-roothide.txt` in sync.
- Preserve roothide `@loader_path/.jbroot` install-name (no fixed `/var/jb` links) and legacy no-`os_unfair_lock` (both enforced by `check-binary-compat.sh`).
