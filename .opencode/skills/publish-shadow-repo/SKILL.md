---
name: publish-shadow-repo
description: Publish Shadow's built debs to the jjolano apt repo (../ios-repo). Use when serving the debs from build/ into the apt repository, regenerating Packages/Release, or releasing a new Shadow version.
---

# Publish Shadow debs to the apt repo

## Layout

- Repo: `../ios-repo` (branch `release`), live at ios.jjolano.me
- `root/` → `iphoneos-arm` (rooted + legacy), `rootless/` → `iphoneos-arm64`, `roothide/` → `iphoneos-arm64e`
- `update.sh` regenerates `Packages` (+5 compressed variants) + `Release`, then `git add/commit/push`
- Release is unsigned (no Release.gpg/InRelease) — Sileo/Cydia accept it with a warning

## Flavor → destination

| deb | dest |
|---|---|
| `me.jjolano.shadow_<ver>_iphoneos-arm64.deb` | `rootless/` |
| `me.jjolano.shadow_<ver>_iphoneos-arm.deb` (fat: armv7/armv7s + arm64/arm64e) | `root/` |
| `me.jjolano.shadow_<ver>_iphoneos-arm64e.deb` (roothide, fat arm64+arm64e, `.jbroot` install_names) | `roothide/` |

## Gotchas

- **One deb per package+version+arch.** The flavors can't share one entry — apt keys on `name_version_arch`.
- **Roothide is `iphoneos-arm64e` by ecosystem convention** (roothide.github.io publishes everything as arm64e even though it supports A8–A11; the fat arm64+arm64e slices cover both). Requires the roothide theos fork's `THEOS_PACKAGE_SCHEME=roothide`. `./build.sh roothide` emits it; requires `../HookKit` built for roothide too (same scheme) so the `.jbroot` deps resolve.
- **The fat deb replaces both the old rooted and legacy packages.** `control` keeps `Conflicts: me.jjolano.shadow.legacy`, so installing it on a device with the old v2-era `me.jjolano.shadow.legacy` package auto-removes it (dpkg deinstalls conflicted packages). Never ship the old legacy id — the fat deb is the single `iphoneos-arm` entry.
- **`update.sh` pushes to the LIVE repo.** Confirm with the user before running.
- Multiversion: old versions stay in the index; the new version joins as an upgrade. `Architectures` in `update.sh` must list `iphoneos-arm64e` (already updated).

## Workflow

1. Build: `./build.sh all` → rootless + fat + roothide debs in `build/`
2. Verify each deb's control: `dpkg-deb -f build/<deb> Package Version Architecture`
3. Copy into `../ios-repo` per the table above
4. Run `../ios-repo/update.sh` (regenerates index + commits + pushes) — **only after explicit confirmation**
5. Verify: `Packages` contains the new entries, `Release` regenerated