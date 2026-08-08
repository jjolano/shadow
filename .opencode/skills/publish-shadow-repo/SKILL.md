---
name: publish-shadow-repo
description: Publish Shadow's built debs to the jjolano apt repo (../ios-repo). Use when serving the debs from build/ into the apt repository, regenerating Packages/Release, or releasing a new Shadow version.
---

# Publish Shadow debs to the apt repo

## Layout

- Repo: `../ios-repo` (branch `release`), live at ios.jjolano.me
- `root/` → `iphoneos-arm` (rooted + legacy), `rootless/` → `iphoneos-arm64`
- `update.sh` regenerates `Packages` (+5 compressed variants) + `Release`, then `git add/commit/push`
- Release is unsigned (no Release.gpg/InRelease) — Sileo/Cydia accept it with a warning

## Flavor → destination

| deb | dest |
|---|---|
| `me.jjolano.shadow_<ver>_iphoneos-arm64.deb` | `rootless/` |
| `me.jjolano.shadow_<ver>_iphoneos-arm.deb` (fat: armv7/armv7s + arm64/arm64e) | `root/` |

## Gotchas

- **One deb per package+version+arch.** The two flavors can't share one entry — apt keys on `name_version_arch`.
- **The fat deb replaces both the old rooted and legacy packages.** `control` keeps `Conflicts: me.jjolano.shadow.legacy`, so installing it on a device with the old v2-era `me.jjolano.shadow.legacy` package auto-removes it (dpkg deinstalls conflicted packages). Never ship the old legacy id — the fat deb is the single `iphoneos-arm` entry.
- **`update.sh` pushes to the LIVE repo.** Confirm with the user before running.
- Multiversion: old versions stay in the index; the new version joins as an upgrade.

## Workflow

1. Build: `./build.sh` → 2 debs in `build/`
2. Verify each deb's control: `dpkg-deb -f build/<deb> Package Version Architecture`
3. Copy into `../ios-repo` per the table above
4. Run `../ios-repo/update.sh` (regenerates index + commits + pushes) — **only after explicit confirmation**
5. Verify: `Packages` contains the new entries, `Release` regenerated