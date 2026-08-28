---
name: publish-shadow-repo
description: Publish Shadow's built debs to the jjolano apt repo (../ios-repo). Use when releasing a new Shadow version, regenerating Packages/Release, or wiring a new package into the repo index.
---

# Publish Shadow debs to the apt repo

## Layout

- Repo: `../ios-repo` (branch `release`), live at ios.jjolano.me
- **Debs are never copied into the repo.** `update.sh` pulls `.deb` assets from
  the GitHub releases of `SOURCE_REPOS` (`jjolano/HookKit jjolano/Shadow`),
  stages them under `.stage/<owner>/<repo>/<tag>/`, and rewrites each
  `Filename:` to `https://github.com/<owner>/<repo>/releases/download/<tag>/`.
  The index points at GitHub; the repo hosts only metadata.
- `root/`, `rootless/`, `roothide/` in `.gitignore` are dead weight from the old
  copy-in model. Nothing writes them.
- `update.sh` regenerates `Packages` (+5 compressed variants) + `Release`, then
  commits and **pushes** — but only if `Packages` or a depiction actually
  changed (`Release` always differs on Date/checksums alone).
- Release is unsigned (no Release.gpg/InRelease) — Sileo/Cydia accept it with a warning

## What each lane emits

`./build.sh all` leaves these in `build/`, plus the dependency debs it copies
from `../prebuilt/packages/<lane>/`:

| lane | deb | arch |
|---|---|---|
| `rootful-legacy` | `me.jjolano.shadow.legacy_<ver>_iphoneos-arm.deb` | armv7+armv7s+arm64+arm64e, iOS 9.0–14.0 |
| `rootful-modern` | `me.jjolano.shadow_<ver>_iphoneos-arm.deb` | arm64+arm64e, >= 14.0 |
| `rootless` | `me.jjolano.shadow_<ver>_iphoneos-arm64.deb` | >= 15.0 |
| `roothide` | `me.jjolano.shadow_<ver>_iphoneos-arm64e.deb` | 15.0–18.0, `.jbroot` install_names |
| harness | `me.jjolano.shadow.harness_<ver>_iphoneos-arm{,64}.deb` | rootful-modern + rootless only |

## Gotchas

- **Two `iphoneos-arm` packages ship, by design.** `me.jjolano.shadow.legacy`
  covers iOS 9.0–14.0 and `me.jjolano.shadow` covers >= 14.0; the controls
  Conflict with each other and the firmware ranges are disjoint, so apt offers
  each device exactly one. Dropping the legacy deb from a release silently ends
  iOS 9–13 support.
- **One deb per package+version+arch.** apt keys on `name_version_arch`; the
  dedupe in `update.sh` keeps the first stanza per triple, in `SOURCE_REPOS`
  order.
- **A release with no `.deb` assets is skipped**, so asset-only releases never
  reach the index. Every `.deb` in a release *is* indexed — no allowlist.
- **Guards abort the run, not just warn:** a partial asset download, or a source
  repo yielding zero debs, exits non-zero rather than publishing a thinned
  index. Retire a repo by removing it from `SOURCE_REPOS`, never by deleting its
  releases.
- **Depictions are per package id.** `depictions/ios/<id>.{json,html}` exist for
  `me.jjolano.shadow` and `me.jjolano.fmwk.hookkit` only — a new package id
  (including `me.jjolano.shadow.legacy`) indexes fine but shows no depiction
  until one is added.
- **Roothide is `iphoneos-arm64e` by ecosystem convention** (roothide.github.io publishes everything as arm64e even though it supports A8–A11; the fat arm64+arm64e slices cover both). Requires the roothide theos fork's `THEOS_PACKAGE_SCHEME=roothide`.
- **`update.sh` pushes to the LIVE repo.** Confirm with the user before running.
- Multiversion: old versions stay in the index (`dpkg-scanpackages --multiversion`); the new version joins as an upgrade.

## Workflow

1. Build: `./build.sh all` → the debs above in `build/`
2. Verify each deb's control: `dpkg-deb -f build/<deb> Package Version Architecture`
3. Upload them as assets to a GitHub release on `jjolano/Shadow` — that release,
   not the filesystem, is what the index reads
4. Run `../ios-repo/update.sh` (pulls releases, regenerates index, commits, pushes)
   — **only after explicit confirmation**
5. Verify: `Packages` contains the new entries with `Filename:` pointing at the
   release, and `Release` regenerated
