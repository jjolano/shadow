# Shadow

A modern jailbreak detection bypass with rootful support back to iOS 9 and fine-grained per-app control over bypass strength.

## Features and Components

The Shadow package (`me.jjolano.shadow`, version 4.0.0) ships the following components:

* **Shadow.framework** — the decision engine that determines which paths, URLs, schemes, bundle IDs, and addresses are hidden from detection.
* **Shadow.dylib** and **ShadowCore.dylib** — the injection entry point and the hook layer that intercepts detection APIs.
* **ShadowSettings.bundle** — preferences UI in the Settings app.
* **shdw** — a command-line tool installed to `/usr/local/bin`. Its `-d` watcher mode regenerates the installed-apps ruleset whenever apps are installed or uninstalled (debounced), and it is also used for ruleset maintenance.

## Installation

Add the [Shadow repository](https://ios.jjolano.me) to your package manager and install the Shadow (`me.jjolano.shadow`) package. Alternatively, download the [latest release](https://github.com/jjolano/shadow/releases/latest) directly from GitHub and open the file with your package manager.

Dependencies are pulled in automatically. You may need additional repositories for the following:

* `AltList` from [opa334's repository](https://opa334.github.io) — application listing in preferences.
* `libSandy` from [opa334's repository](https://opa334.github.io) — sandboxed preference loading.
* `HookKit` (>= 3.0.0) from [jjolano's repository](https://ios.jjolano.me) — the canonical HK3 runtime behind Shadow's compatibility source surface.

`Injection Foundation` from [PoomSmart's repository](https://poomsmart.github.io/repo) is recommended but not required; it ensures Shadow is injected properly into certain apps.

## Usage

After installation, settings are available in the Settings app. You may configure global defaults or add an app-specific configuration. Shadow allows fine-grained control of its bypass strength, so there will be many options available to configure.

## Compatibility

| Lane | Build SDK | Package architecture | Supported system | Binary slices |
| --- | --- | --- | --- | --- |
| Rootful legacy | iPhoneOS 13.7 | `iphoneos-arm` | iOS 9–13 | armv7/armv7s/arm64 at iOS 9; old-ABI arm64e at iOS 12 |
| Rootful modern | iPhoneOS 16.5 | `iphoneos-arm` | iOS 14+ | arm64 and new-ABI arm64e at iOS 14 |
| Rootless | iPhoneOS 16.5 | `iphoneos-arm64` | iOS 15+ | arm64 and new-ABI arm64e at iOS 15 |
| RootHide | iPhoneOS 16.5 | `iphoneos-arm64e` | iOS 15–17 | arm64 and new-ABI arm64e at iOS 15 |

`lanes.sh` is the source of truth for the build SDK, deployment floor, package architecture, and firmware ceiling; CI checks it against every control file. A package being eligible for an iOS version is not a guarantee that every app or detection SDK will work there.

The legacy Shadow package and its HookKit, AltList, and libSandy dependencies use separate `.legacy` package IDs so old- and new-ABI arm64e binaries can never be mixed. Modern rootful, rootless, and RootHide packages keep the normal IDs and are selected by package architecture. Shadow is not guaranteed to work on every app.

## Troubleshooting

If Shadow does not work with a particular app, here are some ideas to try:

* Use a different hooking library. `fishhook` is a safe option, but is somewhat limited in what it can hook.
* Disable all tweaks except Shadow. You can use Choicy or libhooker Configurator to do this per-app.
* Use vnodebypass, if supported on your system.
* If you are on a semi-(un)tethered or rootless jailbreak, reboot into normal jailed iOS and use the app.
* Use another bypass tweak, ideally an app-specific one. Be wary of enabling multiple bypass tweaks at once in case of conflicts.
* Downgrade the app. Sometimes, newer versions have updated detection methods.

## Building and Development

Building requires [Theos](https://theos.dev). Build pinned dependencies first, then the matching package lane:

```sh
.github/scripts/build-deps.sh rootful-modern
./build.sh rootful-modern
```

The available lanes are `rootful-legacy`, `rootful-modern`, `rootless`, and `roothide`; `rootful` builds both rootful packages when both toolchains are available. Legacy Linux builds default to `$THEOS/toolchain/oldabi/linux/iphone` (Clang 11) and `$THEOS/sdks/iPhoneOS13.7.sdk`; `OLDABI_TOOLCHAIN` and `OLDABI_SDKS` can override those locations. Modern dependency builds use HookKit's canonical 3.0 facade; set `HOOKKIT_CANONICAL_DEB` to use a locally built package. The legacy lane remains on the old-ABI HookKit package and accepts `HOOKKIT_LEGACY_DEB`. Modern lanes require macOS/Xcode 12 or newer for the new arm64e ABI, and RootHide uses the [RootHide Theos fork](https://github.com/roothide/theos). Every package is rejected if its architecture set, deployment targets, ABI marker, metadata, loader paths, or required payload is wrong.

Do not run more than one lane build at a time. `stage_deps` installs each lane's AltList/libSandy/HookKit into shared, mutable locations (`vendor/` and `$THEOS/lib`), so concurrent lane builds clobber each other's dependency slices.

Continuous integration builds and verifies the legacy lane on Ubuntu and all three modern lanes on macOS (`.github/workflows/build.yml`).

A host-side test harness for the decision engine — no device, no Theos, no simulator — lives in `tests/`. Run `make -C tests test`; Linux supports the full Docker-backed suite and macOS a native subset. See `tests/README.md` for details. The harness runs on every push and pull request (`.github/workflows/tests.yml`). `tests/tools/` contains on-device probes (`dyldprobe`, `hookprobe`) used for QA.

## Repository Layout

| Path | Contents |
| --- | --- |
| `src/` | Shipping components: `Shadow.framework`, `Shadow.dylib`, `ShadowCore.dylib`, `ShadowSettings.bundle`, `shdw`, and shared `common.h`. |
| `build-support/` | Build glue read by the root and subproject Makefiles: `lanes.sh` (the lane matrix), `build-lanes.mk`, `hookkit.mk`. |
| `packaging/` | Debian control templates (`controls/control.<lane>`) and the staged `layout/` (maintainer scripts, launch daemons, default `DEBIAN/control`). |
| `tests/` | Host decision-engine harness plus device tooling: `ShadowHarness`, `DetectorRunners`, and `tools/` probes. |
| `docs/` | SDK audit and compatibility research notes. |
| `scripts/`, `.github/` | Build/release scripts and CI. |

## Legal

*Copyright Act*, RSC 1985, c C-42, s 41.12.
