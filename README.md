# Shadow

A modern jailbreak detection bypass with rootful support back to iOS 9 and fine-grained per-app control over bypass strength.

## Features and Components

The Shadow package (`me.jjolano.shadow`, version 4.0.0) ships the following components:

* **Shadow.framework** — the decision engine that determines which paths, URLs, schemes, bundle IDs, and addresses are hidden from detection.
* **Shadow.dylib** and **ShadowCore.dylib** — the injection entry point and the hook layer that intercepts detection APIs.
* **ShadowSettings.bundle** — preferences UI in the Settings app.
* **shdw** — a command-line tool installed to `/usr/local/bin`. Its `-d` watcher mode regenerates the installed-apps ruleset whenever apps are installed or uninstalled (debounced), and it is also used for ruleset maintenance.
* **shadowd** — an arm64 XPC daemon included in modern packages. Its vnode-hiding backend activates only on iOS 15.0–16.6.1 and fails closed elsewhere.

## Installation

Add the [Shadow repository](https://ios.jjolano.me) to your package manager and install the Shadow (`me.jjolano.shadow`) package. Alternatively, download the [latest release](https://github.com/jjolano/shadow/releases/latest) directly from GitHub and open the file with your package manager.

Dependencies are pulled in automatically. You may need additional repositories for the following:

* `AltList` from [opa334's repository](https://opa334.github.io) — application listing in preferences.
* `libSandy` from [opa334's repository](https://opa334.github.io) — sandboxed preference loading.
* `HookKit` (>= 2.4.0) from [jjolano's repository](https://ios.jjolano.me) — hooking, including the change-hooking-library feature.

`Injection Foundation` from [PoomSmart's repository](https://poomsmart.github.io/repo) is recommended but not required; it ensures Shadow is injected properly into certain apps.

## Usage

After installation, settings are available in the Settings app. You may configure global defaults or add an app-specific configuration. Shadow allows fine-grained control of its bypass strength, so there will be many options available to configure.

## Compatibility

| Lane | Package architecture | Supported system | Binary slices |
| --- | --- | --- | --- |
| Rootful legacy | `iphoneos-arm` | iOS 9–13 | armv7/armv7s/arm64 at iOS 9; old-ABI arm64e at iOS 12 |
| Rootful modern | `iphoneos-arm` | iOS 14+ | arm64 and new-ABI arm64e at iOS 14 |
| Rootless | `iphoneos-arm64` | iOS 15+ | arm64 and new-ABI arm64e at iOS 15 |
| RootHide | `iphoneos-arm64e` | iOS 15–17 | arm64 and new-ABI arm64e at iOS 15 |

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

The available lanes are `rootful-legacy`, `rootful-modern`, `rootless`, and `roothide`; `rootful` builds both rootful packages when both toolchains are available. Legacy Linux builds default to `$THEOS/toolchain/oldabi/linux/iphone` (Clang 11) and `$THEOS/sdks/iPhoneOS13.7.sdk`; `OLDABI_TOOLCHAIN` and `OLDABI_SDKS` can override those locations. The dependency build invokes HookKit's pinned legacy builder, with `HOOKKIT_LEGACY_DEB` available as a prebuilt override. Modern lanes require macOS/Xcode 12 or newer for the new arm64e ABI, and RootHide uses the [RootHide Theos fork](https://github.com/roothide/theos). Every package is rejected if its architecture set, deployment targets, ABI marker, metadata, loader paths, or required payload is wrong.

Continuous integration builds and verifies the legacy lane on Ubuntu and all three modern lanes on macOS (`.github/workflows/build.yml`).

A host-side test harness for the decision engine — no device, no Theos, no simulator — lives in `tests/`. Run `make -C tests test`; Linux supports the full Docker-backed suite and macOS a native subset. See `tests/README.md` for details. The harness runs on every push and pull request (`.github/workflows/tests.yml`). The `tools/` directory contains on-device probes (`dyldprobe`, `hookprobe`) used for QA.

## Legal

*Copyright Act*, RSC 1985, c C-42, s 41.12.
