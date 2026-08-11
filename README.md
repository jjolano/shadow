# Shadow

A modern jailbreak detection bypass for iOS 12.0 and later, with fine-grained per-app control over bypass strength.

## Features and Components

The Shadow package (`me.jjolano.shadow`, version 4.0.0) ships the following components:

* **Shadow.framework** — the decision engine that determines which paths, URLs, schemes, bundle IDs, and addresses are hidden from detection.
* **Shadow.dylib** and **ShadowCore.dylib** — the injection entry point and the hook layer that intercepts detection APIs.
* **ShadowSettings.bundle** — preferences UI in the Settings app.
* **shdw** — a command-line tool installed to `/usr/local/bin`. Its `-d` watcher mode regenerates the installed-apps ruleset whenever apps are installed or uninstalled (debounced), and it is also used for ruleset maintenance.
* **shadowd** — an XPC daemon (arm64 only, iOS 15+) that maintains system rules; it is installed as a LaunchDaemon on supported devices.

## Installation

Add the [Shadow repository](https://ios.jjolano.me) to your package manager and install the Shadow (`me.jjolano.shadow`) package. Alternatively, download the [latest release](https://github.com/jjolano/shadow/releases/latest) directly from GitHub and open the file with your package manager.

Dependencies are pulled in automatically. You may need additional repositories for the following:

* `AltList` from [opa334's repository](https://opa334.github.io) — application listing in preferences.
* `libSandy` from [opa334's repository](https://opa334.github.io) — sandboxed preference loading.
* `HookKit` (>= 2.0.0) from [jjolano's repository](https://ios.jjolano.me) — hooking, including the change-hooking-library feature.

`Injection Foundation` from [PoomSmart's repository](https://poomsmart.github.io/repo) is recommended but not required; it ensures Shadow is injected properly into certain apps.

## Usage

After installation, settings are available in the Settings app. You may configure global defaults or add an app-specific configuration. Shadow allows fine-grained control of its bypass strength, so there will be many options available to configure.

## Compatibility

* iOS 12.0 or later (per package dependencies).
* Rootful, rootless, and roothide build flavors.
* The `shadowd` daemon is arm64-only and requires iOS 15+; on other devices it is not installed.
* Shadow is not guaranteed to work on all apps.

## Troubleshooting

If Shadow does not work with a particular app, here are some ideas to try:

* Use a different hooking library. `fishhook` is a safe option, but is somewhat limited in what it can hook.
* Disable all tweaks except Shadow. You can use Choicy or libhooker Configurator to do this per-app.
* Use vnodebypass, if supported on your system.
* If you are on a semi-(un)tethered or rootless jailbreak, reboot into normal jailed iOS and use the app.
* Use another bypass tweak, ideally an app-specific one. Be wary of enabling multiple bypass tweaks at once in case of conflicts.
* Downgrade the app. Sometimes, newer versions have updated detection methods.

## Building and Development

Building requires a [Theos](https://theos.dev) toolchain with the iOS SDKs. From the repository root:

* `./build.sh all` — builds the rootless, rootful, and roothide flavors into `build/`. Individual flavors: `./build.sh rootless`, `./build.sh rootful`, `./build.sh roothide`; `./build.sh quick` compiles the framework and dylibs without packaging for fast iteration.
* `make` — theos aggregate build with the default (rooted) flavor.
* The roothide flavor requires the roothide Theos fork and libroothide.

Continuous integration builds the rootless and rootful flavors on every push and pull request (`.github/workflows/build.yml`).

A host-side test harness for the decision engine — no device, no Theos, no simulator — lives in `tests/`. Run it with `make -C tests test|detect|adversary|detector|benign|coverage|fuzz|afuzz|fuzz-smoke`; it runs in Docker on Linux (see `tests/Dockerfile`) or natively on macOS. See `tests/README.md` for details. The harness runs on every push and pull request (`.github/workflows/tests.yml`). The `tools/` directory contains on-device probes (`dyldprobe`, `hookprobe`) used for QA.

## Legal

*Copyright Act*, RSC 1985, c C-42, s 41.12.
