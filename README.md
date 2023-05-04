# Shadow

A jailbreak detection bypass for modern iOS jailbreaks.

## Known Issues

### XinaA15

* No support is given, but Shadow should still be functional.

### palera1n

* On iOS 16.2+, Substitute appears to have issues hooking C functions. In this case, please use the `fishhook` hooking library.
* On iOS 16.4+, `libSandy` is currently reported to not work. Shadow is unable to function due to not being able to load preferences.

## Troubleshooting

Shadow is not guaranteed to work on all apps, but here are some ideas to try:

* Use a different hooking library. `fishhook` is a safe option, but is somewhat limited in what it can hook.
* Disable all tweaks except Shadow. You can use Choicy or libhooker Configurator to do this per-app.
* Use vnodebypass, if supported on your system.
* If semi-(un)tethered or rootless, reboot into normal jailed iOS and use the app.
* Use another bypass tweak, ideally an app-specific bypass tweak. Be wary of enabling multiple bypass tweaks in case of conflicts.
* Downgrade the app. Sometimes, newer versions have updated detection methods.

## Installation

Add my [repo](https://ios.jjolano.me) to your package manager and install the Shadow (`me.jjolano.shadow`) package. Alternatively, download the [latest release](https://github.com/jjolano/shadow/releases/latest) directly from GitHub and open the file with your package manager.

You may need additional repositories for dependencies - these are the current dependencies:

* `libSandy` from [opa334's Repo](https://opa334.github.io) (preferences)
* `AltList` from [opa334‘s Repo](https://opa334.github.io) (preferences)
* `HookKit Framework` (hooking + hooking library feature)
* `RootBridge Framework` (rootless compatibility)

A recommended (but not required) package is `Injection Foundation` from PoomSmart's Repo (`https://poomsmart.github.io/repo`). This package ensures that Shadow is injected properly into certain apps.

## Usage

After installation, settings are available in the Settings app. You may configure global defaults, or add an app-specific configuration. Shadow allows fine-grained control of its bypass strength, so there will be many options available to configure.

## Legal

*Copyright Act*, RSC 1985, c C-42, s 41.12.
