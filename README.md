# Shadow

A jailbreak detection bypass for modern iOS jailbreaks.

## Frequently Asked Questions

> Can you add support/bypass for *app name*?

Due to the design philosophy of Shadow, no. To elaborate, Shadow focuses on hiding the jailbreak via detection methods, not reverse engineering the applications. **This is a very important distinction.**

It can be argued that discovering detection methods is a result of reverse engineering, but please understand this is a task that asks for an extremely high amount of time and effort in addition to the skillset required. This is a hobby project, not a full time job.

> *app name* keeps crashing with Shadow enabled.

This is due to either one of two things: jailbreak detection, or a hook from Shadow is causing the crash. If the latter (and the hook is not from Dangerous Hooks), please create a new GitHub Issue with the name of the app and the hook causing the crash. Also, please ensure the app itself actually does have jailbreak detection.

Support will be limited for unstable jailbreak bootstraps, as the issue may also originate from the jailbreak itself.

> *app name* runs slow with Shadow enabled.

This is expected behaviour, as extra processing is done on basically everything. This can be limited by reducing the hooks enabled. If it is extreme, please create a GitHub Issue. Another reason may be because of a tweak conflict. Try disabling all tweaks except Shadow and see if the problem persists.

## Troubleshooting

If your jailbreak is still getting detected, here are some things to try:

* Disable any compatibility settings.
* Try a different hooking library.
* Disable all tweaks except Shadow. You can use Choicy or libhooker Configurator to do this.
* Use vnodebypass.
* If semi-(un)tethered, reboot into normal jailed iOS and use the app. This is inconvenient but it can work.
* Use another bypass tweak, ideally an app-specific bypass tweak. Be wary of enabling multiple bypass tweaks in case of conflicts.
* Downgrade the app. Sometimes, newer versions have updated detection methods.

## Installation

Add my repo (`https://ios.jjolano.me`) to your package manager and install the Shadow (`me.jjolano.shadow`) package. Alternatively, download the [latest release](https://github.com/jjolano/shadow/releases) directly from GitHub and open the file with your package manager.

You may need additional repositories for dependencies - these are the current dependencies outside of having tweak injection:

* `libSandy` from opa334's Repo (`https://opa334.github.io`)
* `AltList` from opa334‘s Repo (`https://opa334.github.io`)
* `HookKit Framework` (same repo as Shadow)

A recommended (but not required) package is `Injection Foundation` from PoomSmart's Repo (`https://poomsmart.github.io/repo`). This package ensures that Shadow is injected properly into certain apps.

## Usage

After installation, settings are available in the Settings app. You may configure global defaults, or add an app-specific configuration. Shadow allows fine-grained control of its bypass strength, so there will be many options available to configure.

## Legal

*Copyright Act*, RSC 1985, c C-42, s 41.12.
