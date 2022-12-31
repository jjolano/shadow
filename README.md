# Shadow
A jailbreak detection bypass for modern iOS jailbreaks.

## Troubleshooting Detection
If your jailbreak is still getting detected, here are some things to try:
* Use Choicy to disable all tweaks for the app except Shadow. If this works but you require tweaks, please enable tweaks one at a time until detection and create a new GitHub Issue with the name of the suspected conflicting tweak.
* Use vnodebypass.
* Reboot into unjailbroken state and try using the app. Yes, this can be inconvenient but it can work sometimes.
* Use another bypass tweak, whether general or app-specific. Be wary of enabling multiple bypass tweaks in case of conflicts.

## Frequently Asked Questions
> Can you add support for *app name*?

Due to the design philosophy of Shadow, no.

> *app name* keeps crashing with Shadow enabled.

This is due to either one of two things: jailbreak detection, or a hook from Shadow is causing the crash. If the latter (and the hook is not from Dangerous Hooks), please create a new GitHub Issue with the name of the app and the hook causing the crash. Also, please ensure the app itself actually does have jailbreak detection.

> My app runs slow!

This is expected behaviour, as extra processing is done on basically everything. This can be limited by reducing the hooks enabled. If it is extreme, please create a GitHub Issue. Another reason may be because of a tweak conflict. Try disabling all tweaks except Shadow and see if the problem persists.

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
