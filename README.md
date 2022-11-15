# Shadow
A jailbreak detection bypass for modern iOS jailbreaks.

## Note to Users: Bypass Requests
I understand that your app still doesn't work. However, I do not take any bypass or app requests. What I will take though, is if a tangible detection method is provided. Shadow is not designed to be app-specific. Please respect this.

## Supported Systems
Shadow is compiled for all devices on at least iOS 7. The best bypass performance is experienced on at least iOS 11, due to modern jailbreak design keeping the application sandbox intact. It is also iOS 15+ rootless-ready for Procursus-based bootstraps (untested).

## Installation
Add my repo (`https://ios.jjolano.me`) to your package manager and install the Shadow (`me.jjolano.shadow`) package. Alternatively, download the [latest release](https://github.com/jjolano/shadow/releases) directly from GitHub and open the file with your package manager.

## Usage
After installation, settings are available in the Settings app. You may configure global defaults, or add an app-specific configuration.

## Developers
Shadow exposes an API over `CPDistributedMessagingCenter`. This requires RocketBootstrap installed to bypass sandbox restrictions for this functionality.
* `ping`: Responds with `pong` and version numbers.
* `isPathRestricted`: Takes one parameter `path` that performs a lookup whether or not the path is related to jailbreak.
* `getURLSchemes`: Responds with an array of URL schemes related to jailbreak.
* `resolvePath`: Takes one parameter `path` that performs symlink resolving and returns the result.

If you are a jailbreak detection developer and I find you using this **private Apple API** in your production app, I will... hook this class.

## Contributing
Pull requests are welcome. Please describe any changes and improvements to the code, and any tweak behaviours that may be affected.

## Bypass not working?
Some apps may require app-specific bypasses. Please note that Shadow was never intended to tailor towards any specific app. In an ideal world, Shadow would bypass any and all detections that developers can hope to (legally) use. However, there are also limitations mainly from the code injection/substitution platform - these are likely to be difficult to bypass without using something app-specific to effectively skip the checks entirely rather than pass them.

It also seems that developers are using private APIs and somehow getting past App Store restrictions - so that's pretty fun. Shadow tries to handle those as well.

## License
Shadow is licensed under the BSD 3-clause license. Please ensure credit is given if Shadow's codebase has assisted your project.
