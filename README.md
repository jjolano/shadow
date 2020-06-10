# Shadow
A jailbreak detection bypass for modern iOS jailbreaks.

### `shadowd`?
With upcoming versions of Shadow, a system daemon will be installed and will be active when required by Shadow. The purpose of this daemon is to offload the main bulk of Shadow's codebase into a central location as well as increase the potential of what Shadow can bring in future releases.

## Development Status
The upcoming version of Shadow is currently in active development. Unless you are a developer, do not use the `master` branch. The old (working) codebase can be found in the `old` branch.

## Dependencies
* Code injection platform (Substrate, Substitute, libhooker)
* PreferenceLoader
* RocketBootstrap
* Cephei
* AppList
* iOS 11 or above

## Installation
Add [my repo](https://ios.jjolano.me) to your package manager and install the Shadow (`me.jjolano.shadow`) package. Alternatively, download the [latest release](https://github.com/jjolano/shadow/releases) directly from GitHub.

## Usage
Open the Settings app for Shadow settings. Shadow will need to be enabled on a per-app basis.

## Contributing
Pull requests are welcome. Please describe any changes and improvements to the code, and any tweak behaviours that may be affected.

## License
Shadow is licensed under the BSD 3-clause license.
