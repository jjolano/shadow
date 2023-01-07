# HookKit

An iOS tweak developer framework to unify code substitution APIs in runtime.

... I actually don't know how useful this is. (but it's quite fun to see it work)

This framework allows tweak developers to hook functions with a standard and consistent API. Standard hooking functions are accessed through the `HKSubstitutor` class, or using convenience macros.

## Installation

To use this framework:

* Run `install_to_theos.sh` to install HookKit to your Theos development environment.
* Add `HookKit` to `<project_name>_EXTRA_FRAMEWORKS`.
* Add `me.jjolano.fmwk.hookkit` to your package dependencies.
* Include the `HookKit.h` header file. Refer to `HookKit.h` for more information.

`HookKit Framework` is available on my repo (`https://ios.jjolano.me`).

## Advantages and Disadvantages

Advantages:

* Improved performance through use of batch hooking (if supported).
* Ability to switch hooking libraries from your tweak. [Shadow](https://github.com/jjolano/shadow) provides this functionality.

Disadvantages:

* Some library-specific functionality is not implemented (yet)
* Existing tweaks' will need to be rewritten or recompiled to use HookKit

## Library Support

So far, support has been (mostly) implemented for the following code substitution libraries:

* libhooker
* Substitute
* Cydia Substrate
* ElleKit
* Fishhook
* Dobby

## Examples

MobileSubstrate method:

```objc
MSHookFunction(func_1, replaced_func_1, (void **)&orig_func_1);
MSHookFunction(func_2, replaced_func_2, (void **)&orig_func_2);
MSHookFunction(func_3, replaced_func_3, (void **)&orig_func_3);
```

HookKit method (standard):

```objc
HKHookFunction(func_1, replaced_func_1, (void **)&orig_func_1);
HKHookFunction(func_2, replaced_func_2, (void **)&orig_func_2);
HKHookFunction(func_3, replaced_func_3, (void **)&orig_func_3);
```

HookKit method (batching):

```objc
HKEnableBatching();

HKHookFunction(func_1, replaced_func_1, (void **)&orig_func_1);
HKHookFunction(func_2, replaced_func_2, (void **)&orig_func_2);
HKHookFunction(func_3, replaced_func_3, (void **)&orig_func_3);

HKExecuteBatch();
```

## Credits

### fishhook

<https://github.com/facebook/fishhook>

### Dobby

<https://github.com/jmpews/Dobby>

### libhooker

<https://gist.github.com/coolstar/902bb1a4664f3d987ae954aaf39415f9>

### Substitute

<https://github.com/sbingner/substitute>

### ElleKit

<https://github.com/evelyneee/ellekit>
