# HookKit

An iOS tweak developer framework to unify code substitution APIs in runtime.

... I actually don't know how useful this is. (but it's quite fun to see it work)

This framework allows tweak developers to hook functions with a standard and consistent API. Standard hooking functions are accessed through the `HKSubstitutor` class, and batch hooking is accessed through the `HKBatchHook` class.

## Installation

To use this framework:

* Run `install_to_theos.sh` to install HookKit to your Theos development environment.
* Add `HookKit` to `<project_name>_EXTRA_FRAMEWORKS`.
* Add `me.jjolano.fmwk.hookkit` to your package dependencies.
* Include the `HookKit.h` header file. Refer to `HookKit.h` for more information.

`HookKit Framework` is available on my repo (`https://ios.jjolano.me`).

## Advantages and Disadvantages

Advantages:

* Potentially improved performance through use of batch hooking (if supported).
* Consistent API which handles the actual hooking behind the scenes

Disadvantages:

* Library-specific functionality will still require developers to use the specific library functions (WIP reimplementations)
* Existing tweaks' hooks will need to be rewritten to use HookKit (WIP hook overrider)

## Library Support

So far, support has been (mostly) implemented for the following code substitution libraries:

* libhooker
* Substitute
* Cydia Substrate
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
HKSubstitutor* substitutor = [HKSubstitutor defaultSubstitutor];

[substitutor hookFunction:func_1 withReplacement:replaced_func_1 outOldPtr:(void **)&orig_func_1];
[substitutor hookFunction:func_2 withReplacement:replaced_func_2 outOldPtr:(void **)&orig_func_2];
[substitutor hookFunction:func_3 withReplacement:replaced_func_3 outOldPtr:(void **)&orig_func_3];
```

HookKit method (batching):

```objc
HKSubstitutor* substitutor = [HKSubstitutor defaultSubstitutor];
HKBatchHook* batch = [HKBatchHook new];

[batch addFunctionHook:func_1 withReplacement:replaced_func_1 outOldPtr:(void **)&orig_func_1];
[batch addFunctionHook:func_2 withReplacement:replaced_func_2 outOldPtr:(void **)&orig_func_2];
[batch addFunctionHook:func_3 withReplacement:replaced_func_3 outOldPtr:(void **)&orig_func_3];

[batch performHooksWithSubstitutor:substitutor];
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
