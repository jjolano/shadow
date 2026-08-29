# Shadow Harness

The harness hosts Shadow's built-in diagnostics and lists each real SDK runner as **Clean**, **Jailbroken**, or **Not run**. Tap a row to see the full internal diagnostics or every SDK-reported check.

```sh
scripts/build-detector-harness.sh
```

This builds one Shadow Harness package with bundled in-process detectors (no isolated runners):

* IOSSecuritySuite 2.3.0, JailbreakDetector.swift `b6afe56`, iOS Security Toolkit `2.0.0-filtered`, DTTJailbreakDetection `cedd424`, freeRASP 7.1.2, dyldprobe
* **JailbreakDetector.swift** `b6afe56` — configurable file, sandbox-write, and URL-scheme checks — pure Swift, iOS 10+
* **iOS Security Toolkit** `2.0.0-filtered` — root-privilege and hook reports, including dyld, Frida/Cycript/Cynject, and local-port checks — Swift, iOS 13+
* **Roothider JailbreakDetector** `main@5b3d0be` — modern C (mach services, mount, proc, exception_port, dyld)
* **BATJailbreakGuard** `main@spm` — 9 modular checks (FilePath, SymbolicLinks, EnvVars, DynamicLib, Sandbox, RootUser, OpenPorts, PreventedAPIs(fork), Checksum) — Swift 5.5, iOS 13+
* **SafetyNet** `main@spm` — 90+ paths, injected dylib, Frida/SSH ports, sandbox write, URL schemes, Shadow strings — Swift 5.9, iOS 14+, zero deps
* **DeviceSecurityKit** `0.40.0-filtered` — filtered to jailbreak/hook prologue/IMP swizzling/dyld/Frida only (skip VPN/clipboard/bg tasks) — Swift 5.9, requires iOS 15+ at runtime, built at 14.0 `TARGET`
* **JailMonkey** `v2.8.5` — native parity (Cydia/Substrate/bash, FileManager, cydia:// + sileo://, /private write, dyld) — ObjC, iOS 11+

Runners write versioned JSON reports under `/var/mobile/Documents/ShadowDetectorTests` (`<id>.json` with `sdk`, `outcome`, `rounds[].checks[]`). The dashboard (`DetectorDashboard.m:35 SHDWSDKs()`) reads those files and shows each round and raw check message. All runners target `iphone:clang:14.5:14.0 ARCHS arm64`, `LSMinimumSystemVersion 14.0`; DeviceSecurityKit gates at runtime via `@available(iOS 15,*)`.
