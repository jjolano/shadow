# Shadow Harness

The harness hosts Shadow's built-in diagnostics and lists each real SDK runner as **Clean**, **Jailbroken**, or **Not run**. Tap a row to see the full internal diagnostics or every SDK-reported check.

```sh
scripts/build-detector-harness.sh
```

This builds one Shadow Harness package containing the dashboard, twelve isolated
SDK runner applications, and an embedded dyld fidelity probe. The standalone
`dyldprobe.app` is also included for direct probe runs.

* Thirteen detectors, one runner each (versions pinned in `scripts/fetch-detector-sdks.sh`): IOSSecuritySuite, JailbreakDetector.swift, iOS Security Toolkit, DTTJailbreakDetection, freeRASP, Roothider JailbreakDetector, BATJailbreakGuard, SafetyNet, DeviceSecurityKit, JailMonkey, isJailbroken, SwiftyJBD JailBreak-Detection — plus the embedded dyldprobe
* **JailbreakDetector.swift** `b6afe56` — configurable file, sandbox-write, and URL-scheme checks — pure Swift, iOS 10+
* **iOS Security Toolkit** `2.0.0` — all six detector statuses: root privileges, hooks, simulator, debugger, device passcode, and hardware cryptography — Swift, iOS 13+
* **Roothider JailbreakDetector** `main@5b3d0be` — modern C (mach services, mount, proc, exception_port, dyld)
* **BATJailbreakGuard** `main@spm` — 9 modular checks (FilePath, SymbolicLinks, EnvVars, DynamicLib, Sandbox, RootUser, OpenPorts, PreventedAPIs(fork), Checksum) — Swift 5.5, iOS 13+
* **SafetyNet** `main@spm` — 90+ paths, injected dylib, Frida/SSH ports, sandbox write, URL schemes, Shadow strings — Swift 5.9, iOS 14+, zero deps
* **DeviceSecurityKit** `0.40.0` — source-filtered to one-shot jailbreak/hook prologue/IMP swizzling/dyld/Frida/emulator checks (skip configuration-dependent VPN, integrity, attestation, clipboard, and background monitors) — Swift 5.9, requires iOS 15+ at runtime, built at 14.0 `TARGET`
* **JailMonkey** `v2.8.5` — native parity (Cydia/Substrate/bash, FileManager, cydia:// + sileo://, /private write, dyld) — ObjC, iOS 11+
* **isJailbroken** `main@60a5f55` — GPL-3.0 (test-only use) — 44 suspicious paths, symlink lstat, fork(), sandbox write, obfuscated dyld image-name scan (frida/cycript/substrate/`0Shadow.dylib`), sysctl P_TRACED debugger, iOS-on-Mac — ObjC, compiled into its runner
* **SwiftyJBD JailBreak-Detection** `main@6f5f1d9` — unlicensed upstream (test-only use) — cydia:// URL, filesystem, fopen, /private write behind one `isJailbroken()` verdict; upstream ships a two-method fragment, wrapped into `struct SwiftyJBD` at build time — Swift, compiled into its runner

Runners write versioned JSON reports under `/var/mobile/Documents/ShadowDetectorTests` (`<id>.json` with `sdk`, `outcome`, `rounds[].checks[]`). The dashboard (`DetectorDashboard.m:38 SHDWSDKs()`) reads those files and shows each round and raw check message. The dyld row runs the embedded probe directly in the Harness process. A `clean` outcome requires completed checks; incomplete detector results are shown as `error`/`Inconclusive`. All runners target `iphone:clang:14.5:14.0 ARCHS arm64`, `LSMinimumSystemVersion 14.0`; DeviceSecurityKit gates at runtime via `@available(iOS 15,*)`.
