# DetectorRunners — retired.

The isolated per-detector runner apps lived here (one app per SDK, driven
over URL schemes, reporting back over TCP). Run All now executes every
detector **embedded in ShadowHarness** with zero app flips:

- ObjC-source detectors: `tests/ShadowHarness/SHDWEmbedded.m`
- Swift-framework detectors: `tests/ShadowHarness/EmbeddedDrivers.swift`
- Engine: `tests/ShadowHarness/Detectors.m` (serial worker queue)

The only survivor is `FreeRASP/Probe.m`: the framework-independent generic
C probe (mach ports, fork dry-run, dyld svc scan, exception ports), compiled
into the harness. Everything else in this directory was deleted; the
per-detector Makefiles, AppDelegates, plists, entitlements, and the
RunnerSupport TCP transport are gone on purpose.
