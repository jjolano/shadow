# Detector SDK Harness

The dashboard lists each real SDK runner as **Clean**, **Jailbroken**, or **Not run**. Tap a row to see every reported check and rerun that SDK in its isolated app process.

```sh
scripts/build-detector-harness.sh
```

This builds the dashboard plus IOSSecuritySuite 2.3.0, DTTJailbreakDetection `cedd424`, and freeRASP 6.4.0 runners. freeRASP 6.4.0 is pinned because it is the newest official release compatible with the repository's Swift 5.8/iOS 16.5 cross-toolchain; newer releases require a matching newer Darwin Swift SDK.

Runners write versioned JSON reports under `/var/mobile/Documents/ShadowDetectorTests`. The dashboard reads those files and shows each round and raw check message.
