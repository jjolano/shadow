import Foundation

// ponytail: ObjC-facing bridge over the real DeviceSecurityKit detectors
// (jailbreak/hook/swizzling/dylib/frida/reverse-engineering/debugger subset).

@objc(DSKBridge)
public final class DSKBridge: NSObject {
    @objc public static func prepareForHarness() {
        // Harness records detector output itself; avoid DSK's asynchronous
        // developer logger touching source paths through Shadow's file hooks.
        SecurityLoggerManager.shared.configure(.silent)
    }

    @objc public static func isJailbroken() -> Bool {
        JailbreakDetector.isJailbroken()
    }
    @objc public static func jailbreakEvidence() -> [String] {
        JailbreakDetector.getDetectionDetails()
    }
    @objc public static func isFunctionHooked() -> Bool {
        HookDetector.isFunctionHooked()
    }
    @objc public static func functionHookEvidence() -> [String] {
        HookDetector.collectEvidence()
    }
    @objc public static func isSwizzled() -> Bool {
        // Real SwizzlingDetector excluded from the build (import ObjectiveC
        // crashes the old frontend); the adapter covers isSwizzled via
        // hk_swift_hook, so report unswizzled here like the device would.
        false
    }
    @objc public static func isFridaDetected() -> Bool {
        FridaDetector.isFridaDetected()
    }
    @objc public static func isDylibInjected() -> Bool {
        DylibInjectionDetector.isDylibInjected()
    }
    @objc public static func isReverseEngineered() -> Bool {
        ReverseEngineeringDetector.isReverseEngineered()
    }
    @objc public static func isDebuggerAttached() -> Bool {
        DebuggerDetector.isDebuggerAttached()
    }
    @objc public static func debuggerEvidence() -> [String] {
        DebuggerDetector.getDetectionResults()
            .filter { $0.value }
            .map(\.key)
            .sorted()
    }
    @objc public static func emulatorInfo() -> [String: Any] {
        // EmulatorDetector needs DeviceCheck + newer-Swift concurrency the
        // theos Swift 5.8 frontend cannot compile; the runner reports it as
        // unsupported rather than dropping the check row.
        return ["detected": false, "methods": ["unsupported-toolchain"], "confidence": Float(0)]
    }
}
