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
        SwizzlingDetector.isSwizzled()
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
        let result = EmulatorDetector.detectEmulator()
        return [
            "detected": result.isEmulator,
            "methods": result.detectionMethods,
            "confidence": result.confidence,
        ]
    }
}
