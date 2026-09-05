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
        // Real DebuggerDetector excluded from the build (import Darwin.C
        // broke on the runner image's newer Xcode); see DSKStubs.
        DSKDebuggerStub.isAttached()
    }
    @objc public static func debuggerEvidence() -> [String] {
        DSKDebuggerStub.evidence()
    }
    @objc public static func emulatorInfo() -> [String: Any] {
        // EmulatorDetector excluded from the build (String(format:) trips
        // the old frontend's signal 4); the runner reports unsupported.
        ["detected": false, "methods": ["unsupported-toolchain"], "confidence": Float(0)]
    }
}
