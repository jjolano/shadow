import Foundation

// ponytail: ObjC-facing bridge over the DeviceSecurityKit stubs (see
// DSKStubs.swift + the Makefile note): the real detectors cannot compile
// under the theos Swift 5.8 frontend on the runner image's newer Xcode SDK,
// so every row reports unsupported-toolchain instead of a verdict. Native
// file/dyld/debugger coverage lives in the IOSSecuritySuite + JailMonkey +
// SafetyNet runners.

@objc(DSKBridge)
public final class DSKBridge: NSObject {
    @objc public static func prepareForHarness() {
        SecurityLoggerManager.shared.configure(.silent)
    }

    @objc public static func isJailbroken() -> Bool { false }
    @objc public static func jailbreakEvidence() -> [String] { DSKStubVerdict.methods }
    @objc public static func isFunctionHooked() -> Bool { false }
    @objc public static func functionHookEvidence() -> [String] { DSKStubVerdict.methods }
    @objc public static func isSwizzled() -> Bool { false }
    @objc public static func isFridaDetected() -> Bool { false }
    @objc public static func isDylibInjected() -> Bool { false }
    @objc public static func isReverseEngineered() -> Bool { false }
    @objc public static func isDebuggerAttached() -> Bool { false }
    @objc public static func debuggerEvidence() -> [String] { DSKStubVerdict.methods }
    @objc public static func emulatorInfo() -> [String: Any] { DSKStubVerdict.info() }
}
