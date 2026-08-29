import Foundation

// ponytail: ObjC-facing bridge over the real iOS Security Toolkit detectors
// (filtered subset: root-privilege + hook detectors only).

@objc(STKBridge)
public final class STKBridge: NSObject {
    @objc public static func rootPrivilegesThreat() -> Bool {
        JailbreakDetector.threatDetected() == .present
    }

    @objc public static func hooksThreat() -> Bool {
        HooksDetector.threatDetected() == .present
    }
}