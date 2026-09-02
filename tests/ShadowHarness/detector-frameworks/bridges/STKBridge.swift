import Foundation

// ponytail: ObjC-facing bridge over all six iOS Security Toolkit detectors.

@objc(STKBridge)
public final class STKBridge: NSObject {
    private static func statusName(_ status: ThreatStatus) -> String {
        switch status {
        case .notChecked:
            return "notChecked"
        case .notPresent:
            return "notPresent"
        case .present:
            return "present"
        case .exception(let error):
            return "exception: \(error)"
        }
    }

    @objc public static func statuses() -> [String: String] {
        [
            "rootPrivileges": statusName(JailbreakDetector.threatDetected()),
            "hooks": statusName(HooksDetector.threatDetected()),
            "simulator": statusName(SimulatorDetector.threatDetected()),
            "debugger": statusName(DebuggerDetector.threatDetected()),
            "devicePasscode": statusName(DevicePasscodeDetector.threatDetected()),
            "hardwareCryptography": statusName(HardwareSecurityDetector.threatDetected()),
        ]
    }
}
