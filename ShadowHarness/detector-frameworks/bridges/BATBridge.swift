import Foundation

// ponytail: ObjC-facing bridge over the real BATJailbreakGuard services (the
// 9 modular check services, each a self-contained Foundation-only class).

@objc(BATBridge)
public final class BATBridge: NSObject {
    @objc public static func filePath() -> Bool {
        JailbreakDetectionFilePathCheckService().isJailbreakDetected()
    }
    @objc public static func symbolicLinks() -> Bool {
        JailbreakDetectionSymbolicLinksCheckService().isJailbreakDetected()
    }
    @objc public static func environmentVariables() -> Bool {
        JailbreakDetectionEnvironmentVariableCheckService().isJailbreakDetected()
    }
    @objc public static func dynamicLib() -> Bool {
        JailbreakDetectionDynamicLibraryCheckService().isJailbreakDetected()
    }
    @objc public static func sandboxedEnvironment() -> Bool {
        JailbreakDetectionSandboxedEnvironmentViolationService().isJailbreakDetected()
    }
    @objc public static func rootUser() -> Bool {
        JailbreakDetectionRootUserCheckService().isJailbreakDetected()
    }
    @objc public static func openPorts() -> Bool {
        JailbreakDetectionSuspiciousPortsCheckService().isJailbreakDetected()
    }
    @objc public static func preventedAPIs() -> Bool {
        JailbreakDetectionPreventedAPICheckService().isJailbreakDetected()
    }
    @objc public static func checksum() -> Bool {
        JailbreakDetectionChecksumCheckService().isJailbreakDetected()
    }
}