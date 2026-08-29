import Darwin
import Foundation

// ponytail: ObjC-facing bridge over the real IOSSecuritySuite 2.3.0 API so the
// harness can drive it via NSClassFromString after dlopen without importing Swift.

@objc(IOSSBridge)
public final class IOSSBridge: NSObject {
    @objc public static func amIJailbrokenWithFailedChecks() -> [String: String] {
        let result = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
        var failures: [String: String] = [:]
        for failed in result.failedChecks {
            failures[String(describing: failed.check)] = failed.failMessage
        }
        return failures
    }

    @objc public static func amIReverseEngineeredWithFailedChecks() -> [String: String] {
        let result = IOSSecuritySuite.amIReverseEngineeredWithFailedChecks()
        var failures: [String: String] = [:]
        for failed in result.failedChecks {
            failures[String(describing: failed.check)] = failed.failMessage
        }
        return failures
    }

    @objc public static func amITampered(bundleID: String) -> Bool {
        IOSSecuritySuite.amITampered([.bundleID(bundleID)]).result
    }

    @objc public static func amIDebugged() -> Bool { IOSSecuritySuite.amIDebugged() }
    @objc public static func isParentPidUnexpected() -> Bool { IOSSecuritySuite.isParentPidUnexpected() }
    @objc public static func amIRunInEmulator() -> Bool { IOSSecuritySuite.amIRunInEmulator() }
    @objc public static func amIProxied() -> Bool { IOSSecuritySuite.amIProxied(considerVPNConnectionAsProxy: true) }

    @objc public static func amIInLockdownMode() -> Bool {
        if #available(iOS 16, *) { return IOSSecuritySuite.amIInLockdownMode() }
        return false
    }

    @objc public static func amIRuntimeHooked(className: String, selectorName: String) -> Bool {
        guard let cls = NSClassFromString(className) else { return false }
        return IOSSecuritySuite.amIRuntimeHooked(
            dyldAllowList: [], detectionClass: cls, selector: NSSelectorFromString(selectorName), isClassMethod: false)
    }

    @objc public static func amIMSHooked(symbol: String) -> Bool {
        guard let address = dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbol) else { return false }
        return IOSSecuritySuite.amIMSHooked(address)
    }

    @objc public static func hasWatchpoint() -> Bool { IOSSecuritySuite.hasWatchpoint() }

    @objc public static func hasBreakpointAt(symbol: String) -> Bool {
        guard let address = dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbol) else { return false }
        return IOSSecuritySuite.hasBreakpointAt(UnsafeRawPointer(address), functionSize: 16)
    }

    @objc public static func suspiciousDylibs() -> [String] {
        let suspicious = ["shadow", "ellekit", "substrate", "substitute", "libhooker", "systemhook", "frida"]
        let loaded = IOSSecuritySuite.findLoadedDylibs() ?? []
        return loaded.filter { path in suspicious.contains { path.localizedCaseInsensitiveContains($0) } }
    }
}