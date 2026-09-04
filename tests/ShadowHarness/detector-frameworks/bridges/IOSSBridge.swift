import Darwin
import Foundation

@_cdecl("shdw_ioss_runner_probe")
public func shdw_ioss_runner_probe() {}

// ponytail: ObjC-facing bridge over the real IOSSecuritySuite 2.3.0 API so the
// harness can drive it via NSClassFromString after dlopen without importing Swift.

@objc(IOSSBridge)
public final class IOSSBridge: NSObject {
    @objc dynamic public func runnerProbe() {}

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

    @objc(runnerChecksWithBundleID:)
    public static func runnerChecks(bundleID: String) -> [[String: Any]] {
        func check(_ id: String, _ name: String, _ detected: Bool, _ message: String) -> [String: Any] {
            ["id": id, "name": name, "passed": !detected, "message": message]
        }

        let jailbreak = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
        let reverse = IOSSecuritySuite.amIReverseEngineeredWithFailedChecks()
        let jailbreakMessage = jailbreak.failedChecks.map { $0.failMessage }.joined(separator: "; ")
        let reverseMessage = reverse.failedChecks.map { $0.failMessage }.joined(separator: "; ")
        let tampered = IOSSecuritySuite.amITampered([.bundleID(bundleID)]).result
        // amIRuntimeHooked verifies a method's IMP lives in the main executable
        // or a system framework, flagging any other image as an injected hook.
        // A real integration passes one of the APP's OWN classes (compiled into
        // the main binary). Driving it with IOSSBridge — which is compiled into
        // the dlopen'd IOSSecuritySuite.framework — would make ISS flag its own
        // framework, a harness-embedding artifact unrelated to Shadow. Resolve
        // the runner's main-binary probe class (registered in its AppDelegate)
        // and inspect THAT, matching how an app would call this API. Fall back
        // to the bridge class only if the runner did not provide one.
        let detectionClass: AnyClass = NSClassFromString("ShadowIOSSRuntimeProbe") ?? IOSSBridge.self
        let detectionSelector: Selector = (detectionClass == IOSSBridge.self)
            ? #selector(IOSSBridge.runnerProbe)
            : NSSelectorFromString("runnerProbe")
        let runtimeHooked = IOSSecuritySuite.amIRuntimeHooked(
            dyldAllowList: [], detectionClass: detectionClass,
            selector: detectionSelector, isClassMethod: false)
        // The IOSSecuritySuite framework is dlopen'd RTLD_LOCAL by the runner,
        // so its @_cdecl probe symbol is not in the global namespace and
        // dlsym(RTLD_DEFAULT) returns nil (which forced MSHook/Breakpoint to a
        // false "jailbroken" via the ?? true fallback). RTLD_SELF (-3) searches
        // from this image onward and resolves the local symbol.
        let probeAddress = dlsym(UnsafeMutableRawPointer(bitPattern: -3), "shdw_ioss_runner_probe")
            ?? dlsym(UnsafeMutableRawPointer(bitPattern: -2), "shdw_ioss_runner_probe")
        let mshooked = probeAddress.map { IOSSecuritySuite.amIMSHooked($0) } ?? true
        let breakpoint = probeAddress.map {
            IOSSecuritySuite.hasBreakpointAt(UnsafeRawPointer($0), functionSize: 16)
        } ?? true
        let lockdown: Bool
        if #available(iOS 16, *) {
            lockdown = IOSSecuritySuite.amIInLockdownMode()
        } else {
            lockdown = false
        }
        let suspicious = suspiciousDylibs()

        return [
            check("iossecuritysuite.jailbreak", "Jailbreak", jailbreak.jailbroken,
                  jailbreakMessage.isEmpty ? "No failed jailbreak checks" : jailbreakMessage),
            check("iossecuritysuite.reverse", "Reverse engineering", reverse.reverseEngineered,
                  reverseMessage.isEmpty ? "No failed reverse-engineering checks" : reverseMessage),
            check("iossecuritysuite.integrity.bundle", "Bundle integrity", tampered,
                  tampered ? "Bundle identifier mismatch" : "Bundle identifier matches"),
            check("iossecuritysuite.debugger", "Debugger", IOSSecuritySuite.amIDebugged(), "Debugger probe"),
            check("iossecuritysuite.parent", "Unexpected parent", IOSSecuritySuite.isParentPidUnexpected(), "Parent probe"),
            check("iossecuritysuite.emulator", "Emulator", IOSSecuritySuite.amIRunInEmulator(), "Physical device probe"),
            check("iossecuritysuite.proxy", "Proxy or VPN", IOSSecuritySuite.amIProxied(considerVPNConnectionAsProxy: true), "Proxy probe"),
            check("iossecuritysuite.lockdown", "Lockdown mode", lockdown, "Lockdown mode probe"),
            check("iossecuritysuite.runtime_hook", "Runtime hook", runtimeHooked, "Objective-C implementation probe"),
            check("iossecuritysuite.mshook", "MSHook", mshooked,
                  probeAddress == nil ? "Runner probe unavailable" : "Function prologue probe"),
            check("iossecuritysuite.breakpoint", "Breakpoint", breakpoint,
                  probeAddress == nil ? "Runner probe unavailable" : "Breakpoint probe"),
            check("iossecuritysuite.watchpoint", "Watchpoint", IOSSecuritySuite.hasWatchpoint(), "Watchpoint probe"),
            check("iossecuritysuite.dylibs", "Suspicious dylibs", !suspicious.isEmpty,
                  suspicious.isEmpty ? "No suspicious dylibs" : suspicious.joined(separator: "; ")),
        ]
    }
}
