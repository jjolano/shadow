import Foundation
import UIKit

private func safetyNetProbe() {}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  private var started = false

  private func check(_ id: String, _ name: String, _ passed: Bool, _ message: String) -> [String: Any] {
    ["id": id, "name": name, "passed": passed, "message": message]
  }

  @objc dynamic private func runtimeProbe() {}

  private func run(_ url: URL) {
    guard !started, let callback = runnerCallback(url) else { return }
    started = true

    DebuggerDetector.installAntiDebugAtLaunch()
    let jailbreak = JailbreakDetector.detect()
    let executable = Bundle.main.object(forInfoDictionaryKey: "CFBundleExecutable") as? String ?? "SafetyNetRunner"
    var values: [(String, String, Bool)] = [
      ("safetynet.jailbreak_filesystem", "Jailbreak filesystem", jailbreak.filesystem),
      ("safetynet.jailbreak_dylib", "Jailbreak dylib", jailbreak.dylib),
      ("safetynet.frida_port", "Frida port", jailbreak.fridaPort),
      ("safetynet.sandbox_breach", "Sandbox breach", jailbreak.sandboxBreach),
      ("safetynet.url_scheme", "URL scheme", jailbreak.urlScheme),
      ("safetynet.suspicious_process", "Suspicious process", jailbreak.suspiciousProcess),
      ("safetynet.shadow_tweak", "Shadow tweak", jailbreak.shadowTweak),
      ("safetynet.suspicious_symlinks", "Suspicious symlinks", jailbreak.suspiciousSymlinks),
      ("safetynet.suspicious_open_port", "Suspicious open port", jailbreak.suspiciousOpenPort),
      ("safetynet.debugger_attached", "Debugger attached", DebuggerDetector.isDebuggerAttached()),
      ("safetynet.process_traced", "Process traced", DebuggerDetector.isBeingTraced()),
      ("safetynet.watchpoint", "Watchpoint", DebuggerDetector.hasWatchpoint()),
      ("safetynet.p_select", "P_SELECT flag", DebuggerDetector.hasPSelectFlag()),
      ("safetynet.code_signature", "Code signature", !IntegrityValidator.validateCodeSignature()),
      ("safetynet.system_proxy", "System proxy", ProxyDetector.checkSystemProxy()),
      ("safetynet.vpn", "VPN as proxy", ProxyDetector.checkVPNAsProxy()),
      ("safetynet.memory_patch", "Memory patch", IntegrityValidator.detectMemoryPatch(executableName: executable))
    ]
    typealias Probe = @convention(thin) () -> Void
    let probe = unsafeBitCast(safetyNetProbe as Probe, to: UnsafeMutableRawPointer.self)
    values += [
      ("safetynet.breakpoint", "Breakpoint", DebuggerDetector.hasBreakpoint(at: probe, functionSize: nil)),
      ("safetynet.mshook", "MSHook", HookDetector.isMSHooked(at: probe)),
      ("safetynet.runtime_hook", "Runtime hook", HookDetector.isRuntimeHooked(
        dyldAllowList: [], detectionClass: AppDelegate.self,
        selector: #selector(runtimeProbe), isClassMethod: false)),
      ("safetynet.file_integrity", "File integrity", FileIntegrityChecker.checkFileIntegrity([
        .bundleID(Bundle.main.bundleIdentifier ?? "me.jjolano.shadow.test.safetynet")
      ]).result)
    ]
    let checks = values.map { id, name, detected in
      check(id, name, !detected, detected ? "Threat detected" : "No threat detected")
    }
    let clean = checks.allSatisfy { ($0["passed"] as? Bool) == true }
    _ = runnerFinish("safetynet", "SafetyNet", "main@spm", clean ? "clean" : "jailbroken",
      [["phase": "startup", "clean": clean, "checks": checks]],
      ["mode": "all synchronous one-shot detectors"], callback)
  }

  func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.rootViewController = UIViewController()
    window.makeKeyAndVisible()
    self.window = window
    if let url = options?[.url] as? URL { run(url) }
    return true
  }

  func application(_ application: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    run(url)
    return true
  }
}
