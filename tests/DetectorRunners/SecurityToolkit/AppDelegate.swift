import Foundation
import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  private var started = false

  private func check(_ id: String, _ name: String, _ passed: Bool, _ message: String) -> [String: Any] {
    ["id": id, "name": name, "passed": passed, "message": message]
  }

  private func run(_ url: URL) {
    guard !started, let callback = runnerCallback(url) else { return }
    started = true
    let values: [(String, String, ThreatStatus)] = [
      ("securitytoolkit.root_privileges", "Root privileges", JailbreakDetector.threatDetected()),
      ("securitytoolkit.hooks", "Runtime hooks", HooksDetector.threatDetected()),
      ("securitytoolkit.simulator", "Simulator", SimulatorDetector.threatDetected()),
      ("securitytoolkit.debugger", "Debugger", DebuggerDetector.threatDetected()),
      ("securitytoolkit.device_passcode", "Device passcode", DevicePasscodeDetector.threatDetected()),
      ("securitytoolkit.hardware_cryptography", "Hardware cryptography", HardwareSecurityDetector.threatDetected())
    ]
    let checks = values.map { id, name, status -> [String: Any] in
      switch status {
      case .notPresent: return check(id, name, true, "No threat detected")
      case .present: return check(id, name, false, "Threat detected")
      case .notChecked: return check(id, name, false, "Detector did not report a result")
      case .exception(let error): return check(id, name, false, "Detector error: \(String(describing: error))")
      }
    }
    let inconclusive = values.contains { _, _, status in
      if case .notChecked = status { return true }
      if case .exception = status { return true }
      return false
    }
    let clean = !inconclusive && checks.allSatisfy { ($0["passed"] as? Bool) == true }
    let outcome = inconclusive ? "error" : (clean ? "clean" : "jailbroken")
    _ = runnerFinish("securitytoolkit", "iOS Security Toolkit", "2.0.0-filtered", outcome,
      [["phase": "startup", "clean": clean, "checks": checks]], nil, callback)
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
