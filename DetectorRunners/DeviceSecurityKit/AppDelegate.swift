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
    DSKBridge.prepareForHarness()
    let evidence = DSKBridge.jailbreakEvidence()
    let functionHookEvidence = DSKBridge.functionHookEvidence()
    let debuggerEvidence = DSKBridge.debuggerEvidence()
    let emulator = DSKBridge.emulatorInfo()
    let emulatorDetected = emulator["detected"] as? Bool ?? false
    let methods = emulator["methods"] as? [String] ?? []
    let values: [(String, String, Bool, String)] = [
      ("dsk.jailbreak", "Jailbreak", DSKBridge.isJailbroken(), evidence.joined(separator: "; ")),
      ("dsk.function_hook", "Function hook", DSKBridge.isFunctionHooked(), functionHookEvidence.joined(separator: "; ")),
      ("dsk.swizzling", "Method swizzling", DSKBridge.isSwizzled(), "Objective-C implementation probe"),
      ("dsk.frida", "Frida", DSKBridge.isFridaDetected(), "Frida probe"),
      ("dsk.dylib_injection", "Dylib injection", DSKBridge.isDylibInjected(), "Dyld image probe"),
      ("dsk.reverse_engineering", "Reverse engineering", DSKBridge.isReverseEngineered(), "Reverse engineering probe"),
      ("dsk.debugger", "Debugger", DSKBridge.isDebuggerAttached(), debuggerEvidence.joined(separator: "; ")),
      ("dsk.emulator", "Emulator", emulatorDetected, methods.joined(separator: "; "))
    ]
    let checks = values.map { id, name, detected, details in
      check(id, name, !detected, details.isEmpty ? (detected ? "Threat detected" : "No threat detected") : details)
    }
    let clean = checks.allSatisfy { ($0["passed"] as? Bool) == true }
    _ = runnerFinish("devicesecuritykit", "DeviceSecurityKit", "0.40.0-filtered", clean ? "clean" : "jailbroken",
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
