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

    let checksum = JailbreakDetectionChecksumCheckService()
    if let path = Bundle.main.path(forResource: "checksum-canary", ofType: "txt") {
      checksum.setExpectedChecksums([path: "33980678f68fa6084cd257ecf8594c2e08d2e459259bb24d6a87d960e2b2b12d"])
    }
    let values: [(String, String, Bool)] = [
      ("bat.filepath", "FilePath", JailbreakDetectionFilePathCheckService().isJailbreakDetected()),
      ("bat.symboliclinks", "SymbolicLinks", JailbreakDetectionSymbolicLinksCheckService().isJailbreakDetected()),
      ("bat.environmentvariables", "EnvironmentVariables", JailbreakDetectionEnvironmentVariableCheckService().isJailbreakDetected()),
      ("bat.dynamiclib", "DynamicLib", JailbreakDetectionDynamicLibraryCheckService().isJailbreakDetected()),
      ("bat.sandboxed", "SandboxedEnvironment", JailbreakDetectionSandboxedEnvironmentViolationService().isJailbreakDetected()),
      ("bat.rootuser", "RootUser", JailbreakDetectionRootUserCheckService().isJailbreakDetected()),
      ("bat.openports", "OpenPorts", JailbreakDetectionSuspiciousPortsCheckService().isJailbreakDetected()),
      ("bat.preventedapis", "PreventedAPIs", JailbreakDetectionPreventedAPICheckService().isJailbreakDetected()),
      ("bat.checksum", "Checksum", checksum.isJailbreakDetected())
    ]
    let checks = values.map { id, name, detected in
      check(id, name, !detected, detected ? "Jailbreak detected" : "No jailbreak detected")
    }
    let clean = checks.allSatisfy { ($0["passed"] as? Bool) == true }
    _ = runnerFinish("batjailbreakguard", "BATJailbreakGuard", "main@spm", clean ? "clean" : "jailbroken",
      [["phase": "startup", "clean": clean, "checks": checks]], nil, callback)
  }

  func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
    let controller = UIViewController()
    controller.view.backgroundColor = .systemBackground
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.rootViewController = controller
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
