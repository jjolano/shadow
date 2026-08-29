import Foundation
import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  private var label: UILabel?
  private var lastRun = Date.distantPast

  private func check(_ id: String, _ name: String, _ passed: Bool, _ message: String) -> [String: Any] {
    ["id": id, "name": name, "passed": passed, "message": message]
  }

  private func statusCheck(_ id: String, _ name: String, _ status: ThreatStatus) -> [String: Any] {
    switch status {
    case .notPresent:
      return check(id, name, true, "No threat detected")
    case .present:
      return check(id, name, false, "Threat detected")
    case .notChecked:
      return check(id, name, false, "Detector did not report a result")
    case .exception(let error):
      return check(id, name, false, "Detector error: \(String(describing: error))")
    }
  }

  private func run(_ phase: String) {
    guard Date().timeIntervalSince(lastRun) > 2 else { return }
    lastRun = Date()
    let checks = [
      statusCheck("securitytoolkit.root_privileges", "Root privileges", JailbreakDetector.threatDetected()),
      statusCheck("securitytoolkit.hooks", "Runtime hooks", HooksDetector.threatDetected())
    ]
    let clean = checks.allSatisfy { ($0["passed"] as? Bool) == true }
    let round: [String: Any] = ["phase": phase, "clean": clean, "checks": checks]
    let report: [String: Any] = [
      "schemaVersion": 1,
      "sdk": ["id": "securitytoolkit", "name": "iOS Security Toolkit", "version": "2.0.0-filtered"],
      "outcome": clean ? "clean" : "jailbroken",
      "generatedAt": ISO8601DateFormatter().string(from: lastRun),
      "rounds": [round]
    ]
    let directory = URL(fileURLWithPath: "/var/mobile/Documents/ShadowDetectorTests", isDirectory: true)
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    if let data = try? JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]) {
      try? data.write(to: directory.appendingPathComponent("securitytoolkit.json"), options: .atomic)
    }
    label?.text = clean ? "Security Toolkit clean" : "Security Toolkit detected evidence"
    DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
      UIApplication.shared.open(URL(string: "shadow-detectors://refresh")!, options: [:])
    }
  }

  func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
    let controller = UIViewController()
    controller.view.backgroundColor = .systemBackground
    let label = UILabel(frame: controller.view.bounds.insetBy(dx: 24, dy: 24))
    label.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    label.font = .preferredFont(forTextStyle: .title2)
    label.numberOfLines = 0
    label.textAlignment = .center
    label.text = "Running iOS Security Toolkit…"
    controller.view.addSubview(label)
    self.label = label
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.rootViewController = controller
    window.makeKeyAndVisible()
    self.window = window
    run("startup")
    return true
  }

  func applicationDidBecomeActive(_ application: UIApplication) {
    run("active")
  }

  func application(_ application: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    run("startup")
    return true
  }
}
