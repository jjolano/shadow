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

  private func evaluate() -> (jailbroken: Bool, checks: [[String: Any]]) {
    var configuration = JailbreakDetectorConfiguration.default
    configuration.haltAfterFailure = false

    switch JailbreakDetector(using: configuration).detectJailbreak() {
    case .pass:
      return (false, [check("jailbreakdetector.result", "Jailbreak detection", true, "All configured checks passed")])
    case .fail(let reasons):
      let checks = reasons.enumerated().map { index, reason in
        check("jailbreakdetector.failure.\(index)", "Jailbreak evidence", false, reason.description)
      }
      return (true, checks)
    case .simulator:
      return (false, [check("jailbreakdetector.environment", "Environment", true, "Simulator; jailbreak checks skipped")])
    case .macCatalyst:
      return (false, [check("jailbreakdetector.environment", "Environment", true, "Mac Catalyst; jailbreak checks skipped")])
    }
  }

  private func write(_ phase: String) {
    guard Date().timeIntervalSince(lastRun) > 2 else { return }
    lastRun = Date()
    let result = evaluate()
    let clean = !result.jailbroken
    let round: [String: Any] = ["phase": phase, "clean": clean, "checks": result.checks]
    let report: [String: Any] = [
      "schemaVersion": 1,
      "sdk": ["id": "jailbreakdetector", "name": "JailbreakDetector.swift", "version": "main@b6afe56"],
      "outcome": clean ? "clean" : "jailbroken",
      "generatedAt": ISO8601DateFormatter().string(from: lastRun),
      "rounds": [round]
    ]
    let directory = URL(fileURLWithPath: "/var/mobile/Documents/ShadowDetectorTests", isDirectory: true)
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    if let data = try? JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]) {
      try? data.write(to: directory.appendingPathComponent("jailbreakdetector.json"), options: .atomic)
    }
    label?.text = clean ? "JailbreakDetector clean" : "JailbreakDetector detected evidence"
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
    label.text = "Running JailbreakDetector.swift…"
    controller.view.addSubview(label)
    self.label = label
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.rootViewController = controller
    window.makeKeyAndVisible()
    self.window = window
    write("startup")
    return true
  }

  func applicationDidBecomeActive(_ application: UIApplication) {
    write("active")
  }

  func application(_ application: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    write("startup")
    return true
  }
}
