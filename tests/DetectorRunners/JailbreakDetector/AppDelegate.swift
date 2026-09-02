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
    var configuration = JailbreakDetectorConfiguration.default
    configuration.haltAfterFailure = false
    let result = JailbreakDetector(using: configuration).detectJailbreak()
    let values: (Bool, [[String: Any]])
    switch result {
    case .pass:
      values = (false, [check("jailbreakdetector.result", "Jailbreak detection", true, "All configured checks passed")])
    case .fail(let reasons):
      values = (true, reasons.enumerated().map { index, reason in
        check("jailbreakdetector.failure.\(index)", "Jailbreak evidence", false, reason.description)
      })
    case .simulator:
      values = (false, [check("jailbreakdetector.environment", "Environment", true, "Simulator; checks skipped")])
    case .macCatalyst:
      values = (false, [check("jailbreakdetector.environment", "Environment", true, "Mac Catalyst; checks skipped")])
    }
    _ = runnerFinish("jailbreakdetector", "JailbreakDetector.swift", "main@b6afe56", values.0 ? "jailbroken" : "clean",
      [["phase": "startup", "clean": !values.0, "checks": values.1]], nil, callback)
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
