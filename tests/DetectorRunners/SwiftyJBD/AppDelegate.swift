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

    // Upstream exposes a single isJailbroken() verdict (cydia URL, filesystem,
    // fopen, /private write). Report it as one check; the message names the
    // SDK so the dashboard row stays attributable.
    let jailbroken = SwiftyJBD.isJailbroken()
    let checks = [check("swiftyjbd.isJailbroken", "isJailbroken", !jailbroken,
      jailbroken ? "JailBreak-Detection returned true" : "JailBreak-Detection returned false")]
    let clean = !jailbroken
    _ = runnerFinish("swiftyjbd", "SwiftyJBD JailBreak-Detection", "main@6f5f1d9",
      clean ? "clean" : "jailbroken",
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
