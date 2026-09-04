import Darwin
import Foundation
import UIKit

@_silgen_name("shdwInstallHarnessSDKFallback")
private func shdwInstallHarnessSDKFallback() -> Bool

// A probe class that lives in the RUNNER'S MAIN BINARY. IOSSecuritySuite's
// amIRuntimeHooked inspects a method's IMP and passes only when it resides in
// the main executable or a system framework. A real app integration passes one
// of its own main-binary classes; the IOSSBridge lives in the dlopen'd
// IOSSecuritySuite.framework, so using it would make ISS flag its own framework
// as injected (a harness artifact). The bridge resolves this class by name
// (NSClassFromString("ShadowIOSSRuntimeProbe")) and inspects its runnerProbe,
// which correctly dladdr-resolves to this main executable.
@objc(ShadowIOSSRuntimeProbe)
final class ShadowIOSSRuntimeProbe: NSObject {
    @objc dynamic func runnerProbe() {}
}

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
    let framework = Bundle.main.bundlePath + "/Frameworks/IOSSecuritySuite.framework/IOSSecuritySuite"
    guard dlopen(framework, RTLD_NOW | RTLD_LOCAL) != nil else {
      let checks = [check("iossecuritysuite.late_load", "Late-loaded framework", false, "Could not load IOSSBridge framework")]
      _ = runnerFinish("iossecuritysuite", "IOSSecuritySuite", "2.3.0", "jailbroken",
        [["phase": "late-load", "clean": false, "checks": checks]], nil, callback)
      return
    }
    let fallbackInstalled = shdwInstallHarnessSDKFallback()
    let selector = NSSelectorFromString("runnerChecksWithBundleID:")
    let bridge = NSClassFromString("IOSSBridge") as? NSObject.Type
    let reported = bridge?.perform(selector, with: Bundle.main.bundleIdentifier ?? "me.jjolano.shadow.test.iossecuritysuite")?
      .takeUnretainedValue() as? [[String: Any]]
    let checks = [
      check("iossecuritysuite.late_load", "Late-loaded framework", fallbackInstalled,
        fallbackInstalled ? "SDK fallback installed after dlopen" : "SDK fallback was unavailable")
    ] + (reported ?? [check("iossecuritysuite.bridge", "IOSSBridge", false, "IOSSBridge did not return checks")])
    let clean = checks.allSatisfy {
      ($0["passed"] as? Bool) == true
    }
    _ = runnerFinish("iossecuritysuite", "IOSSecuritySuite", "2.3.0", clean ? "clean" : "jailbroken",
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
