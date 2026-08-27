import Darwin
import Foundation
import MachO
import ObjectiveC
import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  private var rounds: [[String: Any]] = []
  private var label: UILabel?
  private var lastRunStarted = Date.distantPast

  private func shadowProbeChecks() -> [[String: Any]] {
    let shadowClass = objc_getClass("ShadowRuleset") as? NSObject.Type
    let shadowSelector = Selector(("internalDictionary"))
    var shadowImages: [String] = []
    for index in 0..<_dyld_image_count() {
      guard let pointer = _dyld_get_image_name(index) else { continue }
      let name = String(cString: pointer)
      if name.localizedCaseInsensitiveContains("shadow") { shadowImages.append(name) }
    }

    let probes: [(String, String, Bool, String)] = [
      ("shadow.path.bundle", "Shadow preference bundle hidden",
       !FileManager.default.fileExists(atPath: "/Library/PreferenceBundles/ShadowPreferences.bundle"),
       "/Library/PreferenceBundles/ShadowPreferences.bundle"),
      ("shadow.path.preferences", "Shadow preferences hidden",
       !FileManager.default.fileExists(atPath: "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"),
       "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"),
      ("shadow.dyld", "Shadow images hidden", shadowImages.isEmpty,
       shadowImages.isEmpty ? "No Shadow image exposed" : shadowImages.joined(separator: "\n")),
      ("shadow.objc.class", "ShadowRuleset hidden", shadowClass == nil,
       shadowClass == nil ? "objc_getClass returned nil" : "ShadowRuleset is visible"),
      ("shadow.objc.method", "internalDictionary hidden",
       shadowClass.map { class_getInstanceMethod($0, shadowSelector) == nil } ?? true,
       shadowClass == nil ? "Class hidden" : "Method lookup completed")
    ]
    return probes.map { ["id": $0.0, "name": $0.1, "passed": $0.2, "message": $0.3] }
  }

  private func run(_ phase: String) -> Bool {
    let status = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
    let failures = Dictionary(uniqueKeysWithValues: status.failedChecks.map {
      (String(describing: $0.check), $0.failMessage)
    })
    let suiteChecks: [[String: Any]] = FailedCheck.allCases.map {
      let identifier = String(describing: $0)
      return [
        "id": "iossecuritysuite.\(identifier)",
        "name": identifier,
        "passed": failures[identifier] == nil,
        "message": failures[identifier] ?? "Passed"
      ]
    }
    rounds.append([
      "phase": phase,
      "clean": !status.jailbroken,
      "checks": suiteChecks + shadowProbeChecks()
    ])
    return writeReport(outcome: status.jailbroken ? "jailbroken" : "clean")
  }

  private func writeReport(outcome: String) -> Bool {
    let directory = URL(fileURLWithPath: "/var/mobile/Documents/ShadowDetectorTests", isDirectory: true)
    let report: [String: Any] = [
      "schemaVersion": 1,
      "sdk": ["id": "iossecuritysuite", "name": "IOSSecuritySuite", "version": "2.3.0"],
      "outcome": outcome,
      "generatedAt": ISO8601DateFormatter().string(from: Date()),
      "rounds": rounds
    ]
    do {
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
      let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
      try data.write(to: directory.appendingPathComponent("iossecuritysuite.json"), options: .atomic)
      return true
    } catch {
      label?.text = "Report write failed\n\n\(error.localizedDescription)"
      return false
    }
  }

  private func startRun(_ application: UIApplication) {
    guard Date().timeIntervalSince(lastRunStarted) > 9 else { return }
    lastRunStarted = Date()
    rounds.removeAll()
    label?.text = "Running IOSSecuritySuite 2.3.0…"
    _ = run("early")
    DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self] in
      guard self?.run("settled") == true else { return }
      self?.label?.text = "Complete\n\nReturning to Detector SDKs"
      if let url = URL(string: "shadow-detectors://refresh") {
        application.open(url, options: [:])
      }
    }
  }

  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    let controller = UIViewController()
    controller.view.backgroundColor = .systemBackground
    let label = UILabel(frame: controller.view.bounds.insetBy(dx: 24, dy: 24))
    label.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    label.adjustsFontForContentSizeCategory = true
    label.font = .preferredFont(forTextStyle: .title2)
    label.numberOfLines = 0
    label.textAlignment = .center
    label.text = "Running IOSSecuritySuite 2.3.0…"
    controller.view.addSubview(label)
    self.label = label
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.rootViewController = controller
    window.makeKeyAndVisible()
    self.window = window

    startRun(application)
    return true
  }

  func applicationDidBecomeActive(_ application: UIApplication) {
    startRun(application)
  }

  func application(
    _ application: UIApplication,
    open url: URL,
    options: [UIApplication.OpenURLOptionsKey: Any] = [:]
  ) -> Bool {
    startRun(application)
    return true
  }
}
