import Darwin
import Foundation
import TalsecRuntime
import UIKit

private let resultChanged = Notification.Name("FreeRASPResultChanged")

private final class ThreatStore {
  static let shared = ThreatStore()
  private let lock = NSLock()
  private var detected = Set<SecurityThreat>()

  func record(_ threat: SecurityThreat) {
    lock.lock()
    detected.insert(threat)
    lock.unlock()
    NotificationCenter.default.post(name: resultChanged, object: nil)
  }

  func snapshot() -> Set<SecurityThreat> {
    lock.lock()
    defer { lock.unlock() }
    return detected
  }
}

extension SecurityThreatCenter: SecurityThreatHandler {
  public func threatDetected(_ securityThreat: SecurityThreat) {
    ThreatStore.shared.record(securityThreat)
  }
}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  private var label: UILabel?
  private var returned = false

  private func writeReport(final: Bool) {
    let threats = ThreatStore.shared.snapshot()
    let jailbreakThreats: Set<SecurityThreat> = [.jailbreak, .runtimeManipulation]
    let jailbroken = !threats.isDisjoint(with: jailbreakThreats)
    let checks: [[String: Any]] = SecurityThreat.allCases.map { threat in
      let detected = threats.contains(threat)
      return [
        "id": "freerasp.\(threat.rawValue)",
        "name": threat.rawValue,
        "passed": !detected,
        "message": detected ? "Threat callback received" : "No threat callback"
      ]
    }
    let outcome = jailbroken ? "jailbroken" : (final ? "clean" : "running")
    let round: [String: Any] = [
      "phase": final ? "settled" : "startup",
      "clean": final && !jailbroken,
      "checks": checks
    ]
    let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("ShadowDetectorTests", isDirectory: true)
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let report: [String: Any] = [
      "schemaVersion": 1,
      "sdk": ["id": "freerasp", "name": "freeRASP", "version": "6.4.0"],
      "outcome": outcome,
      "generatedAt": ISO8601DateFormatter().string(from: Date()),
      "harness": [
        "varJBVisible": access("/var/jb", F_OK) == 0,
        "shadowCoreVisible": access("/var/jb/usr/lib/ShadowCore.dylib", F_OK) == 0
      ],
      "rounds": [round]
    ]
    if let data = try? JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]) {
      try? data.write(to: directory.appendingPathComponent("freerasp.json"), options: .atomic)
    }

    DispatchQueue.main.async { [weak self] in
      self?.label?.text = final ? (jailbroken ? "freeRASP detected jailbreak evidence" : "freeRASP reported clean") : "Running freeRASP 6.4.0…"
      guard final, self?.returned == false else { return }
      self?.returned = true
      if let url = URL(string: "shadow-detectors://refresh") {
        UIApplication.shared.open(url, options: [:])
      }
      DispatchQueue.main.asyncAfter(deadline: .now() + 1) { exit(0) }
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
    label.text = "Running freeRASP 6.4.0…"
    controller.view.addSubview(label)
    self.label = label
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.rootViewController = controller
    window.makeKeyAndVisible()
    self.window = window

    NotificationCenter.default.addObserver(forName: resultChanged, object: nil, queue: .main) { [weak self] _ in
      self?.writeReport(final: false)
    }
    writeReport(final: false)
    Talsec.start(config: TalsecConfig(
      appBundleIds: ["me.jjolano.shadow.test.freerasp"],
      appTeamId: "0000000000",
      watcherMailAddress: nil,
      isProd: false
    ))
    DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [weak self] in
      self?.writeReport(final: true)
    }
    return true
  }
}
