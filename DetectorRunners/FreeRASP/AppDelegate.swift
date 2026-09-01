import Darwin
import Foundation
import TalsecRuntime
import UIKit

private final class ThreatStore {
  static let shared = ThreatStore()
  private let lock = NSLock()
  private var detected = Set<SecurityThreat>()
  private var checksFinished = false

  func record(_ threat: SecurityThreat) {
    lock.lock()
    detected.insert(threat)
    lock.unlock()
  }

  func snapshot() -> (threats: Set<SecurityThreat>, finished: Bool) {
    lock.lock()
    defer { lock.unlock() }
    return (detected, checksFinished)
  }

  func markFinished() {
    lock.lock()
    checksFinished = true
    lock.unlock()
  }

}

extension SecurityThreatCenter: SecurityThreatHandler, RaspExecutionState {
  public func threatDetected(_ securityThreat: SecurityThreat) {
    ThreatStore.shared.record(securityThreat)
  }

  public func onAllChecksFinished() {
    ThreatStore.shared.markFinished()
  }
}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  private var callback: String?
  private var finished = false

  private func finish() {
    guard !finished, let callback, !callback.isEmpty else { return }
    finished = true
    let state = ThreatStore.shared.snapshot()
    let genericProbe = freeRASPGenericProbe()
    var checks = SecurityThreat.allCases.map { threat in
      let detected = state.threats.contains(threat)
      return [
        "id": "freerasp.\(threat.rawValue)",
        "name": threat.rawValue,
        "passed": !detected,
        "message": detected ? "Threat callback received" : "No threat callback"
      ] as [String: Any]
    }
    checks.append([
      "id": "freerasp.completion",
      "name": "All checks finished",
      "passed": state.finished,
      "message": state.finished ? "Completion callback received" : "Timed out before completion"
    ])
    let clean = checks.allSatisfy { ($0["passed"] as? Bool) == true }
    let outcome = state.finished ? (clean ? "clean" : "jailbroken") : "error"
    let sent = runnerFinish("freerasp", "freeRASP", "7.1.2", outcome,
      [["phase": "settled", "clean": clean, "checks": checks]],
      ["allChecksFinished": state.finished, "genericProbe": genericProbe], callback)
    if !sent { exit(1) }
  }

  private func freeRASPGenericProbe() -> [String: Any] {
    guard let raw = SHDWFreeRASPGenericProbeJSON(),
          let data = String(cString: raw).data(using: .utf8),
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      return ["error": "unavailable"]
    }
    return value
  }

  private func start(_ url: URL) {
    guard callback == nil, let value = runnerCallback(url) else { return }
    callback = value
    Talsec.start(config: TalsecConfig(
      appBundleIds: ["me.jjolano.shadow.test.freerasp"],
      appTeamId: "0000000000",
      watcherMailAddress: nil,
      isProd: true
    ))
    DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
      self?.finish()
    }
  }

  func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.rootViewController = UIViewController()
    window.makeKeyAndVisible()
    self.window = window
    if let url = options?[.url] as? URL { start(url) }
    return true
  }

  func application(_ application: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    start(url)
    return true
  }
}
