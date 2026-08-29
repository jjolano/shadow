import Darwin
import Foundation
import TalsecRuntime
import UIKit

private let resultChanged = Notification.Name("FreeRASPResultChanged")

@_silgen_name("_dyld_image_count")
private func dyldImageCount() -> UInt32
@_silgen_name("_dyld_get_image_name")
private func dyldImageName(_ index: UInt32) -> UnsafePointer<CChar>?
@_silgen_name("_dyld_get_image_header")
private func dyldImageHeader(_ index: UInt32) -> UnsafeRawPointer?

private func talsecImageBase() -> UnsafeRawPointer? {
  for index in 0..<dyldImageCount() {
    guard let name = dyldImageName(index),
          String(cString: name).contains("TalsecRuntime.framework/TalsecRuntime") else { continue }
    return dyldImageHeader(index)
  }
  return nil
}

private final class ThreatStore {
  static let shared = ThreatStore()
  private let lock = NSLock()
  private var detected = Set<SecurityThreat>()
  private var checksFinished = false

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

  func markFinished() {
    lock.lock()
    checksFinished = true
    lock.unlock()
    NotificationCenter.default.post(name: resultChanged, object: nil)
  }

  func finished() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return checksFinished
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
  private var label: UILabel?
  private var returned = false
  private var talsecStartReturned = false
  private var stockMarkerVisibleBeforeStart = true
  private var prebootOpenResult = Int32(-1)
  private var prebootOpenErrno = Int32(0)
  private var spawnPID = pid_t(-1)
  private var spawnResult = Int32(-1)

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
    let directory = URL(fileURLWithPath: "/var/mobile/Documents/ShadowDetectorTests", isDirectory: true)
    let report: [String: Any] = [
      "schemaVersion": 1,
      "sdk": ["id": "freerasp", "name": "freeRASP", "version": "7.1.2"],
      "outcome": outcome,
      "generatedAt": ISO8601DateFormatter().string(from: Date()),
      "harness": [
        "varJBVisible": access("/var/jb", F_OK) == 0,
        "shadowCoreVisible": access("/var/jb/usr/lib/ShadowCore.dylib", F_OK) == 0,
        "talsecStartReturned": talsecStartReturned,
        "talsecImageLoaded": talsecImageBase() != nil,
        "talsecAllChecksFinished": ThreatStore.shared.finished(),
        "stockMarkerVisibleBeforeStart": stockMarkerVisibleBeforeStart,
        "prebootOpenResult": prebootOpenResult,
        "prebootOpenErrno": prebootOpenErrno,
        "spawnPID": spawnPID,
        "spawnResult": spawnResult,
      ],
      "rounds": [round]
    ]
    var writeError: Error?
    do {
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
      let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
      try data.write(to: directory.appendingPathComponent("freerasp.json"), options: .atomic)
    } catch {
      writeError = error
    }
    let failure = writeError?.localizedDescription

    DispatchQueue.main.async { [weak self] in
      if let failure {
        self?.label?.text = "Report write failed\n\n\(failure)"
        return
      }
      self?.label?.text = final ? (jailbroken ? "freeRASP detected jailbreak evidence" : "freeRASP reported clean") : "Running freeRASP 7.1.2…"
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
    label.text = "Running freeRASP 7.1.2…"
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
    stockMarkerVisibleBeforeStart = FileManager.default.fileExists(atPath: "/.file")
    errno = 0
    prebootOpenResult = open("/private/preboot", 0x100)
    prebootOpenErrno = errno
    if prebootOpenResult >= 0 { close(prebootOpenResult) }
    spawnResult = posix_spawn(&spawnPID, "", nil, nil, nil, nil)
    Talsec.start(config: TalsecConfig(
      appBundleIds: ["me.jjolano.shadow.test.freerasp"],
      appTeamId: "0000000000",
      watcherMailAddress: nil,
      isProd: true
    ))
    talsecStartReturned = true
    DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
      self?.writeReport(final: true)
    }
    return true
  }
}
