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

  private func check(_ id: String, _ name: String, _ passed: Bool, _ message: String) -> [String: Any] {
    ["id": id, "name": name, "passed": passed, "message": message]
  }

  private func mSHookCheck(_ symbol: String) -> [String: Any] {
    guard let address = dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbol) else {
      return check("iossecuritysuite.mshook.\(symbol)", "MSHook \(symbol)", false, "dlsym failed")
    }
    let hooked = IOSSecuritySuite.amIMSHooked(address)
    return check(
      "iossecuritysuite.mshook.\(symbol)", "MSHook \(symbol)", !hooked,
      hooked ? "Hook prologue detected" : "No hook prologue detected"
    )
  }

  private func runtimeHookCheck(_ id: String, _ name: String, _ detectionClass: AnyClass, _ selector: Selector) -> [String: Any] {
    let hooked = IOSSecuritySuite.amIRuntimeHooked(
      dyldAllowList: [], detectionClass: detectionClass, selector: selector, isClassMethod: false
    )
    guard hooked, let method = class_getInstanceMethod(detectionClass, selector) else {
      return check(id, name, !hooked, hooked ? "Method missing" : "No hook detected")
    }
    var info = Dl_info()
    let result = dladdr(UnsafeRawPointer(method_getImplementation(method)), &info)
    let image = result == 1 && info.dli_fname != nil ? String(cString: info.dli_fname) : "no image"
    return check(id, name, false, "Hook detected; dladdr=\(result) \(image)")
  }

  private func hardenedRuntimeHookCheck(_ id: String, _ name: String, _ detectionClass: AnyClass, _ selector: Selector) -> [String: Any] {
    guard let implementation = class_getMethodImplementation(detectionClass, selector) else {
      return check(id, name, false, "Method missing")
    }

    var info = Dl_info()
    guard dladdr(UnsafeRawPointer(implementation), &info) == 1, let imageName = info.dli_fname else {
      return check(id, name, false, "IMP attribution failed")
    }

    let image = String(cString: imageName)
    let lower = image.lowercased()
    let binary = String(cString: _dyld_get_image_name(0)).lowercased()
    let clean = lower.contains("/system/library/") || lower.contains(binary)
    return check(
      id, name, clean,
      clean ? "System or app implementation" : "Hook detected in \(image)"
    )
  }

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
    ["class_getMethodImplementation", "dladdr", "dlsym", "stat"]
      .forEach(FishHookChecker.denyFishHook)

    let jailbreak = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
    let jailbreakFailures = Dictionary(uniqueKeysWithValues: jailbreak.failedChecks.map {
      (String(describing: $0.check), $0.failMessage)
    })
    let jailbreakChecks: [FailedCheck] = [
      .urlSchemes, .existenceOfSuspiciousFiles, .suspiciousFilesCanBeOpened,
      .restrictedDirectoriesWriteable, .fork, .symbolicLinks, .dyld, .suspiciousObjCClasses
    ]
    let suiteChecks: [[String: Any]] = jailbreakChecks.map {
      let identifier = String(describing: $0)
      return check(
        "iossecuritysuite.jailbreak.\(identifier)", "Jailbreak: \(identifier)",
        jailbreakFailures[identifier] == nil, jailbreakFailures[identifier] ?? "Passed"
      )
    }

    let reverse = IOSSecuritySuite.amIReverseEngineeredWithFailedChecks()
    let reverseFailures = Dictionary(uniqueKeysWithValues: reverse.failedChecks.map {
      (String(describing: $0.check), $0.failMessage)
    })
    let reverseChecks: [[String: Any]] = [
      FailedCheck.existenceOfSuspiciousFiles, .dyld, .openedPorts, .pSelectFlag
    ].map {
      let identifier = String(describing: $0)
      return check(
        "iossecuritysuite.reverse.\(identifier)", "Reverse engineering: \(identifier)",
        reverseFailures[identifier] == nil, reverseFailures[identifier] ?? "Passed"
      )
    }

    let integrity = IOSSecuritySuite.amITampered([
      .bundleID(Bundle.main.bundleIdentifier ?? "me.jjolano.shadow.test.iossecuritysuite")
    ])
    let suspiciousNames = ["shadow", "ellekit", "substrate", "substitute", "libhooker", "systemhook", "frida"]
    let loadedDylibs = IOSSecuritySuite.findLoadedDylibs()
    let exposedDylibs = loadedDylibs?.filter { path in
      suspiciousNames.contains { path.localizedCaseInsensitiveContains($0) }
    } ?? []
    var lockdownMode = false
    if #available(iOS 16, *) { lockdownMode = IOSSecuritySuite.amIInLockdownMode() }

    var extendedChecks: [[String: Any]] = [
      check("iossecuritysuite.debugger", "Debugger", !IOSSecuritySuite.amIDebugged(), "Debugger not detected"),
      check("iossecuritysuite.parent", "Unexpected parent", !IOSSecuritySuite.isParentPidUnexpected(), "Parent is launchd"),
      check("iossecuritysuite.emulator", "Emulator", !IOSSecuritySuite.amIRunInEmulator(), "Physical device"),
      check("iossecuritysuite.proxy", "Proxy or VPN", !IOSSecuritySuite.amIProxied(considerVPNConnectionAsProxy: true), "No proxy or VPN detected"),
      check("iossecuritysuite.lockdown", "Lockdown mode", !lockdownMode, lockdownMode ? "Lockdown mode enabled" : "Lockdown mode disabled"),
      check("iossecuritysuite.integrity.bundle", "Bundle integrity", !integrity.result, integrity.result ? "Bundle identifier mismatch" : "Bundle identifier matches"),
      runtimeHookCheck("iossecuritysuite.runtime.filemanager", "Runtime hook: FileManager fileExists", FileManager.self, #selector(FileManager.fileExists(atPath:))),
      runtimeHookCheck("iossecuritysuite.runtime.uiapplication", "Runtime hook: UIApplication canOpenURL", UIApplication.self, #selector(UIApplication.canOpenURL(_:))),
      hardenedRuntimeHookCheck("iossecuritysuite.runtime.hardened.filemanager", "Runtime hook: hardened FileManager", FileManager.self, #selector(FileManager.fileExists(atPath:))),
      hardenedRuntimeHookCheck("iossecuritysuite.runtime.hardened.uiapplication", "Runtime hook: hardened UIApplication", UIApplication.self, #selector(UIApplication.canOpenURL(_:))),
      check("iossecuritysuite.watchpoint", "Watchpoint", !IOSSecuritySuite.hasWatchpoint(), "Watchpoint not detected"),
      check("iossecuritysuite.loadcommands", "Suspicious load commands", loadedDylibs != nil && exposedDylibs.isEmpty, exposedDylibs.isEmpty ? "No injected dylib exposed" : exposedDylibs.joined(separator: "\n")),
      mSHookCheck("stat"), mSHookCheck("access"), mSHookCheck("fork"), mSHookCheck("readlink")
    ]
    if let address = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "stat") {
      let breakpoint = IOSSecuritySuite.hasBreakpointAt(UnsafeRawPointer(address), functionSize: 16)
      extendedChecks.append(check("iossecuritysuite.breakpoint", "Breakpoint", !breakpoint, breakpoint ? "Breakpoint detected" : "Breakpoint not detected"))
    } else {
      extendedChecks.append(check("iossecuritysuite.breakpoint", "Breakpoint", false, "dlsym failed"))
    }

    let checks = suiteChecks + reverseChecks + extendedChecks + shadowProbeChecks()
    let clean = !jailbreak.jailbroken && !reverse.reverseEngineered && checks.allSatisfy {
      ($0["passed"] as? Bool) == true
    }
    rounds.append([
      "phase": phase,
      "clean": clean,
      "checks": checks
    ])
    let allClean = rounds.allSatisfy { ($0["clean"] as? Bool) == true }
    return writeReport(outcome: allClean ? "clean" : "jailbroken")
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
