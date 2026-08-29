import Foundation
import TalsecRuntime

private let talsecLock = NSLock()
private var talsecThreats = Set<SecurityThreat>()
private var talsecChecksFinished = false

extension SecurityThreatCenter: SecurityThreatHandler, RaspExecutionState {
    public func threatDetected(_ securityThreat: SecurityThreat) {
        talsecLock.lock()
        talsecThreats.insert(securityThreat)
        talsecLock.unlock()
    }

    public func onAllChecksFinished() {
        talsecLock.lock()
        talsecChecksFinished = true
        talsecLock.unlock()
    }
}

@objc(TalsecBridge)
public final class TalsecBridge: NSObject {
    @objc public static func start() {
        talsecLock.lock()
        talsecThreats.removeAll()
        talsecChecksFinished = false
        talsecLock.unlock()

        let config = TalsecConfig(
            appBundleIds: ["me.jjolano.shadow.harness"],
            appTeamId: "0000000000",
            watcherMailAddress: "test@example.com",
            isProd: true
        )
        Talsec.start(config: config)
    }

    @objc public static func threats() -> [String] {
        talsecLock.lock()
        defer { talsecLock.unlock() }
        return talsecThreats.map { $0.rawValue }
    }

    @objc public static func allChecksFinished() -> Bool {
        talsecLock.lock()
        defer { talsecLock.unlock() }
        return talsecChecksFinished
    }
}
