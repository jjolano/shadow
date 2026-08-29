import Foundation

private final class SafetyNetResultBox: @unchecked Sendable {
    var event: ThreatEvent?
}

@objc(SafetyNetBridge)
public final class SafetyNetBridge: NSObject {
    @objc public static func runChecks() -> [String: Any] {
        let sem = DispatchSemaphore(value: 0)
        let result = SafetyNetResultBox()
        let task = Task.detached(priority: nil) {
            result.event = await SafetyNet.shared.check(checks: .all)
            sem.signal()
        }

        // This bridge is called from the detector worker, not the main thread;
        // SafetyNet may hop to MainActor for URL-scheme checks.
        sem.wait()
        _ = task

        guard let event = result.event else {
            return ["error": "SafetyNet returned no threat event"]
        }
        return [
            "level": event.level?.rawValue ?? -1,
            "reasons": event.reasons.map { $0.rawValue },
        ]
    }
}
