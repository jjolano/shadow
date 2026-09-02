import Foundation

// ponytail: ObjC-facing bridge over the real JailbreakDetector.swift API.
// Returns an NSDictionary: jailbroken (Bool) + either reasons ([String]) or detail.

@objc(JBDBridge)
public final class JBDBridge: NSObject {
    @objc public static func detectJailbreak() -> [String: Any] {
        var configuration = JailbreakDetectorConfiguration.default
        configuration.haltAfterFailure = false
        switch JailbreakDetector(using: configuration).detectJailbreak() {
        case .pass:
            return ["jailbroken": false, "detail": "All configured checks passed"]
        case .fail(let reasons):
            return ["jailbroken": true, "reasons": reasons.map { $0.description }]
        case .simulator:
            return ["jailbroken": false, "detail": "Simulator; jailbreak checks skipped"]
        case .macCatalyst:
            return ["jailbroken": false, "detail": "Mac Catalyst; jailbreak checks skipped"]
        }
    }
}