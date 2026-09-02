import Foundation

// ponytail: filtered replacement for the real SignatureUpdateManager, whose
// async update API + @unchecked Sendable cannot compile with the Swift 5.8
// theos toolchain. It only supplies remotely-updated signature lists; the
// on-device detectors fall back to the built-in obfuscated lists, so an empty
// stub keeps the real detectors' behavior intact.

public enum SignatureCategory: String, Codable, CaseIterable {
    case jailbreakPaths
    case jailbreakEnvVars
    case jailbreakURLSchemes
    case jailbreakTestPaths
    case jailbreakAntiDetectionMarkers
    case debuggerProcessNames
    case debuggerEnvVars
    case emulatorPaths
    case emulatorEnvVars
    case reverseEngineeringLibraries
    case reverseEngineeringEnvVars
}

public final class SignatureUpdateManager {
    public static let shared = SignatureUpdateManager()
    public func entries(for category: SignatureCategory) -> [String] { [] }
}