import Foundation

// ponytail: minimal compile-shims for the DeviceSecurityKit subset the
// harness builds (same pattern as the SignatureUpdateManager stub). The
// real files these replace need newer-Swift features the theos Swift 5.8
// toolchain lacks (implicit _Concurrency/_StringProcessing imports crash
// its frontend), but none of their behavior feeds the runner verdicts:
//  - SecurityLogger: the bridge configures .silent; all detector call
//    sites are log-only.
//  - SystemImageValidator: dladdr-path prefix check against the three
//    prefixes decoded from the real obfuscator ('/usr/lib/',
//    '/System/Library/', '/Library/Apple/'); replicated verbatim minus
//    the obfuscator.
//  - FunctionAddress: bit-cast of a function value to its code address;
//    verbatim copy (no concurrency use).
// EmulatorDetector + its list options are excluded from the build (DeviceCheck
// + concurrency the old frontend cannot compile); the bridge reports that
// row as unsupported-toolchain.

public final class SecurityLogger {
    public enum LogLevel: Int {
        case debug = 0, info = 1, warning = 2, error = 3
    }
    public init(subsystem: String, category: String) {}
    public func debug(_ message: @autoclosure () -> String) {}
    public func info(_ message: @autoclosure () -> String) {}
    public func warning(_ message: @autoclosure () -> String) {}
    public func error(_ message: @autoclosure () -> String) {}
    public static func security(subsystem: String) -> SecurityLogger {
        SecurityLogger(subsystem: subsystem, category: "Security")
    }
    public static func detection(subsystem: String) -> SecurityLogger {
        SecurityLogger(subsystem: subsystem, category: "Detection")
    }
    public static func redact(_ value: String) -> String { value }
}

internal struct SystemImageValidator {
    internal static let shared = SystemImageValidator()
    private let systemPrefixes = [
        "/usr/lib/",
        "/System/Library/",
        "/Library/Apple/",
    ]
    internal func isSystemImage(_ path: String) -> Bool {
        systemPrefixes.contains { normalizedImagePath(path).hasPrefix($0) }
    }
    internal func normalizedImagePath(_ path: String) -> String { path }
}

internal enum FunctionAddress {
    internal static func of<T>(_ function: T) -> UnsafeRawPointer {
        withUnsafeBytes(of: function) { raw in
            raw.load(as: UnsafeRawPointer.self)
        }
    }
}
