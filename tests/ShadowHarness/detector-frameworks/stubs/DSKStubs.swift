import Foundation

// ponytail: DeviceSecurityKit ships stub-only in the harness (see the
// Makefile note): every real detector file crashes the theos Swift 5.8
// frontend on the runner image's newer Xcode SDK. Each row reports a static
// verdict the runner treats as a skip (unsupported-toolchain), so the DSK
// section stays present without pretending to check anything.

public final class SecurityLogger {
    public enum LogLevel: Int {
        case debug = 0, info = 1, warning = 2, error = 3
    }
    public init(subsystem: String, category: String) {}
    public func log(_ message: String, level: LogLevel = .info, file: String = #file, function: String = #function, line: Int = #line) {}
    public func debug(_ message: String, file: String = #file, function: String = #function, line: Int = #line) {}
    public func info(_ message: String, file: String = #file, function: String = #function, line: Int = #line) {}
    public func warning(_ message: String, file: String = #file, function: String = #function, line: Int = #line) {}
    public func error(_ message: String, file: String = #file, function: String = #function, line: Int = #line) {}
    public static func security(subsystem: String) -> SecurityLogger {
        SecurityLogger(subsystem: subsystem, category: "Security")
    }
    public static func detection(subsystem: String) -> SecurityLogger {
        SecurityLogger(subsystem: subsystem, category: "Detection")
    }
    public static func redact(_ value: String) -> String { value }
}

public final class SecurityLoggerManager {
    public static let shared = SecurityLoggerManager()
    public func configure(_ configuration: SecurityLoggerConfiguration) {}
    public func currentConfiguration() -> SecurityLoggerConfiguration { .default }
}

public struct SecurityLoggerConfiguration {
    public static let `default` = SecurityLoggerConfiguration()
    public static let silent = SecurityLoggerConfiguration()
}

public enum DSKStubVerdict {
    public static let methods = ["unsupported-toolchain"]
    public static func info() -> [String: Any] {
        ["detected": false, "methods": methods, "confidence": Float(0)]
    }
}
