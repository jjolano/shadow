import Foundation

// ponytail: compile-shims for DeviceSecurityKit support files the theos
// Swift 5.8 frontend cannot compile (signal 4 on implicit
// _Concurrency/_StringProcessing imports, tripped by `canImport(os.log)`
// + lazy OSLog in SecurityLogger.swift):
//  - SecurityLogger: log-only; the bridge configures the manager .silent.
//    Plain methods (not @autoclosure) to match every real call site.
//  - DSKDebuggerStub: DebuggerDetector is excluded too (`import Darwin.C`
//    no longer resolves on the runner image's newer Xcode SDK). On-device
//    the harness is never ptraced, so not-attached is the correct verdict;
//    native debugger coverage lives in the IOSSecuritySuite + JailMonkey
//    runners.

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

public enum DSKDebuggerStub {
    public static func isAttached() -> Bool { false }
    public static func evidence() -> [String] { [] }
}
