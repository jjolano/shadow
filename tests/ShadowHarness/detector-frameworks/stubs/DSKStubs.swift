import Foundation

// ponytail: DebuggerDetector excluded from the framework build (`import
// Darwin.C` no longer resolves on the runner image's newer Xcode SDK; the
// old Swift frontend dies with signal 4). The runner's debugger row keeps
// working through this stub: on a real device the harness process is never
// ptraced, so "not attached / no evidence" is the correct verdict, and
// native debugger coverage (ptrace, sysctl P_TRACED) lives in the
// IOSSecuritySuite + JailMonkey runners.

public enum DSKDebuggerStub {
    public static func isAttached() -> Bool { false }
    public static func evidence() -> [String] { [] }
}
