TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
DEPS ?= ../../../.detector-deps
BRIDGES = bridges
STUBS = stubs

include $(THEOS)/makefiles/common.mk

IOS_SUITE_DIR = $(DEPS)/IOSSecuritySuite/IOSSecuritySuite
FRAMEWORK_NAME = IOSSecuritySuite
IOSSecuritySuite_FILES = $(wildcard $(IOS_SUITE_DIR)/*.swift) $(BRIDGES)/IOSSBridge.swift
IOSSecuritySuite_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-harness-fw-module-cache
IOSSecuritySuite_FRAMEWORKS = UIKit Foundation
IOSSecuritySuite_LDFLAGS = -lswiftFoundation
IOSSecuritySuite_INSTALL_PATH = /Library/Frameworks

JB_DETECTOR_DIR = $(DEPS)/JailbreakDetector.swift/Sources/JailbreakDetector
FRAMEWORK_NAME += JailbreakDetector
JailbreakDetector_FILES = $(wildcard $(JB_DETECTOR_DIR)/*.swift) $(BRIDGES)/JBDBridge.swift
JailbreakDetector_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-harness-fw-module-cache
JailbreakDetector_FRAMEWORKS = UIKit Foundation
JailbreakDetector_LDFLAGS = -lswiftFoundation
JailbreakDetector_INSTALL_PATH = /Library/Frameworks

SECURITY_TOOLKIT_DIR = $(DEPS)/iOS-Security-Toolkit/Sources
FRAMEWORK_NAME += SecurityToolkit
SecurityToolkit_FILES = $(SECURITY_TOOLKIT_DIR)/ThreatReport.swift \
    $(SECURITY_TOOLKIT_DIR)/internal/JailbreakDetector.swift \
    $(SECURITY_TOOLKIT_DIR)/internal/HooksDetector.swift \
    $(SECURITY_TOOLKIT_DIR)/internal/SimulatorDetector.swift \
    $(SECURITY_TOOLKIT_DIR)/internal/DebuggerDetector.swift \
    $(SECURITY_TOOLKIT_DIR)/internal/DevicePasscodeDetector.swift \
    $(SECURITY_TOOLKIT_DIR)/internal/HardwareSecurityDetector.swift \
    $(BRIDGES)/STKBridge.swift
SecurityToolkit_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-harness-fw-module-cache
SecurityToolkit_FRAMEWORKS = UIKit Foundation LocalAuthentication
SecurityToolkit_LDFLAGS = -lswiftFoundation
SecurityToolkit_INSTALL_PATH = /Library/Frameworks

BAT_DIR = $(DEPS)/BATJailbreakGuard/Sources/BATJailbreakGuard
BAT_FILES := $(shell find $(BAT_DIR) -name '*.swift' -o -name '*.swift' | sort)
FRAMEWORK_NAME += BATJailbreakGuard
BATJailbreakGuard_FILES = $(BAT_FILES) $(BRIDGES)/BATBridge.swift
BATJailbreakGuard_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-harness-fw-module-cache
BATJailbreakGuard_FRAMEWORKS = UIKit Foundation
BATJailbreakGuard_LDFLAGS = -lswiftFoundation
BATJailbreakGuard_INSTALL_PATH = /Library/Frameworks

DSK_DIR = $(DEPS)/DeviceSecurityKit/Sources/DeviceSecurityKit
FRAMEWORK_NAME += DeviceSecurityKit
# ponytail: DebuggerDetector excluded -- `import Darwin.C` resolves on
# Xcode 16.4's SDK but the runner image moved to a newer Xcode whose Swift
# frontend rejects it (same signal-4 family as the earlier _Concurrency /
# ObjectiveC exclusions). The runner keeps its debugger row via
# DSKStubs.debuggerInfo; native ptrace/sysctl coverage lives in the
# IOSSecuritySuite + JailMonkey runners.
DeviceSecurityKit_FILES = \
    $(DSK_DIR)/Detectors/JailbreakDetector.swift \
    $(DSK_DIR)/Detectors/HookDetector.swift \
    $(DSK_DIR)/Detectors/SwizzlingDetector.swift \
    $(DSK_DIR)/Detectors/DylibInjectionDetector.swift \
    $(DSK_DIR)/Detectors/FridaDetector.swift \
    $(DSK_DIR)/Detectors/ReverseEngineeringDetector.swift \
    $(DSK_DIR)/Lists/JailbreakListOptions.swift \
    $(DSK_DIR)/Lists/DebuggerDetectorList.swift \
    $(DSK_DIR)/Lists/ReverseEngineeringListsOptions.swift \
    $(DSK_DIR)/StringObfuscator/StringObfuscator.swift \
    $(DSK_DIR)/SecurityLogger/SecurityLoggerConfiguration.swift \
    $(DSK_DIR)/SecurityLogger/SecurityLoggerManager.swift \
    $(DSK_DIR)/SystemImageValidator.swift \
    $(DSK_DIR)/FunctionAddress.swift \
    $(STUBS)/SignatureUpdateManager.swift \
    $(STUBS)/DSKStubs.swift \
    $(BRIDGES)/DSKBridge.swift
DeviceSecurityKit_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-harness-fw-module-cache
DeviceSecurityKit_FRAMEWORKS = UIKit Foundation DeviceCheck
DeviceSecurityKit_LDFLAGS = -lswiftFoundation
DeviceSecurityKit_INSTALL_PATH = /Library/Frameworks

include $(THEOS_MAKE_PATH)/framework.mk
