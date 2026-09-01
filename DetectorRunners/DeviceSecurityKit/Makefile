TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
DSK_DIR ?= ../../.detector-deps/DeviceSecurityKit/Sources/DeviceSecurityKit

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = DeviceSecurityKitRunner
DeviceSecurityKitRunner_FILES = AppDelegate.swift ../RunnerSupport.swift ../RunnerSupport.m \
	$(DSK_DIR)/Detectors/JailbreakDetector.swift \
	$(DSK_DIR)/Detectors/DebuggerDetector.swift \
	$(DSK_DIR)/Detectors/HookDetector.swift \
	$(DSK_DIR)/Detectors/SwizzlingDetector.swift \
	$(DSK_DIR)/Detectors/DylibInjectionDetector.swift \
	$(DSK_DIR)/Detectors/FridaDetector.swift \
	$(DSK_DIR)/Detectors/ReverseEngineeringDetector.swift \
	$(DSK_DIR)/Detectors/EmulatorDetector.swift \
	$(DSK_DIR)/Lists/JailbreakListOptions.swift \
	$(DSK_DIR)/Lists/DebuggerDetectorList.swift \
	$(DSK_DIR)/Lists/ReverseEngineeringListsOptions.swift \
	$(DSK_DIR)/Lists/EmulatorDetectorListOptions.swift \
	$(DSK_DIR)/StringObfuscator/StringObfuscator.swift \
	$(DSK_DIR)/SecurityLogger/SecurityLogger.swift \
	$(DSK_DIR)/SecurityLogger/SecurityLoggerConfiguration.swift \
	$(DSK_DIR)/SecurityLogger/SecurityLoggerManager.swift \
	$(DSK_DIR)/SystemImageValidator.swift \
	$(DSK_DIR)/FunctionAddress.swift \
	../../ShadowHarness/detector-frameworks/stubs/SignatureUpdateManager.swift \
	../../ShadowHarness/detector-frameworks/bridges/DSKBridge.swift
DeviceSecurityKitRunner_SWIFT_BRIDGING_HEADER = ../RunnerSupportC.h
DeviceSecurityKitRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-dsk-module-cache
DeviceSecurityKitRunner_FRAMEWORKS = UIKit Foundation Security DeviceCheck
DeviceSecurityKitRunner_LDFLAGS = -lswiftFoundation
DeviceSecurityKitRunner_INSTALL_PATH = /Applications
DeviceSecurityKitRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
