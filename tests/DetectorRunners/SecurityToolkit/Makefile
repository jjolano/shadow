TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
SECURITY_TOOLKIT_DIR ?= ../../../.detector-deps/iOS-Security-Toolkit/Sources

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = SecurityToolkitRunner
SecurityToolkitRunner_FILES = AppDelegate.swift ../RunnerSupport.swift ../RunnerSupport.m \
	$(SECURITY_TOOLKIT_DIR)/ThreatReport.swift \
	$(SECURITY_TOOLKIT_DIR)/internal/JailbreakDetector.swift \
	$(SECURITY_TOOLKIT_DIR)/internal/HooksDetector.swift \
	$(SECURITY_TOOLKIT_DIR)/internal/SimulatorDetector.swift \
	$(SECURITY_TOOLKIT_DIR)/internal/DebuggerDetector.swift \
	$(SECURITY_TOOLKIT_DIR)/internal/DevicePasscodeDetector.swift \
	$(SECURITY_TOOLKIT_DIR)/internal/HardwareSecurityDetector.swift
SecurityToolkitRunner_SWIFT_BRIDGING_HEADER = ../RunnerSupportC.h
SecurityToolkitRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-securitytoolkit-module-cache
SecurityToolkitRunner_FRAMEWORKS = UIKit Foundation LocalAuthentication
SecurityToolkitRunner_LDFLAGS = -lswiftFoundation
SecurityToolkitRunner_INSTALL_PATH = /Applications
SecurityToolkitRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
