TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
SECURITY_TOOLKIT_DIR ?= ../../.detector-deps/iOS-Security-Toolkit/Sources

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = SecurityToolkitRunner
# ponytail: Theos' Swift toolchain lacks _Concurrency; keep the synchronous
# jailbreak/hook detectors and omit the package's recurring Combine API.
SecurityToolkitRunner_FILES = AppDelegate.swift $(SECURITY_TOOLKIT_DIR)/ThreatReport.swift $(SECURITY_TOOLKIT_DIR)/internal/JailbreakDetector.swift $(SECURITY_TOOLKIT_DIR)/internal/HooksDetector.swift
SecurityToolkitRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-securitytoolkit-module-cache
SecurityToolkitRunner_FRAMEWORKS = UIKit Foundation
SecurityToolkitRunner_LDFLAGS = -lswiftFoundation
SecurityToolkitRunner_INSTALL_PATH = /Applications
SecurityToolkitRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
