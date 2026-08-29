TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
JAILBREAK_DETECTOR_DIR ?= ../../.detector-deps/JailbreakDetector.swift/Sources/JailbreakDetector

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = JailbreakDetectorRunner
JailbreakDetectorRunner_FILES = AppDelegate.swift $(wildcard $(JAILBREAK_DETECTOR_DIR)/*.swift)
JailbreakDetectorRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-jailbreakdetector-module-cache
JailbreakDetectorRunner_FRAMEWORKS = UIKit Foundation
JailbreakDetectorRunner_LDFLAGS = -lswiftFoundation
JailbreakDetectorRunner_INSTALL_PATH = /Applications
JailbreakDetectorRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
