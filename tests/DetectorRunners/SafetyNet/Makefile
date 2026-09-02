TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
SAFETYNET_DIR ?= ../../../.detector-deps/SafetyNet/Sources/SafetyNet
SAFETYNET_OBJC_DIR ?= ../../../.detector-deps/SafetyNet/Sources/SafetyNetObjC
SAFETYNET_FILES = \
	$(SAFETYNET_DIR)/Detectors/DebuggerDetector.swift \
	$(SAFETYNET_DIR)/Detectors/FileIntegrityChecker.swift \
	$(SAFETYNET_DIR)/Detectors/HookDetector.swift \
	$(SAFETYNET_DIR)/Detectors/IntegrityValidator.swift \
	$(SAFETYNET_DIR)/Detectors/JailbreakDetector.swift \
	$(SAFETYNET_DIR)/Detectors/ProxyDetector.swift \
	$(SAFETYNET_DIR)/Internal/SecurityLogging.swift

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = SafetyNetRunner
SafetyNetRunner_FILES = AppDelegate.swift ../RunnerSupport.swift ../RunnerSupport.m \
	$(SAFETYNET_FILES) $(SAFETYNET_OBJC_DIR)/AntiDebugBridge.m
SafetyNetRunner_CFLAGS = -I$(SAFETYNET_OBJC_DIR) -I$(SAFETYNET_OBJC_DIR)/include
SafetyNetRunner_SWIFT_BRIDGING_HEADER = ../RunnerSupportC.h
SafetyNetRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-safetynet-module-cache -I$(SAFETYNET_OBJC_DIR)
SafetyNetRunner_FRAMEWORKS = UIKit Foundation Security CFNetwork CryptoKit
SafetyNetRunner_LDFLAGS = -lswiftFoundation
SafetyNetRunner_INSTALL_PATH = /Applications
SafetyNetRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
