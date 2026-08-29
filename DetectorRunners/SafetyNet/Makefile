TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
SAFETY_DIR ?= ../../.detector-deps/SafetyNet/Sources/SafetyNet

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = SafetyNetRunner
# ponytail: native replica needs no package compile; the package's models live in subdirectories.
SafetyNetRunner_FILES = AppDelegate.swift
SafetyNetRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-safetynet-module-cache
SafetyNetRunner_FRAMEWORKS = UIKit Foundation
SafetyNetRunner_LDFLAGS = -lswiftFoundation
SafetyNetRunner_INSTALL_PATH = /Applications
SafetyNetRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
