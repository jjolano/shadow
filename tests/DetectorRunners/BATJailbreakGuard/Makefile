TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
BAT_DIR ?= ../../../.detector-deps/BATJailbreakGuard/Sources/BATJailbreakGuard
BAT_FILES := $(shell find $(BAT_DIR) -name '*.swift' | sort)

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = BATJailbreakGuardRunner
BATJailbreakGuardRunner_FILES = AppDelegate.swift ../RunnerSupport.swift ../RunnerSupport.m $(BAT_FILES)
BATJailbreakGuardRunner_SWIFT_BRIDGING_HEADER = ../RunnerSupportC.h
BATJailbreakGuardRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-bat-module-cache
BATJailbreakGuardRunner_FRAMEWORKS = UIKit Foundation
BATJailbreakGuardRunner_LDFLAGS = -lswiftFoundation
BATJailbreakGuardRunner_INSTALL_PATH = /Applications
BATJailbreakGuardRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
