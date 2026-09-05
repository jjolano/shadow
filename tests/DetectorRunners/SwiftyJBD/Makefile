TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
SWIFTYJBD_DIR ?= ../../../.detector-deps/SwiftyJBD

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = SwiftyJBDRunner
SwiftyJBDRunner_FILES = AppDelegate.swift ../RunnerSupport.swift ../RunnerSupport.m $(SWIFTYJBD_DIR)/JailBreak.swift
SwiftyJBDRunner_SWIFT_BRIDGING_HEADER = SwiftyJBDRunner-Bridging.h
SwiftyJBDRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-swiftyjbd-module-cache
SwiftyJBDRunner_FRAMEWORKS = UIKit Foundation
SwiftyJBDRunner_LDFLAGS = -lswiftFoundation
SwiftyJBDRunner_INSTALL_PATH = /Applications
SwiftyJBDRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
