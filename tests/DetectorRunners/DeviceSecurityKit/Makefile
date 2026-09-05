TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
DSK_DIR ?= ../../../.detector-deps/DeviceSecurityKit/Sources/DeviceSecurityKit

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = DeviceSecurityKitRunner
DeviceSecurityKitRunner_FILES = AppDelegate.swift ../RunnerSupport.swift ../RunnerSupport.m \
	../../ShadowHarness/detector-frameworks/stubs/SignatureUpdateManager.swift \
	../../ShadowHarness/detector-frameworks/stubs/DSKStubs.swift \
	../../ShadowHarness/detector-frameworks/bridges/DSKBridge.swift
DeviceSecurityKitRunner_SWIFT_BRIDGING_HEADER = ../RunnerSupportC.h
DeviceSecurityKitRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-dsk-module-cache
DeviceSecurityKitRunner_FRAMEWORKS = UIKit Foundation Security DeviceCheck
DeviceSecurityKitRunner_LDFLAGS = -lswiftFoundation
DeviceSecurityKitRunner_INSTALL_PATH = /Applications
DeviceSecurityKitRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
