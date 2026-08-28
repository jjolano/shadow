TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
DSK_DIR ?= ../../.detector-deps/DeviceSecurityKit/Sources/DeviceSecurityKit

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = DeviceSecurityKitRunner
# ponytail: filtered — jailbreak/hook/swizzling only, no VPN/clipboard/bg tasks
DeviceSecurityKitRunner_FILES = AppDelegate.swift $(wildcard $(DSK_DIR)/*.swift)
DeviceSecurityKitRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-dsk-module-cache
DeviceSecurityKitRunner_FRAMEWORKS = UIKit Foundation Security
DeviceSecurityKitRunner_LDFLAGS = -lswiftFoundation
DeviceSecurityKitRunner_INSTALL_PATH = /Applications
DeviceSecurityKitRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
