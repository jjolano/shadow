TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
BAT_DIR ?= ../../.detector-deps/BATJailbreakGuard/Sources/BATJailbreakGuard

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = BATJailbreakGuardRunner
# ponytail: native Swift, no external import — wildcard keeps dep optional, AppDelegate covers all 9 checks natively
BATJailbreakGuardRunner_FILES = AppDelegate.swift $(wildcard $(BAT_DIR)/*.swift)
BATJailbreakGuardRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-bat-module-cache
BATJailbreakGuardRunner_FRAMEWORKS = UIKit Foundation
BATJailbreakGuardRunner_LDFLAGS = -lswiftFoundation
BATJailbreakGuardRunner_INSTALL_PATH = /Applications
BATJailbreakGuardRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
