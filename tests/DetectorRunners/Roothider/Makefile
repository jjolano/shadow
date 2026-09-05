TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
ROOTHIDER_DIR ?= ../../../.detector-deps/JailbreakDetector

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = RoothiderRunner
RoothiderRunner_FILES = AppDelegate.m ../RunnerSupport.m $(ROOTHIDER_DIR)/main.m
RoothiderRunner_CFLAGS = -fobjc-arc -I../../ShadowHarness/stubs -I$(ROOTHIDER_DIR) -fmodules-cache-path=/tmp/shadow-detector-roothider-module-cache
RoothiderRunner_FRAMEWORKS = UIKit Foundation Security LocalAuthentication
# Roothider's passcode_status probe SecItemAdds a WhenPasscodeSet item: without
# an application-identifier that call fails with -34018 (missing entitlement),
# a harness packaging artifact rather than a jailbreak signal — a real app
# always carries one. Sign with minimal keychain entitlements (ad-hoc team
# prefix; only local keychain-group derivation matters) so the probe passes
# naturally with zero Shadow involvement.
RoothiderRunner_CODESIGN_FLAGS = -S$(THEOS_PROJECT_DIR)/Resources/RoothiderRunner.entitlements
RoothiderRunner_INSTALL_PATH = /Applications
RoothiderRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
