# The Harness contains its dashboard, Shadow diagnostics, and the dyld probe.
# SDK detector implementations remain separate applications so startup-
# sensitive SDKs never share the Harness process or its already-loaded Shadow
# framework.
TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
SHDW_DYLDPROBE_OBJ_DIR := ../tools/dyldprobe/.theos/obj

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = ShadowHarness
ShadowHarness_FILES = main.m AppDelegate.m SceneDelegate.m DetectorDashboard.m StatusViewController.m Battery.m Detectors.m ../tools/dyldprobe/main.m ../detectors/ShadowDetector.m
ShadowHarness_CFLAGS = -fobjc-arc -fmodules-cache-path=/tmp/shadow-harness-module-cache -DSHADOW_HARNESS -DSHDW_DYLDPROBE_EMBEDDED -I../detectors -I../../src/Shadow.framework/Headers
ShadowHarness_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowHarness_LDFLAGS += -F../../src/ -F../../vendor/
ShadowHarness_EXTRA_FRAMEWORKS = Shadow
ShadowHarness_FRAMEWORKS = UIKit Foundation
ShadowHarness_INSTALL_PATH = /Applications
ShadowHarness_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk

before-stage::
	$(ECHO_NOTHING)rm -rf \
		"$(THEOS_STAGING_DIR)/Applications/IOSSecuritySuiteRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/JailbreakDetectorRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/SecurityToolkitRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/DTTJailbreakDetectionRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/FreeRASPRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/RoothiderRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/BATJailbreakGuardRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/SafetyNetRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/DeviceSecurityKitRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/JailMonkeyRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks" \
		"$(THEOS_STAGING_DIR)/Applications/dyldprobe.app"$(ECHO_END)

ifneq ($(INCLUDE_DETECTOR_RUNNERS),)
after-stage::
	$(ECHO_NOTHING)for app in \
		../DetectorRunners/IOSSecuritySuite/.theos/_/Applications/IOSSecuritySuiteRunner.app \
		../DetectorRunners/JailbreakDetector/.theos/_/Applications/JailbreakDetectorRunner.app \
		../DetectorRunners/SecurityToolkit/.theos/_/Applications/SecurityToolkitRunner.app \
		../DetectorRunners/DTTJailbreakDetection/.theos/_/Applications/DTTJailbreakDetectionRunner.app \
		../DetectorRunners/FreeRASP/.theos/_/Applications/FreeRASPRunner.app \
		../DetectorRunners/Roothider/.theos/_/Applications/RoothiderRunner.app \
		../DetectorRunners/BATJailbreakGuard/.theos/_/Applications/BATJailbreakGuardRunner.app \
		../DetectorRunners/SafetyNet/.theos/_/Applications/SafetyNetRunner.app \
		../DetectorRunners/DeviceSecurityKit/.theos/_/Applications/DeviceSecurityKitRunner.app \
		../DetectorRunners/JailMonkey/.theos/_/Applications/JailMonkeyRunner.app \
		../tools/dyldprobe/.theos/_/Applications/dyldprobe.app; do \
		test -d "$$app" || exit 1; \
		cp -R "$$app" "$(THEOS_STAGING_DIR)/Applications/"; \
	done; \
	test -f "$(SHDW_DYLDPROBE_OBJ_DIR)/shdwtestlib.dylib" || exit 1; \
	mkdir -p "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks"; \
	cp "$(SHDW_DYLDPROBE_OBJ_DIR)/shdwtestlib.dylib" \
		"$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/"$(ECHO_END)
endif
