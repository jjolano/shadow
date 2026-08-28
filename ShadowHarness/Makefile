# The redesigned UI (scene lifecycle, list layouts, SF Symbols) needs iOS 14+.
# build.sh passes TARGET explicitly per flavor; this default covers standalone
# builds of the harness.
TARGET ?= iphone:clang:latest:14.0
include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = ShadowHarness

ShadowHarness_FILES = main.m AppDelegate.m SceneDelegate.m DetectorDashboard.m StatusViewController.m Battery.m ../tests/detectors/ShadowDetector.m
ShadowHarness_CFLAGS = -fobjc-arc -fmodules-cache-path=/tmp/shadow-harness-module-cache -DSHADOW_HARNESS -I../tests/detectors -I../Shadow.framework/Headers
# Mirror shdw's linkage exactly: Shadow.framework resolves at runtime through
# these rpaths (rooted + rootless layouts), staged builds come from $THEOS/lib.
ShadowHarness_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowHarness_LDFLAGS += -F../ -F../vendor/
ShadowHarness_EXTRA_FRAMEWORKS = Shadow
ShadowHarness_FRAMEWORKS = UIKit Foundation
ShadowHarness_INSTALL_PATH = /Applications
# Explicit so the icon PNGs (and Info.plist, per theos convention) land in
# the bundle; theos would pick up Resources/ by default anyway.
ShadowHarness_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk

before-stage::
	$(ECHO_NOTHING)rm -rf \
		"$(THEOS_STAGING_DIR)/Applications/IOSSecuritySuiteRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/DTTJailbreakDetectionRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/FreeRASPRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/RoothiderRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/BATJailbreakGuardRunner.app" \
		"$(THEOS_STAGING_DIR)/Applications/dyldprobe.app"$(ECHO_END)

ifneq ($(INCLUDE_DETECTOR_RUNNERS),)
after-stage::
	$(ECHO_NOTHING)for app in \
		../DetectorRunners/IOSSecuritySuite/.theos/_/Applications/IOSSecuritySuiteRunner.app \
		../DetectorRunners/DTTJailbreakDetection/.theos/_/Applications/DTTJailbreakDetectionRunner.app \
		../DetectorRunners/FreeRASP/.theos/_/Applications/FreeRASPRunner.app \
		../DetectorRunners/Roothider/.theos/_/Applications/RoothiderRunner.app \
		../DetectorRunners/BATJailbreakGuard/.theos/_/Applications/BATJailbreakGuardRunner.app \
		../tools/dyldprobe/.theos/_/Applications/dyldprobe.app; do \
		test -d "$$app" || exit 1; \
		cp -R "$$app" "$(THEOS_STAGING_DIR)/Applications/"; \
	done$(ECHO_END)
endif
