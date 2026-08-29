TARGET ?= iphone:clang:latest:14.0
include $(THEOS)/makefiles/common.mk
APPLICATION_NAME = ShadowHarness
ShadowHarness_FILES = main.m AppDelegate.m SceneDelegate.m DetectorDashboard.m StatusViewController.m Battery.m Detectors.m ../tests/detectors/ShadowDetector.m
ShadowHarness_CFLAGS = -fobjc-arc -fmodules-cache-path=/tmp/shadow-harness-module-cache -DSHADOW_HARNESS -I../tests/detectors -I../Shadow.framework/Headers
ShadowHarness_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowHarness_LDFLAGS += -F../ -F../vendor/
ShadowHarness_EXTRA_FRAMEWORKS = Shadow
ShadowHarness_FRAMEWORKS = UIKit Foundation
ShadowHarness_INSTALL_PATH = /Applications
ShadowHarness_RESOURCE_DIRS = Resources
include $(THEOS_MAKE_PATH)/application.mk
before-stage::
	$(ECHO_NOTHING)rm -rf "$(THEOS_STAGING_DIR)/Applications/dyldprobe.app"$(ECHO_END)
ifeq ($(INCLUDE_DETECTOR_RUNNERS),1)
$(warning INCLUDE_DETECTOR_RUNNERS is deprecated — detectors are in-process)
endif
