include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = ShadowHarness

ShadowHarness_FILES = main.m AppDelegate.m StatusViewController.m Battery.m ShadowDetector.m
ShadowHarness_CFLAGS = -fobjc-arc -I../Shadow.framework/Headers
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
