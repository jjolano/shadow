#include <Theos application build>
# dyldprobe — W5 on-device verification tool for Shadow v5.
# Build:  make ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:12.0
# Rootless variant: THEOS_PACKAGE_SCHEME=rootless make ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:15.0
include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = dyldprobe

dyldprobe_FILES = main.m
dyldprobe_FRAMEWORKS = UIKit Foundation
dyldprobe_CFLAGS = -fobjc-arc
dyldprobe_CODESIGN_FLAGS = -Sentitlements.plist

# shdwtestlib: a tiny dedicated dylib for the add/remove-image stress
# (main.m section 6). A shared-cache library (e.g. /usr/lib/libxml2.dylib)
# may not be unloadable, so the stress needs a real on-disk image. Installed
# inside the dyldprobe bundle; the probe copies it to a container path before
# dlopen so the path is never in Shadow's restricted domain on rootful or
# rootless (the /usr/lib and /var/jb/usr/lib copies also serve as fallback
# copy sources).
LIBRARY_NAME = shdwtestlib
shdwtestlib_FILES = testlib.m
shdwtestlib_INSTALL_PATH = /Applications/dyldprobe.app

include $(THEOS_MAKE_PATH)/application.mk
include $(THEOS_MAKE_PATH)/library.mk
