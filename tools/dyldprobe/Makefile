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

include $(THEOS_MAKE_PATH)/application.mk
