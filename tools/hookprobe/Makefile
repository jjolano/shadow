# hookprobe — on-device runtime battery for Shadow's hook layer.
#
# A bare CLI tool (no Info.plist → nil bundle ID → Shadow's global prefs),
# dlopens ShadowCore in-process so the ctor installs the hook layer, then
# probes each hooked API group against restricted vs control paths.
#
# Build (rootless device):
#   THEOS_PACKAGE_SCHEME=rootless make ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:15.0
# Deploy the produced binary (see the shadow-build skill) and run as root:
#   sudo /var/jb/usr/bin/hookprobe
# Exit: 0 = all probes passed, 1 = probe failure(s), 2 = hooks not active.
include $(THEOS)/makefiles/common.mk

TOOL_NAME = hookprobe

hookprobe_FILES = main.m
hookprobe_FRAMEWORKS = Foundation
hookprobe_CFLAGS = -fobjc-arc
hookprobe_INSTALL_PATH = /usr/bin

include $(THEOS_MAKE_PATH)/tool.mk
