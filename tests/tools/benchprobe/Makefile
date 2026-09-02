# benchprobe — on-device per-call microbenchmark battery for Shadow's hooks.
#
# A bare CLI tool (no Info.plist, so Shadow recognizes it as a diagnostic),
# dlopens ShadowCore in-process so the ctor installs the hook layer, then
# times one representative call per hooked API group in a tight loop and
# emits CSV rows. `--no-shadow` skips the dlopen for the stock arm.
#
# Build (rootless device):
#   THEOS_PACKAGE_SCHEME=rootless make ARCHS="arm64" TARGET=iphone:clang:latest:15.0
# Deploy to /var/jb/usr/bin/benchprobe and run as root:
#   sudo /var/jb/usr/bin/benchprobe --iters 10000
# Exit: 0 = ran, 2 = hooks not active (prefs gate / ctor bail).
include $(THEOS)/makefiles/common.mk

TOOL_NAME = benchprobe

benchprobe_FILES = main.m
benchprobe_FRAMEWORKS = Foundation Security
benchprobe_CFLAGS = -fobjc-arc
benchprobe_INSTALL_PATH = /usr/bin

include $(THEOS_MAKE_PATH)/tool.mk
