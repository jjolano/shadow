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

# Loaded only by hookprobe's identity mode.  Each target has a distinct
# install name, so dyld cannot collapse copied/lookalike paths into one image.
LIBRARY_NAME = hookprobeidentitycopy hookprobeidentitysymlink hookprobeidentitybasename \
               hookprobeidentityembedded hookprobeidentitycase hookprobeidentityprefix \
               hookprobeidentitylate

hookprobeidentitycopy_FILES = identity_fixture.m
hookprobeidentitysymlink_FILES = identity_fixture.m
hookprobeidentitybasename_FILES = identity_fixture.m
hookprobeidentityembedded_FILES = identity_fixture.m
hookprobeidentitycase_FILES = identity_fixture.m
hookprobeidentityprefix_FILES = identity_fixture.m
hookprobeidentitylate_FILES = identity_fixture.m

hookprobeidentitycopy_FRAMEWORKS = Foundation
hookprobeidentitysymlink_FRAMEWORKS = Foundation
hookprobeidentitybasename_FRAMEWORKS = Foundation
hookprobeidentityembedded_FRAMEWORKS = Foundation
hookprobeidentitycase_FRAMEWORKS = Foundation
hookprobeidentityprefix_FRAMEWORKS = Foundation
hookprobeidentitylate_FRAMEWORKS = Foundation

hookprobeidentitycopy_CFLAGS = -fobjc-arc
hookprobeidentitysymlink_CFLAGS = -fobjc-arc
hookprobeidentitybasename_CFLAGS = -fobjc-arc
hookprobeidentityembedded_CFLAGS = -fobjc-arc
hookprobeidentitycase_CFLAGS = -fobjc-arc
hookprobeidentityprefix_CFLAGS = -fobjc-arc
hookprobeidentitylate_CFLAGS = -fobjc-arc

hookprobeidentitycopy_INSTALL_PATH = /usr/lib
hookprobeidentitysymlink_INSTALL_PATH = /usr/lib
hookprobeidentitybasename_INSTALL_PATH = /usr/lib
hookprobeidentityembedded_INSTALL_PATH = /usr/lib
hookprobeidentitycase_INSTALL_PATH = /usr/lib
hookprobeidentityprefix_INSTALL_PATH = /usr/lib
hookprobeidentitylate_INSTALL_PATH = /usr/lib

include $(THEOS_MAKE_PATH)/tool.mk
include $(THEOS_MAKE_PATH)/library.mk
