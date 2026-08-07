ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:latest:12.0

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += Shadow.framework
SUBPROJECTS += Shadow.dylib
SUBPROJECTS += ShadowCore.dylib
SUBPROJECTS += ShadowSettings.bundle
SUBPROJECTS += shdw
# shadowd is arm64-only (iOS 15+); the legacy armv7/armv7s pass must not build it.
ifneq ($(findstring arm64,$(ARCHS)),)
SUBPROJECTS += shadowd
endif
include $(THEOS_MAKE_PATH)/aggregate.mk

# LaunchDaemon plist selection. The rootless scheme stages the whole layout/
# under /var/jb (THEOS_PACKAGE_INSTALL_PREFIX), so one shared layout carries
# both flavors' plists; pick the matching one here, after staging, before
# packaging. Mirrors the sandyd .rootless.plist convention.
before-package::
ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.plist"$(ECHO_END)
	$(ECHO_NOTHING)mv "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.rootless.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.plist"$(ECHO_END)
else
ifeq ($(findstring arm64,$(ARCHS)),)
# Legacy pass: no daemon binary ships, so no daemon plist either (launchd
# would crash-loop trying to exec a missing arm64 binary).
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.rootless.plist"$(ECHO_END)
else
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.rootless.plist"$(ECHO_END)
endif
endif
