ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:latest:12.0

ifeq ($(SHADOW_LANE),rootful-legacy)
override ARCHS := armv7 armv7s arm64 arm64e
override TARGET := iphone:clang:13.7
override TARGET_OS_DEPLOYMENT_VERSION := 9.0
override TARGET_OS_DEPLOYMENT_VERSION_arm64e := 12.0
override THEOS_PACKAGE_SCHEME :=
else ifeq ($(SHADOW_LANE),rootful-modern)
override ARCHS := arm64 arm64e
override TARGET := iphone:clang:latest:14.0
override THEOS_PACKAGE_SCHEME :=
else ifeq ($(SHADOW_LANE),rootless)
override ARCHS := arm64 arm64e
override TARGET := iphone:clang:latest:15.0
override THEOS_PACKAGE_SCHEME := rootless
else ifeq ($(SHADOW_LANE),roothide)
override ARCHS := arm64 arm64e
override TARGET := iphone:clang:latest:15.0
override THEOS_PACKAGE_SCHEME := roothide
else ifneq ($(SHADOW_LANE),)
$(error unknown SHADOW_LANE '$(SHADOW_LANE)')
endif
export ARCHS TARGET TARGET_OS_DEPLOYMENT_VERSION TARGET_OS_DEPLOYMENT_VERSION_arm64e THEOS_PACKAGE_SCHEME

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += Shadow.framework
SUBPROJECTS += Shadow.dylib
SUBPROJECTS += ShadowCore.dylib
SUBPROJECTS += ShadowSettings.bundle
SUBPROJECTS += shdw
# shadowd is unavailable in the iOS 9-13 legacy package.
ifneq ($(SHADOW_LANE),rootful-legacy)
ifneq ($(findstring arm64,$(ARCHS)),)
SUBPROJECTS += shadowd
endif
endif
include $(THEOS_MAKE_PATH)/aggregate.mk

# LaunchDaemon plist selection. The rootless scheme stages the whole layout/
# under /var/jb (THEOS_PACKAGE_INSTALL_PREFIX), so one shared layout carries
# both flavors' plists; pick the matching one here, after staging, before
# packaging. Mirrors the sandyd .rootless.plist convention.
before-package::
ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.plist"$(ECHO_END)
	$(ECHO_NOTHING)test -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.rootless.plist" && mv "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.rootless.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.plist" || true$(ECHO_END)
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.plist"$(ECHO_END)
	$(ECHO_NOTHING)test -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.rootless.plist" && mv "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.rootless.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.plist" || true$(ECHO_END)
else
ifeq ($(SHADOW_LANE),rootful-legacy)
# Legacy keeps the stateless ruleset watcher but omits shadowd and its plist.
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.rootless.plist"$(ECHO_END)
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.rootless.plist"$(ECHO_END)
else
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.rootless.plist"$(ECHO_END)
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.rootless.plist"$(ECHO_END)
endif
endif
