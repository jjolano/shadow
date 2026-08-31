include build-lanes.mk

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += Shadow.framework
SUBPROJECTS += Shadow.dylib
SUBPROJECTS += ShadowCore.dylib
SUBPROJECTS += ShadowSettings.bundle
SUBPROJECTS += shdw
include $(THEOS_MAKE_PATH)/aggregate.mk

# The rootless scheme stages the whole layout/ under /var/jb. Select the
# matching ruleset-watcher plist after staging, before packaging.
before-package::
ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.plist"$(ECHO_END)
	$(ECHO_NOTHING)test -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.rootless.plist" && mv "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.rootless.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.plist" || true$(ECHO_END)
else
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.rootless.plist"$(ECHO_END)
endif
