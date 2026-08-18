include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = Shadow

Shadow_FILES = Core.m Core+Utilities.m Ruleset.m RulesetCompiler.m RulesetStore.m RestrictionEngine.m JBPath.m Settings.m DpkgRulesGenerator.m SystemRulesGenerator.m HookConfiguration.m
Shadow_FRAMEWORKS = Foundation CoreFoundation
Shadow_PRIVATE_FRAMEWORKS = MobileCoreServices
Shadow_INSTALL_PATH = /Library/Frameworks
# The path seam (Shadow/JBPath.h) is compile-time: the rooted/rootless mapping
# comes from THEOS_PACKAGE_INSTALL_PREFIX; the roothide scheme defines
# SHADOW_ROOTHIDE and links libroothide.
Shadow_CFLAGS = -fobjc-arc -fvisibility=hidden -IHeaders
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
Shadow_CFLAGS += -DSHADOW_ROOTHIDE
endif
Shadow_LDFLAGS = -Wl,-x -F../vendor/
# The roothide scheme module forces -install_name "@loader_path/.jbroot...";
# our explicit @rpath install_name would override it (instance LDFLAGS come
# after internal LDFLAGS), breaking roothide's .jbroot symlink resolution.
ifneq ($(THEOS_PACKAGE_SCHEME),roothide)
Shadow_LDFLAGS += -install_name @rpath/Shadow.framework/Shadow
else
Shadow_LDFLAGS += -lroothide
endif
# -fvisibility=hidden hides everything; the export list below is the ONLY
# thing that stays linkable (theos never applies Shadow.tbd as an export
# list, so without this every ObjC class is stripped and the tweak can't
# link). Keep exported_symbols.txt in sync with the classes.
Shadow_LDFLAGS += -exported_symbols_list exported_symbols.txt
Shadow_LDFLAGS += -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib

include $(THEOS_MAKE_PATH)/framework.mk
