#import "ShadowDetector.h"

#import <unistd.h>
#import <fcntl.h>
#import <errno.h>

#import <Shadow.h>

// Check 1: existence of well-known jailbreak artifacts (rootless + rooted
// era). Probed via access(F_OK): on the host, access is interposed so
// /var/jb and rooted-JB prefixes resolve into the fixture jbroot, and in
// shadow mode engine-restricted paths report ENOENT.
static const char* const kSuspiciousPaths[] = {
    // Modern rootless jailbreaks (Dopamine, palera1n, roothide)
    "/var/jb",
    "/var/jb/usr/bin",
    "/var/jb/Library/LaunchDaemons",
    "/var/jb/etc/rc.d",
    "/var/Liy/.procursus_strapped",
    "/var/Liy",
    "/Applications/Dopamine.app",
    "/var/mobile/Library/Preferences/com.opa334.Dopamine.plist",
    "/Applications/palera1nLoader.app",
    "/usr/bin/palera1n-helper",
    "/var/mobile/Library/Preferences/com.samiiau.loader.plist",
    "/var/mobile/Library/Preferences/com.roothide.pref.plist",
    "/usr/lib/libellekit.dylib",
    "/var/jb/usr/lib/libellekit.dylib",
    "/var/mobile/Library/Preferences/ABPattern",
    "/usr/lib/ABDYLD.dylib",
    "/usr/lib/ABSubLoader.dylib",
    "/usr/sbin/frida-server",
    "/usr/lib/frida",

    // Electra
    "/etc/apt/sources.list.d/electra.list",
    "/etc/apt/sources.list.d/sileo.sources",
    "/.bootstrapped_electra",
    "/usr/lib/libjailbreak.dylib",
    "/jb/lzma",

    // unc0ver
    "/.cydia_no_stash",
    "/.installed_unc0ver",
    "/jb/offsets.plist",
    "/usr/share/jailbreak/injectme.plist",
    "/etc/apt/undecimus/undecimus.list",
    "/var/lib/dpkg/info/mobilesubstrate.md5sums",
    "/jb/jailbreakd.plist",
    "/jb/amfid_payload.dylib",
    "/jb/libjailbreak.dylib",

    // checkra1n
    "/var/binpack",
    "/var/binpack/Applications/loader.app",

    // Substrate/Substitute/libhooker
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/CydiaSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.plist",
    "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.plist",
    "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/substrate",
    "/usr/lib/TweakInject",

    // Cydia and package managers
    "/usr/libexec/cydia/firmware.sh",
    "/var/lib/cydia",
    "/etc/apt",
    "/private/var/lib/apt",
    "/var/log/apt",
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/private/var/stash",
    "/private/var/lib/cydia",
    "/private/var/cache/apt/",
    "/private/var/log/syslog",
    "/private/var/tmp/cydia.log",

    // Preference bundles (jailbreak tools)
    "/Library/PreferenceBundles/LibertyPref.bundle",
    "/Library/PreferenceBundles/ShadowPreferences.bundle",
    "/Library/PreferenceBundles/ABypassPrefs.bundle",
    "/Library/PreferenceBundles/FlyJBPrefs.bundle",
    "/Library/PreferenceBundles/Cephei.bundle",
    "/Library/PreferenceBundles/SubstitutePrefs.bundle",
    "/Library/PreferenceBundles/libhbangprefs.bundle",

    // Legacy jailbreak apps
    "/Applications/Icy.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/blackra1n.app",
    "/Applications/SBSettings.app",
    "/Applications/FakeCarrier.app",
    "/Applications/WinterBoard.app",
    "/Applications/IntelliScreen.app",
    "/Applications/FlyJB.app",
    "/Library/BawAppie/ABypass",

    // Other artifacts
    "/private/var/mobile/Library/SBSettings/Themes",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/var/mobile/Library/Preferences/me.jjolano.shadow.plist",

    // Shadow's own artifacts: the vnode daemon and the ruleset watcher. The
    // daemon binary and shdw are rootful exact-blacklist entries in the
    // shipped JailbreakMisc.plist (SystemRules covers them only when its
    // generation succeeded), so probing them must stay ENOENT from the
    // shipped rulesets alone.
    "/usr/libexec/shadowd",
    "/var/jb/usr/libexec/shadowd",
    "/usr/local/bin/shdw",
    "/var/jb/usr/local/bin/shdw",
};

// These paths exist legitimately on simulators and are SKIPPED by
// IOSSecuritySuite there (EmulatorChecker.amIRunInEmulator). The harness
// host is the emulator case, so the RUN omits them — but the AUDIT probes
// them too, because they are classic detector paths and a real ruleset
// gap would leak them on devices where they exist (e.g. /usr/sbin/sshd).
static const char* const kEmulatorOnlyPaths[] = {
    "/bin/bash",
    "/usr/sbin/sshd",
    "/usr/libexec/ssh-keysign",
    "/bin/sh",
    "/etc/ssh/sshd_config",
    "/usr/libexec/sftp-server",
    "/usr/bin/ssh",
};

// Check 2: suspicious files that can actually be opened (R_OK).
static const char* const kReadablePaths[] = {
    "/.installed_unc0ver",
    "/.bootstrapped_electra",
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/etc/apt",
    "/var/log/apt",
};

// Check 3: restricted directories writable by the probe. Scoped to the
// simulated rootless jailbreak roots (the host cannot simulate the iOS
// sandbox, and the meaningful signal is jbroot writability).
static const char* const kWritableDirs[] = {
    "/var/jb",
    "/var/jb/usr/lib",
    "/var/jb/Library",
};

// Check 4: jailbreak URL schemes. Consulted through Shadow's engine
// (isSchemeRestricted) — with Shadow active the schemes are filtered, with
// an empty ruleset (Shadow off) they are reachable.
static const char* const kSuspiciousSchemes[] = {
    "cydia", "sileo", "zbra", "undecimus", "filza", "xina",
};

static void setResult(ShdwDetectorResult* r, const char* fmt, const char* arg) {
    if(!r->jailbroken) {
        r->jailbroken = YES;
        snprintf(r->reason, sizeof(r->reason), fmt, arg);
    }
}

// Appends one audit entry. `group` names the check; `detail` the probe.
static void auditAdd(NSMutableArray* audit, NSString* group, NSString* detail, BOOL fired) {
    [audit addObject:@{
        @"probe" : [NSString stringWithFormat:@"%@ %@", group, detail],
        @"fired" : @(fired),
        @"detail" : detail,
    }];
}

NSArray* ShdwDetectorAudit(void) {
    NSMutableArray* audit = [NSMutableArray new];

    for(NSUInteger i = 0; i < sizeof(kSuspiciousPaths) / sizeof(kSuspiciousPaths[0]); i++) {
        auditAdd(audit, @"exists", [NSString stringWithUTF8String:kSuspiciousPaths[i]],
            access(kSuspiciousPaths[i], F_OK) == 0);
    }

    for(NSUInteger i = 0; i < sizeof(kEmulatorOnlyPaths) / sizeof(kEmulatorOnlyPaths[0]); i++) {
        auditAdd(audit, @"exists(emu)", [NSString stringWithUTF8String:kEmulatorOnlyPaths[i]],
            access(kEmulatorOnlyPaths[i], F_OK) == 0);
    }

    for(NSUInteger i = 0; i < sizeof(kReadablePaths) / sizeof(kReadablePaths[0]); i++) {
        auditAdd(audit, @"readable", [NSString stringWithUTF8String:kReadablePaths[i]],
            access(kReadablePaths[i], R_OK) == 0);
    }

    for(NSUInteger i = 0; i < sizeof(kWritableDirs) / sizeof(kWritableDirs[0]); i++) {
        NSString* random = [NSString stringWithFormat:@"%s/AmIJailbroken?%08x",
            kWritableDirs[i], (unsigned)arc4random()];
        int fd = open([random fileSystemRepresentation], O_CREAT | O_WRONLY | O_EXCL, 0644);

        if(fd >= 0) {
            close(fd);
            unlink([random fileSystemRepresentation]);
        }

        auditAdd(audit, @"writable", [NSString stringWithUTF8String:kWritableDirs[i]], fd >= 0);
    }

    for(NSUInteger i = 0; i < sizeof(kSuspiciousSchemes) / sizeof(kSuspiciousSchemes[0]); i++) {
        NSString* scheme = [NSString stringWithUTF8String:kSuspiciousSchemes[i]];
        auditAdd(audit, @"scheme", scheme,
            ![[Shadow sharedInstance] isSchemeRestricted:scheme]);
    }

    return audit;
}

ShdwDetectorResult ShdwDetectorRun(void) {
    ShdwDetectorResult result = { NO, "" };

    for(NSUInteger i = 0; i < sizeof(kSuspiciousPaths) / sizeof(kSuspiciousPaths[0]); i++) {
        if(access(kSuspiciousPaths[i], F_OK) == 0) {
            setResult(&result, "suspicious file exists: %s", kSuspiciousPaths[i]);
            return result;
        }
    }

    for(NSUInteger i = 0; i < sizeof(kReadablePaths) / sizeof(kReadablePaths[0]); i++) {
        if(access(kReadablePaths[i], R_OK) == 0) {
            setResult(&result, "suspicious file readable: %s", kReadablePaths[i]);
            return result;
        }
    }

    for(NSUInteger i = 0; i < sizeof(kWritableDirs) / sizeof(kWritableDirs[0]); i++) {
        NSString* random = [NSString stringWithFormat:@"%s/AmIJailbroken?%08x",
            kWritableDirs[i], (unsigned)arc4random()];

        int fd = open([random fileSystemRepresentation], O_CREAT | O_WRONLY | O_EXCL, 0644);

        if(fd >= 0) {
            close(fd);
            unlink([random fileSystemRepresentation]);
            setResult(&result, "wrote to restricted directory: %s", kWritableDirs[i]);
            return result;
        }
    }

    for(NSUInteger i = 0; i < sizeof(kSuspiciousSchemes) / sizeof(kSuspiciousSchemes[0]); i++) {
        NSString* scheme = [NSString stringWithUTF8String:kSuspiciousSchemes[i]];

        // A detector asks "can this scheme open?"; Shadow's answer is
        // isSchemeRestricted — reachable = not restricted.
        if(![[Shadow sharedInstance] isSchemeRestricted:scheme]) {
            setResult(&result, "jailbreak URL scheme reachable: %s", kSuspiciousSchemes[i]);
            return result;
        }
    }

    return result;
}
