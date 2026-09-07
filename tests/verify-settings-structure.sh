#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"

# Device-tool path check resolves against the private harness checkout
# (PRIVATE_HT, default tests/). Public runs skip it; private runs it.
HT=${PRIVATE_HT:-tests}

root=src/ShadowSettings.bundle/Resources/Root.plist
app=src/ShadowSettings.bundle/Resources/App.plist
runtime=src/ShadowCore.dylib/shadowcore.x
loader=src/Shadow.dylib/dylib.x
settings=src/Shadow.framework/Settings.m
profile=src/Shadow.framework/HookConfiguration.m

if grep -Rqs --exclude-dir=.theos 'SHDWPreset' src/Shadow.framework src/ShadowCore.dylib src/ShadowSettings.bundle; then
    echo 'SETTINGS DRIFT: preset API or UI returned'
    exit 1
fi

if grep -Eq 'SHDWHooksListController|BypassPreset' "$root"; then
    echo 'SETTINGS DRIFT: root pane exposes profile controls'
    exit 1
fi

# The root pane keeps the global activation switch, the applications list, and
# About — nothing else. The removed tools (respring/reset/import/export) and
# the detector log must stay gone.
grep -q '<string>Global_Enabled</string>' "$root" || {
    echo 'SETTINGS DRIFT: root pane lost the global activation switch'
    exit 1
}
if grep -Eq 'respring:|reset:|exportSettings:|importSettings:|DetectorLog' "$root"; then
    echo 'SETTINGS DRIFT: removed tools or detector log returned to the root pane'
    exit 1
fi

# The app pane is a single Follow Global toggle plus the two settings it
# governs (App_Enabled and Detector_Aggressive): three switches, no revived
# per-hook or profile controls, and no App_Disabled (the single-toggle backend
# never writes it). Aggressive mode has no separate follow-global toggle — it
# follows the one App_FollowGlobal. Universal_/Adapter_ per-hook keys must never
# reappear as UI; Detector_Aggressive is the one allowed detector-mode key.
if [ "$(grep -c '<string>PSSwitchCell</string>' "$app")" -ne 3 ] ||
   ! grep -q '<string>App_Enabled</string>' "$app" ||
   ! grep -q '<string>App_FollowGlobal</string>' "$app" ||
   ! grep -q '<string>Detector_Aggressive</string>' "$app" ||
   grep -q '<string>App_AggressiveFollowGlobal</string>' "$app" ||
   grep -Eq 'App_Disabled|BypassPreset|Universal_|Adapter_' "$app"; then
    echo 'SETTINGS DRIFT: app pane is not the single follow-global toggle plus App_Enabled and Detector_Aggressive'
    exit 1
fi

# Preferences' PSSpecifier controller cannot run in the public Linux host
# checks. Execute its actual remove/insert call sequence against the plist IDs
# instead, covering initial follow-global state and repeated off/on restores.
controller=src/ShadowSettings.bundle/SHDWAppListController.m
python3 - "$controller" "$app" <<'PY'
import plistlib
import re
import sys
from pathlib import Path


def block(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    for position in range(opening + 1, len(source)):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
            if depth == 0:
                return source[opening:position + 1]
    raise AssertionError(marker)


def operations(source):
    calls = re.compile(
        r'\[self removeSpecifier:(?P<remove>\w+) animated:[^]]+\];'
        r'|\[self insertSpecifier:(?P<insert>\w+) '
        r'afterSpecifier:(?P<after>.*?) animated:YES\];'
    )
    result = []
    for call in calls.finditer(source):
        if call.group("remove"):
            result.append(("remove", call.group("remove"), None))
            continue
        after = call.group("after")
        identifier = re.search(r'specifierForID:@"([^"]+)"', after)
        result.append(("insert", call.group("insert"),
                       identifier.group(1) if identifier else after.strip()))
    return result


source = Path(sys.argv[1]).read_text()
with open(sys.argv[2], "rb") as stream:
    plist_ids = [item["id"] for item in plistlib.load(stream)["items"]]

specifiers = block(source, "- (NSArray *)specifiers")
setter = block(source, "- (void)setPreferenceValue:")
initial = block(specifiers, "if([self followGlobal])")
follow_global = block(setter, 'if([key isEqualToString:@"App_FollowGlobal"])')
enabled = block(follow_global, "if([value boolValue])")
disabled = block(follow_global, "} else {")

assert 'aggressiveGroupSpecifier = [self specifierForID:@"AppAggressiveGroup"];' in specifiers
initial_ops = operations(initial)
on_ops = operations(enabled)
off_ops = operations(disabled)
assert [op[1] for op in initial_ops] == [
    "enabledSpecifier", "aggressiveSpecifier", "aggressiveGroupSpecifier"
]
assert [op[1] for op in on_ops] == [
    "aggressiveSpecifier", "enabledSpecifier", "aggressiveGroupSpecifier"
]
assert [op[1:] for op in off_ops] == [
    ("enabledSpecifier", "App_FollowGlobal"),
    ("aggressiveGroupSpecifier", "enabledSpecifier"),
    ("aggressiveSpecifier", "aggressiveGroupSpecifier"),
]

specifier_ids = {
    "enabledSpecifier": "App_Enabled",
    "aggressiveGroupSpecifier": "AppAggressiveGroup",
    "aggressiveSpecifier": "Detector_Aggressive",
}
full = [
    "AppSettingsGroup", "App_FollowGlobal", "App_Enabled",
    "AppAggressiveGroup", "Detector_Aggressive",
]
assert plist_ids == full, "App.plist specifier order changed"


def apply(specifiers, calls):
    specifiers = list(specifiers)
    for kind, name, anchor in calls:
        identifier = specifier_ids[name]
        if kind == "remove":
            assert identifier in specifiers, (kind, identifier, specifiers)
            specifiers.remove(identifier)
        else:
            assert identifier not in specifiers, (kind, identifier, specifiers)
            index = specifiers.index(specifier_ids.get(anchor, anchor))
            specifiers.insert(index + 1, identifier)
    return specifiers


following = ["AppSettingsGroup", "App_FollowGlobal"]
assert apply(full, initial_ops) == following
for _ in range(2):
    assert apply(full, on_ops) == following
    assert apply(following, off_ops) == full
    following = apply(full, on_ops)
print("PASS: app controller follow-global visibility transitions (static call sequence)")
PY

# Aggressive mode is a live scalar resolved with global fallback (like
# activation), gated into disable-style adapter paths — never a per-hook knob.
grep -q 'SHDWDetectorAggressiveID' "$profile" || {
    echo 'SETTINGS DRIFT: built-in profile lost the Detector_Aggressive default'
    exit 1
}
grep -q 'SHDWDetectorAggressiveID' src/Shadow.framework/SettingsMigration.m || {
    echo 'SETTINGS DRIFT: Detector_Aggressive not in the live-key allowlist'
    exit 1
}
grep -q 'shdw_detector_aggressive' src/ShadowCore.dylib/hooks/Adapters/DeviceSecurityKit.x || {
    echo 'SETTINGS DRIFT: disable-style adapter path no longer gated on aggressive mode'
    exit 1
}

for obsolete in Hooks Individual Dangerous Adapters Troubleshooting DetectorLog; do
    if [ -e "src/ShadowSettings.bundle/Resources/$obsolete.plist" ]; then
        echo "SETTINGS DRIFT: obsolete $obsolete pane returned"
        exit 1
    fi
done

# The detector log is gone entirely: no controller, no runtime recorder.
if [ -e src/ShadowSettings.bundle/SHDWDetectorLogListController.m ]; then
    echo 'SETTINGS DRIFT: detector log controller returned'
    exit 1
fi
if grep -q 'DetectorLog' src/Shadow.framework/RestrictionEngine.m; then
    echo 'SETTINGS DRIFT: detector log runtime recorder returned'
    exit 1
fi

for key in SHDWUniversalFoundationID SHDWUniversalMachBootstrapID SHDWUniversalIOKitID SHDWUniversalSyscallID; do
    grep -q "$key : @(YES)" "$profile" || {
        echo "SETTINGS DRIFT: built-in profile does not enable $key"
        exit 1
    }
done

grep -q 'result\[SHDWAppEnabledID\] = @(enabled)' "$settings" &&
! grep -q 'addEntriesFromDictionary' "$settings" &&
grep -q 'SHDWApplicationEnabled' "$loader" &&
grep -q 'bundleIdentifier.length == 0' "$settings" || {
    echo 'SETTINGS DRIFT: runtime no longer uses the fixed profile with per-app activation'
    exit 1
}

grep -q 'kSHDWDetectorRunnerOverridesKey = @"Test_DetectorOverrides"' "$settings" &&
grep -q 'isEqualToString:@"me.jjolano.shadow.harness"' "$settings" &&
grep -q 'SHDWAdapterDeviceCheckID, SHDWAdapterFreeRASPID' "$settings" &&
grep -q 'SHDWAdapterDeviceSecurityKitID, SHDWAdapterIOSSecuritySuiteID' "$settings" || {
    echo 'SETTINGS DRIFT: detector overrides must remain private to test runners'
    exit 1
}

# A per-app toggle edit takes the app off "follow global" by writing an
# explicit App_Enabled and stamping the single-toggle migration marker;
# clearing it (follow global) drops the override key.
grep -q 'setBool:YES forKey:SHDWSingleToggleMigrationID' src/ShadowSettings.bundle/SHDWPrefs.m &&
grep -q 'removeObjectForKey:SHDWAppEnabledID' src/ShadowSettings.bundle/SHDWPrefs.m || {
    echo 'SETTINGS DRIFT: per-app toggle must use explicit single-toggle semantics with follow-global clear'
    exit 1
}

grep -q 'SHDWAppDisabledID.*SHDWAppEnabledID' src/Shadow.framework/SettingsMigration.m ||
grep -q 'migrated\[SHDWAppEnabledID\] = @NO' src/Shadow.framework/SettingsMigration.m || {
    echo 'SETTINGS DRIFT: legacy App_Disabled migration is missing'
    exit 1
}

# Shadow runs the fixed full-capability profile when enabled, so migration must
# prune the plist to the live surface — obsolete hook toggles cannot linger as
# phantom switches. Enforce the allowlist-and-strip shape.
grep -q 'liveScalarKeys' src/Shadow.framework/SettingsMigration.m &&
grep -q 'removeObjectForKey:key' src/Shadow.framework/SettingsMigration.m || {
    echo 'SETTINGS DRIFT: migration no longer prunes obsolete keys to the live surface'
    exit 1
}

for source in "$loader" "$settings"; do
    grep -q 'dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST' "$source" || {
        echo "SETTINGS DRIFT: $source lost the sandboxed per-app fallback"
        exit 1
    }
done

# Canonical preference path is shared by the device tools in the private
# harness; skip when no harness checkout is present.
if [ -f "$HT/stealth_device.py" ]; then
grep -q 'return "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"' "$HT/stealth_device.py" &&
grep -q '^PREFS_REMOTE=/var/mobile/Library/Preferences/me.jjolano.shadow.plist$' "$HT/bench/run-b.sh" || {
    echo 'SETTINGS DRIFT: device tools must edit the canonical preference file'
    exit 1
}
fi
