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

# Reformat tolerance for the source-text pins below: clang-format may respace
# `if(x)` into `if (x)` or wrap a long declaration onto the next line, so a pin
# compares TOKENS — the file and the needle both with every whitespace character
# removed — instead of raw text. Spacing-only changes cannot break a pin; a
# genuinely missing token still fails it.
norm() { tr -d '[:space:]'; }

# True when "$1"'s whitespace-stripped text contains each remaining needle, in
# order, all whitespace likewise stripped. Needles are literal substrings (no
# regex/glob interpretation), so pins carrying `[`, `*` or `?` keep meaning them.
pinned() {
    file=$1
    shift
    [ -f "$file" ] || return 1
    text=$(norm <"$file")
    for needle in "$@"; do
        needle=$(printf '%s' "$needle" | norm)
        rest=${text#*"$needle"}
        [ "$rest" != "$text" ] || return 1
        text=$rest
    done
    return 0
}

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


def anchor_pattern(needle):
    """Regex for `needle`, tolerant of reformat spacing."""
    return r"\s*".join(
        re.escape(tok) for tok in re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", needle)
    )


def anchor(text, needle, start=0):
    """Index of `needle` in `text`, tolerant of reformat spacing."""
    match = re.search(anchor_pattern(needle), text[start:])
    if match is None:
        raise ValueError(f"anchor not found: {needle!r}")
    return start + match.start()


def unsplit(text):
    """Rejoin adjacent literals (`@"A" @"B"`) that reformat wrapping may split."""
    return re.sub(r'"\s*@"', "", text)


def has(text, needle):
    """True when `needle` occurs in `text`, tolerant of reformat spacing and of
    long literals the formatter wrapped into adjacent literals."""
    return re.search(anchor_pattern(needle), unsplit(text)) is not None


def block(source, marker):
    start = anchor(source, marker)
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
        r'\[self\s+removeSpecifier:(?P<remove>\w+)\s+animated:[^]]+\];'
        r'|\[self\s+insertSpecifier:(?P<insert>\w+)\s+'
        r'afterSpecifier:(?P<after>.*?)\s+animated:YES\];',
        re.S,
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

assert has(specifiers, 'aggressiveGroupSpecifier = [self specifierForID:@"AppAggressiveGroup"];')
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
    "AppResetGroup", "AppReset",
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


following = ["AppSettingsGroup", "App_FollowGlobal", "AppResetGroup", "AppReset"]
assert apply(full, initial_ops) == following
for _ in range(2):
    assert apply(full, on_ops) == following
    assert apply(following, off_ops) == full
    following = apply(full, on_ops)
print("PASS: app controller follow-global visibility transitions (static call sequence)")

reset = block(source, '- (void)resetAppSettings:')
assert has(reset, 'style:UIAlertActionStyleCancel handler:nil')
confirmation = block(reset, 'style:UIAlertActionStyleDestructive handler:')
assert has(confirmation, 'BOOL saved = SHDWResetApp(prefs, [self applicationID]);')
assert has(confirmation, '[self reloadSpecifiers];')
assert anchor(confirmation, '[self reloadSpecifiers];') < anchor(confirmation, 'if(saved)')
success = block(confirmation, 'if(saved)')
failure = block(confirmation, '} else {')
assert 'SHDWToggleHaptic();' in success and confirmation.count('SHDWToggleHaptic();') == 1
assert has(failure, 'RESET_APP_FAILED') and has(failure, 'RESET_APP_FAILED_DESC')
assert 'RESET_OK' in failure and 'SHDWToggleHaptic' not in failure
dismissal = block(failure, '[self dismissViewControllerAnimated:YES completion:')
assert has(dismissal, '[self presentViewController:failure animated:YES completion:nil];')
assert reset.count('SHDWResetApp(') == 1
assert has(reset, '[self presentViewController:alert animated:YES completion:nil];')
with open(sys.argv[2], 'rb') as stream:
    reset_row = next(row for row in plistlib.load(stream)['items'] if row['id'] == 'AppReset')
assert reset_row['action'] == 'resetAppSettings:' and reset_row['isDestructive']

settings_dir = Path(sys.argv[1]).parent
about = (settings_dir / 'SHDWAboutListController.m').read_text()
updates = (settings_dir / 'SHDWUpdatesController.m').read_text()
about_plist = plistlib.loads((settings_dir / 'Resources/About.plist').read_bytes())
updates_row = next(row for row in about_plist['items'] if row.get('id') == 'AboutUpdates')
assert updates_row['cell'] == 'PSLinkCell' and updates_row['detail'] == 'SHDWUpdatesController'
assert {row['get'] for row in about_plist['items'] if 'get' in row} == {
    'aboutInstalledVersion:', 'aboutDeveloper:', 'aboutTranslator:'}
for removed in ['openChangeLog', 'aboutLatestVersion', 'aboutUpdateStatus',
                'releaseNotesController', 'VISIT_CHANGELOG', 'NOTES_DONE', 'NOTES_LOADING']:
    for path in list(settings_dir.glob('*.[mh]')) + list((settings_dir / 'Resources').rglob('*')):
        if path.is_file() and path.suffix in ['.m', '.h', '.strings', '.plist']:
            assert removed not in path.read_text(), (path, removed)
assert 'NSURLSession' not in about
assert has(about, 'SHDWInstalledVersion() ?: [self localized:@"UNKNOWN"]')
check = block(updates, '- (void)checkForUpdates:')
assert updates.count('dataTaskWithURL:') == check.count('dataTaskWithURL:') == 1
assert has(check, 'if(fetchingLatestVersion) return;')
assert updates.count('[self checkForUpdates:') == 1
for lifecycle in ['viewDidLoad', 'viewWillAppear:', 'viewDidDisappear:']:
    method = block(updates, '- (void)' + lifecycle)
    assert 'checkForUpdates' not in method and 'resume]' not in method
assert 'completionHandler(nil);' in updates
assert has(updates, 'text.editable = NO;') and has(updates, 'text.selectable = YES;')
assert has(updates, 'text.scrollEnabled = YES;') and 'UIDataDetectorTypeNone' in updates
assert 'presentViewController:' not in updates
prefs_source = (settings_dir / 'SHDWPrefs.m').read_text()
symbol = block(prefs_source, 'UIImage *SHDWSettingsSymbol(')
assert anchor(symbol, 'respondsToSelector:') < anchor(symbol, '[UIImage systemImageNamed:')
assert 'UIImageRenderingModeAlwaysTemplate' in symbol
root_source = (settings_dir / 'SHDWRootListController.m').read_text()
list_source = (settings_dir / 'SHDWATLController.m').read_text()
assert 'SHDWAppIsCustomized(value)' in root_source
assert 'SHDWAppFollowsGlobal(prefs, appID)' in list_source
assert has(list_source, 'cell.accessoryView = nil;')
assert has(list_source, 'cell.accessibilityValue = nil;')
assert not has(list_source, 'cell.imageView.image =')
for path in settings_dir.glob('*.m'):
    assert '@available(' not in path.read_text(), path
print("PASS: reset confirmation, explicit-only Updates wiring, inline notes and legacy guards (static)")
PY
python3 tests/verify-settings-localization.py

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
grep -q 'shdw_detector_aggressive' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x || {
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
    pinned "$profile" "$key : @(YES)" || {
        echo "SETTINGS DRIFT: built-in profile does not enable $key"
        exit 1
    }
done

pinned "$settings" 'result[SHDWAppEnabledID] = @(enabled)' &&
! grep -q 'addEntriesFromDictionary' "$settings" &&
grep -q 'SHDWApplicationEnabled' "$loader" &&
pinned "$settings" 'bundleIdentifier.length == 0' || {
    echo 'SETTINGS DRIFT: runtime no longer uses the fixed profile with per-app activation'
    exit 1
}

pinned "$settings" 'kSHDWDetectorRunnerOverridesKey = @"Test_DetectorOverrides"' &&
grep -q 'isEqualToString:@"me.jjolano.shadow.harness"' "$settings" &&
pinned "$settings" 'SHDWAdapterDeviceCheckID, SHDWAdapterFreeRASPID' \
 'SHDWAdapterDeviceSecurityKitID, SHDWAdapterIOSSecuritySuiteID' || {
    echo 'SETTINGS DRIFT: detector overrides must remain private to test runners'
    exit 1
}

# A per-app toggle edit takes the app off "follow global" by writing an
# explicit App_Enabled and stamping the single-toggle migration marker;
# clearing it (follow global) drops the override key.
pinned src/ShadowSettings.bundle/SHDWPrefs.m 'setBool:YES forKey:SHDWSingleToggleMigrationID' &&
grep -q 'removeObjectForKey:SHDWAppEnabledID' src/ShadowSettings.bundle/SHDWPrefs.m || {
    echo 'SETTINGS DRIFT: per-app toggle must use explicit single-toggle semantics with follow-global clear'
    exit 1
}

grep -q 'SHDWAppDisabledID.*SHDWAppEnabledID' src/Shadow.framework/SettingsMigration.m ||
pinned src/Shadow.framework/SettingsMigration.m 'migrated[SHDWAppEnabledID] = @NO' || {
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
if [ -f "[private-harness-path][harness-tool].py" ]; then
grep -q 'return "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"' "[private-harness-path][harness-tool].py" &&
grep -q '^PREFS_REMOTE=/var/mobile/Library/Preferences/me.jjolano.shadow.plist$' "[private-harness-path]" || {
    echo 'SETTINGS DRIFT: device tools must edit the canonical preference file'
    exit 1
}
fi
