"""Pin NSFileManager path listing denial to Cocoa's absent-file read shape."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/ShadowCore.dylib/hooks/Universal/NSFileManager.x").read_text()
utilities = (ROOT / "src/Shadow.framework/Core+Utilities.m").read_text()

start = source.index("- (NSArray<NSString *> *)contentsOfDirectoryAtPath:")
end = source.index("- (NSDirectoryEnumerator<NSURL *> *)enumeratorAtURL:", start)
listing = source[start:end]
assert "if(!isCallerExternal())" in listing
assert "shdw_foundation_path_denied(self, path," in listing
assert "[Shadow fileErrorWithCode:NSFileReadNoSuchFileError path:path url:nil]" in listing
assert "return nil;" in listing
assert "fileNoSuchFileErrorForPath:path" not in listing

policy_start = source.index("static BOOL shdw_foundation_path_denied(")
policy_end = source.index("static BOOL shdw_foundation_url_denied(", policy_start)
policy = source[policy_start:policy_end]
assert "shdw_path_is_main_bundle_exempt(cpath)" in policy
assert "shdw_path_is_external_hidden(cpath)" in policy
assert "[_shadow isPathRestricted:path options:policyOptions]" in policy

factory_start = utilities.index("+ (NSError *)fileErrorWithCode:")
factory_end = utilities.index("+ (NSError *)fileNoSuchFileErrorForPath:", factory_start)
factory = utilities[factory_start:factory_end]
assert "errorWithDomain:NSCocoaErrorDomain" in factory
assert "code:code" in factory
assert "NSFilePathErrorKey" in factory
assert "NSFileReadNoSuchFileError" in source

print("verify-foundation-fm-listing: external-hidden listing denial uses Cocoa NSFileReadNoSuchFileError (260) with path userInfo")
