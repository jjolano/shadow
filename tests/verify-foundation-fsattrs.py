"""Pin the Foundation filesystem-attributes denial to Cocoa's absent-file code."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/ShadowCore.dylib/hooks/Universal/NSFileManager.x").read_text()


def method(selector: str, next_selector: str) -> str:
    start = source.index(selector)
    end = source.index(next_selector, start)
    return source[start:end]


filesystem_attrs = method(
    "- (NSDictionary<NSFileAttributeKey, id> *)attributesOfFileSystemForPath:",
    "- (BOOL)getRelationship:",
)
expected_error = "[Shadow fileErrorWithCode:NSFileReadNoSuchFileError path:path url:nil]"
assert filesystem_attrs.count(expected_error) == 2
assert "fileNoSuchFileErrorForPath:" not in filesystem_attrs
assert "shdw_path_is_external_hidden(cpath)" in filesystem_attrs
assert "[_shadow isPathRestricted:path" in filesystem_attrs
assert "shdw_path_is_main_bundle_exempt(cpath)" in filesystem_attrs

legacy_attrs = method(
    "- (NSDictionary *)fileSystemAttributesAtPath:",
    "- (NSArray *)directoryContentsAtPath:",
)
assert "NSError" not in legacy_attrs
assert "return nil;" in legacy_attrs

utilities = (ROOT / "src/Shadow.framework/Core+Utilities.m").read_text()
error_helper = utilities[
    utilities.index("+ (NSError *)fileErrorWithCode:"):
    utilities.index("+ (NSError *)fileNoSuchFileErrorForPath:")
]
assert "errorWithDomain:NSCocoaErrorDomain" in error_helper
assert "code:code" in error_helper
assert "NSFileReadNoSuchFileError" in source
print("verify-foundation-fsattrs: both denial branches use Cocoa NSFileReadNoSuchFileError (260)")
