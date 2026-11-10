"""Pin NSURL read denials to Cocoa's absent-file read code."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/ShadowCore.dylib/hooks/Universal/NSURL.x").read_text()


def method(selector: str, next_selector: str) -> str:
    start = source.index(selector)
    end = source.index(next_selector, start)
    return source[start:end]


expected = "[Shadow fileErrorWithCode:NSFileReadNoSuchFileError path:[self path] url:self]"
methods = (
    (
        "getResourceValue",
        "- (BOOL)getResourceValue:",
        "- (NSDictionary<NSURLResourceKey, id> *)resourceValuesForKeys:",
    ),
    (
        "resourceValuesForKeys",
        "- (NSDictionary<NSURLResourceKey, id> *)resourceValuesForKeys:",
        "- (BOOL)setResourceValue:",
    ),
    (
        "checkPromisedItemIsReachableAndReturnError",
        "- (BOOL)checkPromisedItemIsReachableAndReturnError:",
        "- (BOOL)getPromisedItemResourceValue:",
    ),
    (
        "getPromisedItemResourceValue",
        "- (BOOL)getPromisedItemResourceValue:",
        "- (NSDictionary<NSURLResourceKey, id> *)promisedItemResourceValuesForKeys:",
    ),
    (
        "promisedItemResourceValuesForKeys",
        "- (NSDictionary<NSURLResourceKey, id> *)promisedItemResourceValuesForKeys:",
        "- (NSURL *)fileReferenceURL",
    ),
)
for name, selector, next_selector in methods:
    body = method(selector, next_selector)
    assert body.count(expected) == 1, f"{name} must use the 260 read-error factory exactly once"
    assert "fileNoSuchFileErrorForURL:self" not in body, f"{name} must not use the generic code-4 factory"

print("verify-nsurl-values: NSURL resource and promised-item readers use NSFileReadNoSuchFileError (260)")
