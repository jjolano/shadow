"""Contract for the JB-identifier codegen: build-support/jb-identifiers.plist ->
scripts/gen-jb-identifiers.py -> generated C arrays consumed by AppEnvironment.x.

Pure-host: renders its own header (no Theos), compiles the arrays with the host
cc, reads the strings back, and checks the generator rejects bad input and that
AppEnvironment.x actually consumes the generated symbols with the original match
semantics. No device, no Foundation.
"""
import os
import plistlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
gen = root / "scripts/gen-jb-identifiers.py"
plist = root / "build-support/jb-identifiers.plist"
appenv = (root / "src/ShadowCore.dylib/hooks/Universal/AppEnvironment.x").read_text()

CC = os.environ.get("CC", "cc")
SYMBOLS = {
    "NSUserDefaultsSuites": "shdw_jb_nsuserdefaults_suites",
    "JBPreferenceDomainIDs": "shdw_jb_preference_domain_ids",
}


def run_gen(src, out, expect_ok=True):
    result = subprocess.run(
        [sys.executable, str(gen), str(src), str(out)],
        capture_output=True, text=True,
    )
    if expect_ok:
        assert result.returncode == 0, "gen failed: %s" % result.stderr
    else:
        assert result.returncode != 0, "gen should have failed on %s" % src
    return result


def write_plist(tmp, data, name="in.plist"):
    path = Path(tmp) / name
    with open(path, "wb") as handle:
        plistlib.dump(data, handle)
    return path


def read_back_arrays(header_path):
    """Compile the generated header and print each array element so we verify
    the C the compiler actually sees, not just the generator's text output."""
    with tempfile.TemporaryDirectory() as tmp:
        driver = Path(tmp) / "driver.c"
        driver.write_text(
            '#include <stdio.h>\n'
            '#include "%s"\n'
            "int main(void){\n"
            "  for(const char* const* p = %s; *p; p++) printf(\"S:%%s\\n\", *p);\n"
            "  for(const char* const* p = %s; *p; p++) printf(\"P:%%s\\n\", *p);\n"
            "  return 0;\n}\n"
            % (header_path, SYMBOLS["NSUserDefaultsSuites"],
               SYMBOLS["JBPreferenceDomainIDs"])
        )
        binx = Path(tmp) / "driver"
        subprocess.run([CC, "-std=c99", "-Wall", "-Wextra", "-o", str(binx),
                        str(driver)], check=True, capture_output=True, text=True)
        out = subprocess.run([str(binx)], check=True, capture_output=True,
                             text=True).stdout
    suites = [l[2:] for l in out.splitlines() if l.startswith("S:")]
    prefs = [l[2:] for l in out.splitlines() if l.startswith("P:")]
    return suites, prefs


# --- 1. real plist renders, compiles, and round-trips its values exactly ------
data = plistlib.loads(plist.read_bytes())
for category in SYMBOLS:
    assert category in data, "plist missing category %s" % category

with tempfile.TemporaryDirectory() as tmp:
    header = Path(tmp) / "jb-identifiers.h"
    run_gen(plist, header)
    first = header.read_text()
    first_mtime = header.stat().st_mtime_ns

    # Determinism + no-rewrite on identical input.
    run_gen(plist, header)
    assert header.read_text() == first, "generator output is non-deterministic"
    assert header.stat().st_mtime_ns == first_mtime, "unchanged output was rewritten"

    suites, prefs = read_back_arrays(header)
    assert suites == data["NSUserDefaultsSuites"], (suites, data["NSUserDefaultsSuites"])
    assert prefs == data["JBPreferenceDomainIDs"], (prefs, data["JBPreferenceDomainIDs"])

    # Count macros agree with the arrays.
    assert "#define %s_count %d" % (SYMBOLS["NSUserDefaultsSuites"], len(suites)) in first
    assert "#define %s_count %d" % (SYMBOLS["JBPreferenceDomainIDs"], len(prefs)) in first

# --- 2. invalid inputs fail (no stale/partial output) -------------------------
with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp) / "out.h"
    run_gen(write_plist(tmp, {"NSUserDefaultsSuites": ["a"]}), out, expect_ok=False)  # missing category
    run_gen(write_plist(tmp, {"NSUserDefaultsSuites": [], "JBPreferenceDomainIDs": [],
                              "Bogus": []}), out, expect_ok=False)  # unknown category
    run_gen(write_plist(tmp, {"NSUserDefaultsSuites": ["dup", "dup"],
                              "JBPreferenceDomainIDs": []}), out, expect_ok=False)  # duplicate
    run_gen(write_plist(tmp, {"NSUserDefaultsSuites": [""],
                              "JBPreferenceDomainIDs": []}), out, expect_ok=False)  # empty entry
    run_gen(write_plist(tmp, {"NSUserDefaultsSuites": [123],
                              "JBPreferenceDomainIDs": []}), out, expect_ok=False)  # non-string
    run_gen(write_plist(tmp, {"NSUserDefaultsSuites": "notarray",
                              "JBPreferenceDomainIDs": []}), out, expect_ok=False)  # not a list
    bad = Path(tmp) / "bad.plist"
    bad.write_text("not a plist at all")
    run_gen(bad, out, expect_ok=False)

# --- 3. escaping: quotes, backslashes, and non-ASCII survive to the compiler --
with tempfile.TemporaryDirectory() as tmp:
    tricky = ['a"b', "c\\d", "caf\u00e9.app", "caf\u00e9face", "com.normal.id"]
    src = write_plist(tmp, {"NSUserDefaultsSuites": tricky,
                            "JBPreferenceDomainIDs": ["x.y"]})
    header = Path(tmp) / "jb-identifiers.h"
    run_gen(src, header)
    suites, prefs = read_back_arrays(header)
    assert suites == tricky, (suites, tricky)
    assert prefs == ["x.y"]

# --- 4. AppEnvironment.x consumes the generated symbols, semantics preserved --
assert '#import "jb-identifiers.h"' in appenv, "AppEnvironment.x must include the generated header"
# No inline literals left behind (the values now live only in the plist).
for value in data["NSUserDefaultsSuites"] + data["JBPreferenceDomainIDs"]:
    assert ('@"%s"' % value) not in appenv, "stale inline literal %r in AppEnvironment.x" % value
# Match semantics: exact-set for suites, leaf exact-match for pref domains.
assert re.search(r"for\(const char\* const\* p = %s; \*p; p\+\+\)" % SYMBOLS["NSUserDefaultsSuites"], appenv)
assert re.search(r"for\(const char\* const\* p = %s; \*p; p\+\+\)" % SYMBOLS["JBPreferenceDomainIDs"], appenv)
assert "[restrictedSuites containsObject:suitename]" in appenv
assert "suitename.lastPathComponent" in appenv
assert "[leaf isEqualToString:pref]" in appenv

print("verify-jb-identifiers: codegen determinism, validation, escaping, and consumer wiring passed")
