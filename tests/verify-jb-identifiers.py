"""Compile the identifier arrays and check their data and consumer wiring."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
header = root / "src/ShadowCore.dylib/hooks/Universal/jb-identifiers.h"
appenv = header.with_name("AppEnvironment.x").read_text()
symbols = ("shdw_jb_nsuserdefaults_suites", "shdw_jb_preference_domain_ids")


def anchor_pattern(needle):
    """Regex for `needle`, tolerant of reformat spacing."""
    return r"\s*".join(
        re.escape(tok) for tok in re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", needle)
    )


def has(text, needle):
    """True when `needle` occurs in `text`, tolerant of reformat spacing."""
    return re.search(anchor_pattern(needle), text) is not None


source = '#include <stdio.h>\n#include <assert.h>\n#include "%s"\nint main(void) {\n' % header
for prefix, symbol in zip(("S:", "P:"), symbols):
    source += """
    assert(%(symbol)s[sizeof(%(symbol)s) / sizeof(%(symbol)s[0]) - 1] == NULL);
    for(size_t i = 0; i + 1 < sizeof(%(symbol)s) / sizeof(%(symbol)s[0]); i++) {
        assert(%(symbol)s[i] && %(symbol)s[i][0]);
        printf("%(prefix)s%%s\\n", %(symbol)s[i]);
    }
""" % {"symbol": symbol, "prefix": prefix}
source += "return 0; }\n"
with tempfile.TemporaryDirectory() as tmp:
    driver, binary = Path(tmp) / "driver.c", Path(tmp) / "driver"
    driver.write_text(source)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c99", "-Wall", "-Wextra",
                    "-Werror", str(driver), "-o", str(binary)], check=True)
    output = subprocess.check_output([str(binary)])
assert hashlib.sha256(output).hexdigest() == "6c5d2b391886540703dcbc607858cdaa0028018112074514ed7779bbc9254e28", "identifier data changed"
assert has(appenv, '#import "jb-identifiers.h"')
for symbol in symbols:
    assert has(appenv, 'for(const char* const* p = %s; *p; p++)' % symbol), symbol
assert has(appenv, "[restrictedSuites containsObject:suitename]")
assert has(appenv, "suitename.lastPathComponent")
assert has(appenv, "[leaf isEqualToString:pref]")
print("verify-jb-identifiers: compiled data and consumer wiring passed")
