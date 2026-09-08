"""Check source tables and wiring; optionally compare a built .deb's resources."""
import argparse
from collections import Counter
import io
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tarfile

SETTINGS = Path(__file__).resolve().parents[1] / "src/ShadowSettings.bundle"
RESOURCES = SETTINGS / "Resources"
LANGUAGES = ("en", "ar", "zh-Hans", "zh-Hant")
TABLES = ("Root", "App", "About")


def strings(text):
    # Only the OpenStep strings-table grammar, not a general plist parser.
    token = re.compile(r'\s+|/\*.*?\*/|//[^\n]*|"(?:[^"\\]|\\.)*"|[\w.$/:-]+|[=;]', re.S)
    tokens, end = [], 0
    for match in token.finditer(text):
        assert match.start() == end, f"Invalid strings syntax at {end}"
        end = match.end()
        value = match.group()
        if not value.isspace() and not value.startswith(("/*", "//")):
            tokens.append(value)
    assert end == len(text), f"Invalid strings syntax at {end}"

    def unquote(value):
        if not value.startswith('"'):
            assert value not in ("=", ";")
            return value
        escapes = {'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', 'f': '\f',
                   '"': '"', '\\': '\\'}

        def decode(match):
            escaped = match.group()[1:]
            if escaped.startswith("U"):
                return chr(int(escaped[1:], 16))
            if escaped[0] in "01234567":
                return chr(int(escaped, 8))
            assert escaped in escapes, f"Unsupported escape: {match.group()}"
            return escapes[escaped]

        decoded = re.sub(r'\\(?:U[0-9a-fA-F]{4}|[0-7]{1,3}|.)', decode, value[1:-1])
        return decoded.encode("utf-16", "surrogatepass").decode("utf-16")

    assert len(tokens) % 4 == 0, "Incomplete strings entry"
    result = {}
    for index in range(0, len(tokens), 4):
        key, equals, value, semicolon = tokens[index:index + 4]
        assert equals == "=" and semicolon == ";", "Expected key = value;"
        key, value = unquote(key), unquote(value)
        assert key not in result, f"Duplicate key: {key}"
        assert value, f"Empty translation: {key}"
        result[key] = value
    return result


def placeholders(value):
    result, next_argument = Counter(), 1
    pattern = re.compile(r'%(?:([1-9][0-9]*)\$)?([-+ #0]*)(\d*)(?:\.(\d+))?(hh|ll|[hlLqztj])?([@diuoxXfFeEgGaAcCsSp%])')
    position = 0
    while True:
        position = value.find("%", position)
        if position == -1:
            break
        match = pattern.match(value, position)
        assert match, f"Invalid format: {value}"
        argument, _, _, _, length, conversion = match.groups()
        position = match.end()
        if conversion == "%":
            continue
        result[(int(argument) if argument else next_argument, (length or "") + conversion)] += 1
        if not argument:
            next_argument += 1
    return result


def verify():
    assert strings(r'/* test */ key = "\U95dc\U65bc \"quoted\" \\ \n";') == {
        "key": '關於 "quoted" \\ \n'}
    assert strings(r'key = "\UD83D\UDE00";')["key"] == "\U0001f600"
    assert placeholders("%1$@, %2$@") == placeholders("%2$@، %1$@")
    for invalid in ['key = "x"', 'key = "x"; key = "y";', 'key = "\\Q";', 'key = "x"; !']:
        try:
            strings(invalid)
        except (AssertionError, ValueError):
            pass
        else:
            raise AssertionError(f"Accepted invalid strings: {invalid}")

    assert (RESOURCES / "Base.lproj").is_symlink()
    assert os.readlink(RESOURCES / "Base.lproj") == "en.lproj"
    info = plistlib.loads((RESOURCES / "Info.plist").read_bytes())
    assert info["CFBundleDevelopmentRegion"] == "en"
    tables = {(language, table): strings((RESOURCES / f"{language}.lproj/{table}.strings").read_text())
              for language in LANGUAGES for table in TABLES}
    for table in TABLES:
        english = tables["en", table]
        plist = plistlib.loads((RESOURCES / f"{table}.plist").read_bytes())
        required = {item[field] for item in plist["items"] for field in ("label", "footerText", "title") if field in item}
        if plist["title"] != "Shadow":
            required.add(plist["title"])
        controllers = {"Root": ["RootList"], "App": ["AppList", "ATL"], "About": ["AboutList", "Updates"]}[table]
        for controller in controllers:
            source = (SETTINGS / f"SHDW{controller}Controller.m").read_text()
            # Includes keys in ternaries, arrays and selected-key variables, not
            # just literal localized: calls. IDs/actions use different spelling.
            required.update(re.findall(r'@"([A-Z][A-Z0-9_]+)"', source))
            lookup_tables = re.findall(r'\btable:@"([^"]+)"', source)
            assert len(lookup_tables) == source.count('localizedStringForKey:'), controller
            assert all(name == table for name in lookup_tables), controller
            if controller.endswith("List"):
                call = f'SHDWLocalizeSpecifiers(_specifiers, '
                assert source.count(call) == 1
                assert re.search(r'SHDWLocalizeSpecifiers\(_specifiers, .*?, @"' + table + r'"\);', source)
                assert source.index('loadSpecifiersFromPlistName:') < source.index(call)
        assert required <= english.keys(), (table, required - english.keys())
        for language in LANGUAGES:
            localized = tables[language, table]
            # A selected table does not inherit missing keys from English.
            assert english.keys() <= localized.keys(), (language, table, english.keys() - localized.keys())
            for key, value in localized.items():
                tokens = placeholders(value)
                if key in english:
                    assert tokens == placeholders(english[key]), (language, table, key)
            assert all(localized[key] != key for key in required), (language, table)
    app = (SETTINGS / "SHDWAppListController.m").read_text()
    about = (SETTINGS / "SHDWAboutListController.m").read_text()
    assert 'self.title = [bundle localizedStringForKey:@"APP_SETTINGS" value:nil table:@"App"]' in app
    assert app.index('self.title = [bundle') < app.index('self.title = proxy.atl_fastDisplayName')
    assert 'self.title = [self localized:@"ABOUT_TITLE"]' in about
    print("PASS: OpenStep strings syntax, all locales, static/dynamic keys, formats, explicit pane tables and titles")
    return tables


def verify_package(package, tables):
    archive = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        members = {member.name: member for member in tar.getmembers()}
        base = next(name for name in members if name.endswith("/ShadowSettings.bundle/Base.lproj"))
        assert members[base].issym() and members[base].linkname == "en.lproj"
        bundle = base[:-len("Base.lproj")]
        for (language, table), expected in tables.items():
            stream = tar.extractfile(bundle + f"{language}.lproj/{table}.strings")
            assert stream is not None
            data = stream.read()
            assert data.startswith(b"bplist00"), (language, table, "not compiled binary plist")
            assert plistlib.loads(data) == expected, (language, table, "package differs from source")
        stream = tar.extractfile(bundle + "Info.plist")
        assert stream is not None
        assert plistlib.load(stream)["CFBundleDevelopmentRegion"] == "en"
    print("PASS: package binary strings match every source key/value in all 12 tables; Base symlink preserved")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path)
    args = parser.parse_args()
    tables = verify()
    if args.package:
        verify_package(args.package, tables)
