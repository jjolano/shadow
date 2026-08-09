#!/usr/bin/env bash
# Release export check: every built binary must export exactly its allowlist —
# nothing more, nothing less — per arch slice. Run via `make check-exports`,
# or pass binary paths as arguments (auto-discovers under .theos otherwise).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Mach-O-aware nm: GNU binutils nm cannot read Mach-O files.
NM=""
for cand in "$(command -v llvm-nm 2>/dev/null)" \
            "$(ls ~/.local/share/mise/installs/swift/*/usr/bin/llvm-nm 2>/dev/null | tail -n 1)" \
            "$(command -v nm 2>/dev/null)"; do
	[ -n "$cand" ] && [ -x "$cand" ] && { NM="$cand"; break; }
done
if [ -z "$NM" ]; then
	echo "error: no Mach-O-aware nm found (looked for llvm-nm, nm)" >&2
	exit 1
fi

ALLOW_HOOKKIT="$ROOT/scripts/export-HookKit.list"
ALLOW_HKGUM="$ROOT/scripts/export-HKGum.list"
ARCHS="arm64 arm64e armv7 armv7s"

status=0
checked=0

check_binary() {
	local bin="$1" allow="$2"
	if [ ! -f "$bin" ]; then
		echo "error: $bin not found (run make first)" >&2
		status=1
		return
	fi
	local arch out exports missing extra narch=0
	for arch in $ARCHS; do
		out="$("$NM" -gU -arch "$arch" "$bin" 2>/dev/null)" || continue
		[ -n "$out" ] || continue
		narch=$((narch + 1))
		exports="$(printf '%s\n' "$out" | sed '/^$/d' | awk '{print $NF}' | sort -u)"
		missing="$(comm -23 <(sort -u "$allow") <(printf '%s\n' "$exports"))"
		extra="$(comm -13 <(sort -u "$allow") <(printf '%s\n' "$exports"))"
		if [ -n "$missing$extra" ]; then
			status=1
			echo "FAIL $bin [$arch]"
			[ -n "$missing" ] && printf '  allowlisted but not exported:\n%s\n' \
				"$(printf '%s\n' "$missing" | sed 's/^/    /')"
			[ -n "$extra" ] && printf '  exported but not allowlisted:\n%s\n' \
				"$(printf '%s\n' "$extra" | sed 's/^/    /')"
		else
			checked=$((checked + 1))
			echo "PASS $bin [$arch] ($(printf '%s' "$exports" | tr '\n' ' '))"
		fi
	done
	if [ "$narch" -eq 0 ]; then
		echo "error: no known slices found in $bin" >&2
		status=1
	fi
}

if [ "$#" -gt 0 ]; then
	bins=("$@")
else
	bins=(
		$(find .theos -path "*HookKit.framework/HookKit" -type f 2>/dev/null)
		$(find .theos -name "HKGum.dylib" -type f 2>/dev/null)
	)
fi

if [ "${#bins[@]}" -eq 0 ]; then
	echo "error: no built binaries found under .theos (run make first)" >&2
	exit 1
fi

for bin in "${bins[@]}"; do
	case "$bin" in
		*HKGum.dylib) check_binary "$bin" "$ALLOW_HKGUM" ;;
		*) check_binary "$bin" "$ALLOW_HOOKKIT" ;;
	esac
done

if [ "$status" -eq 0 ]; then
	echo "OK: $checked slice(s) export exactly their allowlist"
else
	echo "FAIL: export check did not pass" >&2
fi
exit "$status"