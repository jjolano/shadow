# Public tests: pure-C checks + static contract scripts only. The full
# engine-linked harness (detector/adversary/fuzz/device batteries) lives
# in the private repo; see tests/README.md.

# Pure-C check for the svc path-munging logic (path_rewrite.c — no
# Foundation, so it compiles and runs on any host, macOS or Linux).
verify-path-rewrite:
	$(CC) -std=c99 -Wall -Wextra -o /tmp/shadow-rewrite-test \
		verify-path-rewrite.c ../src/ShadowCore.dylib/hooks/Universal/path_rewrite.c
	/tmp/shadow-rewrite-test

# Host check of the actual fstatat/faccessat hook bodies with policy doubles.
verify-at-path-rewrite:
	python3 verify-at-path-rewrite.py

# Host check of the actual raw-SVC add-image callback and initializer bodies.
verify-svc-self-image:
	python3 verify-svc-self-image.py

# Pure-C record filter and static snapshot-query contract.
verify-mount-filter:
	$(CC) -std=c99 -Wall -Wextra -o /tmp/shadow-mount-filter-test \
		verify-mount-filter.c
	/tmp/shadow-mount-filter-test
	python3 verify-mount-query.py

# Pure-C check for the anti-fishhook journal/repair core (rebind_slots.h).
verify-rebind-repair:
	$(CC) -std=c99 -Wall -Wextra -o /tmp/shadow-rebind-test \
		verify-rebind-repair.c
	/tmp/shadow-rebind-test

# Device-driver logic selftests live in the private harness repo (pure-logic,
# no device); public CI does not run them. Local run with a sibling checkout:
#   python3 ../../shadow-private/harness-tests/stealth_device.py selftest
verify-device-driver:
	@echo "verify-device-driver: private harness only (see above); skipping"

# HookKit headers for the harness come from the Theos install (HookKit repo:
# make install-theos), staged into vendor/ (gitignored, arch-independent) since
# neither this harness nor the container carries Theos. build.sh no longer
# stages them, so the harness provisions its own.
THEOS ?= /opt/theos
HOOKKIT_HEADERS ?= $(THEOS)/lib/HookKit.framework/Headers

stage-hookkit-headers:
	@test -d "$(HOOKKIT_HEADERS)" || { echo "no HookKit headers at $(HOOKKIT_HEADERS) — set HOOKKIT_HEADERS or run 'make install-theos' in the HookKit repo" >&2; exit 1; }
	rm -rf ../vendor/HookKit.framework/Headers
	mkdir -p ../vendor/HookKit.framework
	cp -R "$(HOOKKIT_HEADERS)" ../vendor/HookKit.framework/Headers

# Static contract checks (CWD-agnostic: every script cds to the repo root).
lane-contract:
	sh verify-lane-contract.sh

hook-matrix:
	sh verify-hook-matrix.sh

syscall-meta:
	sh verify-syscall-meta.sh

settings-structure:
	sh verify-settings-structure.sh

# JB-identifier codegen contract: renders its own header (no Theos), compiles
# the generated arrays with the host cc, and checks generator validation +
# AppEnvironment.x consumer wiring.
jb-identifiers:
	python3 verify-jb-identifiers.py

verify-environment-storage:
	python3 verify-environment-storage.py

test: verify-path-rewrite verify-at-path-rewrite verify-svc-self-image verify-mount-filter verify-rebind-repair verify-device-driver lane-contract hook-matrix syscall-meta settings-structure jb-identifiers verify-environment-storage

clean:
	rm -f harness harness.d

.PHONY: test verify-path-rewrite verify-at-path-rewrite verify-svc-self-image verify-mount-filter verify-rebind-repair verify-device-driver lane-contract hook-matrix syscall-meta settings-structure jb-identifiers verify-environment-storage stage-hookkit-headers clean
