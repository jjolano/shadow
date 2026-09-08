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

# Host check of the actual fresh fd/DIR path-policy bodies with mutation doubles.
verify-fd-path-freshness:
	python3 verify-fd-path-freshness.py

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

THEOS ?= /opt/theos

# Static contract checks (CWD-agnostic: every script cds to the repo root).
lane-contract:
	sh verify-lane-contract.sh

hook-matrix:
	sh verify-hook-matrix.sh

syscall-meta:
	sh verify-syscall-meta.sh

settings-structure:
	sh verify-settings-structure.sh

# Optional Foundation check; not a dependency of the portable host suite.
settings-behavior:
	python3 verify-settings-behavior.py $(if $(GNUSTEP_IMAGE),--docker $(GNUSTEP_IMAGE),)

.PHONY: settings-behavior

# Compile the identifier arrays and check their data and consumer wiring.
jb-identifiers:
	python3 verify-jb-identifiers.py

verify-environment-storage:
	python3 verify-environment-storage.py

verify-rules-generation:
	python3 verify-rules-generation.py

verify-binary-compat:
	bash BinaryCompatTests.sh

test: verify-path-rewrite verify-at-path-rewrite verify-fd-path-freshness verify-svc-self-image verify-mount-filter verify-rebind-repair lane-contract hook-matrix syscall-meta settings-structure jb-identifiers verify-environment-storage verify-rules-generation verify-binary-compat

clean:
	rm -f harness harness.d

.PHONY: test verify-path-rewrite verify-at-path-rewrite verify-fd-path-freshness verify-svc-self-image verify-mount-filter verify-rebind-repair lane-contract hook-matrix syscall-meta settings-structure jb-identifiers verify-environment-storage verify-rules-generation verify-binary-compat clean
