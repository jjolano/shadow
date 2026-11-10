# Public tests: pure-C checks + static contract scripts only. The full
# engine-linked harness (detector/adversary/fuzz/device batteries) lives
# in the private repo; see tests/README.md.

# Pure-C check for the svc path-munging logic (path_rewrite.c — no
# Foundation, so it compiles and runs on any host, macOS or Linux).
verify-path-rewrite:
	$(CC) -std=c99 -Wall -Wextra -o /tmp/shadow-rewrite-test \
		verify-path-rewrite.c ../src/ShadowCore.dylib/hooks/Universal/path_rewrite.c
	/tmp/shadow-rewrite-test

# Host check for staged realpath output: denied resolutions never reach the
# caller buffer, while approved strings are copied completely and bounded.
verify-realpath-buffer:
	$(CC) -std=c99 -Wall -Wextra -o /tmp/shadow-realpath-buffer-test \
		verify-realpath-buffer.c ../src/ShadowCore.dylib/hooks/Universal/path_rewrite.c
	/tmp/shadow-realpath-buffer-test

# Host check of the actual fstatat/faccessat hook bodies with policy doubles.
verify-at-path-rewrite:
	python3 verify-at-path-rewrite.py

# Host check of the real chflags/lchflags/fchflags hook bodies with policy doubles.
verify-chflags:
	python3 verify-chflags.py

# Pin path-string directory-listing denials to Cocoa's absent-file read error.
verify-foundation-fm-listing:
	python3 verify-foundation-fm-listing.py

# Pin both Foundation filesystem-attribute denials to Cocoa's absent-file error.
verify-foundation-fsattrs:
	python3 verify-foundation-fsattrs.py

# Pin both NSURL resource-value read denials to Cocoa's absent-file read code.
verify-nsurl-values:
	python3 verify-nsurl-values.py

# Host check of the actual lexical path standardizer with pinned spellings.
verify-path-standardize:
	python3 verify-path-standardize.py

# Host check of the actual fresh fd/DIR path-policy bodies with mutation doubles.
verify-fd-path-freshness:
	python3 verify-fd-path-freshness.py

# Host check of the actual process-policy bodies (classification caches, pid
# list compaction, MIB classifier, boot-args answer) with kinfo doubles.
verify-proc-policy:
	python3 verify-proc-policy.py

# Host check of the actual raw-SVC add-image callback and initializer bodies.
verify-svc-self-image:
	python3 verify-svc-self-image.py

# Host check of the actual accessx_np/SYS_access_extended batch filter with
# predicate doubles and kernel-shaped descriptor buffers.
verify-accessx-filter:
	python3 verify-accessx-filter.py

# Pure-C mount-record filter.
verify-mount-filter:
	$(CC) -std=c99 -Wall -Wextra -o /tmp/shadow-mount-filter-test \
		verify-mount-filter.c
	/tmp/shadow-mount-filter-test

# Host check of the restricted-image span and svc branch-encoding decisions:
# extracts the real bodies (and their constants) from the hook sources and
# drives them with synthetic Mach-O images.
verify-image-span:
	python3 verify-image-span.py

# Host check of the actual KERN_PROCARGS2 payload filter, driven with payloads
# in the kernel's documented string layout (and with the pointer-array shape it
# must never trust again).
verify-procargs-filter:
	python3 verify-procargs-filter.py

# Pure-C check for the anti-fishhook journal/repair core (rebind_slots.h).
verify-rebind-repair:
	$(CC) -std=c99 -Wall -Wextra -pthread -o /tmp/shadow-rebind-test \
		verify-rebind-repair.c
	/tmp/shadow-rebind-test

THEOS ?= /opt/theos
# Host regression pin for copy-source backing aliases and denial shape.
verify-copy-source-policy:
	python3 verify-copy-source-policy.py

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

verify-plugin-table:
	python3 verify-plugin-table.py

verify-binary-compat:
	bash BinaryCompatTests.sh

# The matrix's own stale-entry detector must fail on a deliberate drift entry.
hook-matrix-selftest:
	@if sh verify-hook-matrix.sh --selftest-drift >/tmp/shadow-matrix-selftest.log 2>&1; then \
		echo 'MATRIX SELFTEST: stale entry was not detected'; exit 1; \
	fi
	@grep -q 'MATRIX STALE' /tmp/shadow-matrix-selftest.log || { \
		echo 'MATRIX SELFTEST: failure was not the stale-entry path'; exit 1; }

test: verify-realpath-buffer verify-path-rewrite verify-at-path-rewrite verify-chflags verify-foundation-fsattrs verify-foundation-fm-listing verify-nsurl-values verify-path-standardize verify-fd-path-freshness verify-proc-policy verify-svc-self-image verify-accessx-filter verify-image-span verify-mount-filter verify-rebind-repair verify-procargs-filter verify-copy-source-policy lane-contract hook-matrix hook-matrix-selftest syscall-meta settings-structure jb-identifiers verify-environment-storage verify-rules-generation verify-plugin-table verify-binary-compat

clean:
	rm -f harness harness.d
.PHONY: test verify-realpath-buffer verify-path-rewrite verify-at-path-rewrite verify-chflags verify-foundation-fsattrs verify-foundation-fm-listing verify-nsurl-values verify-path-standardize verify-fd-path-freshness verify-proc-policy verify-svc-self-image verify-accessx-filter verify-image-span verify-procargs-filter verify-mount-filter verify-rebind-repair verify-procargs-filter verify-copy-source-policy lane-contract hook-matrix hook-matrix-selftest syscall-meta settings-structure jb-identifiers verify-environment-storage verify-rules-generation verify-plugin-table verify-binary-compat clean

