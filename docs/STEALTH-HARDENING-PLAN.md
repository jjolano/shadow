# Shadow stealth hardening execution plan

This is the execution contract for the remaining stealth work. It supersedes
the verification claims in `docs/v5-PLAN.md`; `docs/HOOK-FIX-PLAN.md` remains
implementation history and the source of the regression ledger below.

The executor changes one task at a time, preserves unrelated worktree edits,
uses the literal repository paths and commands below, and stores raw evidence
under the one run root named by `SHADOW_EVIDENCE_ROOT`. A STOP outcome is a
correct completed result when a gate says STOP is allowed.

## Execution checkpoint — 2026-08-15

- TOOL-01/TOOL-02 and the ORA-01 evidence plumbing are implemented and their
  host self-tests pass.
- ORA-02 is device-complete in run `20260815T113107Z-ora02-final`. Both lock
  states were authoritatively `0`; lock state was never the blocker. The
  SpringBoard path produced an `ActivePrewarm=1` process that did not enter
  `main`, so automated cold verification now runs the signed producer directly
  as `mobile` with its real container environment and an exact headless argv
  flag. Stdin/stdout/stderr are detached, the producer writes before UIKit,
  then remains alive until exact-PID cleanup. Uninjected validated as
  `CONTROL-INACTIVE`; injected validated `PASS` with
  `shadow_core_loaded=true`; forced `exists /var/jb` produced aggregate
  `FAIL`/exit `1`; the fresh recovery nonce returned it to `PASS`. The injected
  CFPrefs recursive-lock crash was fixed by removing synchronous detector-log
  preferences I/O. The final restore manifest passed exact package, component,
  preferences, context, report, process, and daemon inventory checks.
- ORA-03 is device-complete in run `20260815T133350Z-dyld-public`. The real
  `TASK_DYLD_INFO` struct was writable, but dyld republished its real arrays
  after add-image callbacks. Shadow now re-applies the filtered mirror from
  dyld's post-publication debugger-notification path using the existing native
  backend, and uses the existing litehook import-slot backend for public dyld
  APIs that fishhook only installed partially on this iOS 15 row. Uninjected
  validated as `CONTROL-INACTIVE`; injected validated `PASS` with matching
  273-image public/direct views, no protected images, and an ENOENT `/var/jb`
  canary. Both reports share revision `ad21b66851dfe9865521bec51ba0cc626d02d1e30f66f08c76ba6bc64b8c2057`;
  both validators and the exact restore passed.
- Next execution is ORA-04's timing/oracle gate.

## Goal and claims boundary

Shadow should make a supported target process match stock observations on
declared detection surfaces without changing unrelated processes or jailbreak
services.

Supported work in this plan:

- userspace filesystem, URL, process, environment, Mach, dyld, and Objective-C
  hooks;
- truthful stock/uninjected/injected probes and deterministic activation;
- repair, direct device evaluation, and removal of the global VISSHADOW
  backend;
- capability research for a future process-aware kernel provider.

No release claim may cover hostile kernel-memory inspection, server-side
attestation, a separate privileged observer, raw kernel lookup, or raw
directory enumeration unless its named provider and device row pass the
corresponding gate. Do not add handwritten kernel hooks, patchfinder offsets,
syscall-table patches, shared vnode-op patches, dependencies, a permanent
administrative interface, or another orchestration framework.

## Original six items, preserved

| Original item | Task coverage |
|---|---|
| 1. Make the harness truthful | TOOL-01, TOOL-02, ORA-01 through ORA-04 |
| 2. Make hook activation deterministic | ACT-01, ACT-02 |
| 3. Close observed filesystem and URL-scheme gaps | HOOK-01, HOOK-02, HOOK-04; ACT-01, ACT-02 |
| 4. Harden caller provenance and dyld consistency | ID-01, ID-02; DYLD-01, DYLD-02 |
| 5. Remove detector-triggered timing and persistence fingerprints | ACT-01, ACT-02, REL-02 |
| 6. Remove or fix claimed vnode hiding | VNODE-01 through VNODE-04, including VNODE-03L; CAP-01 |

## Non-negotiable safety rules

1. Never SSH as `root`. All connections use the configured mobile endpoint.
   Privileged actions run only inside `tests/stealth-device.sh` through checked
   non-interactive stdin to `sudo -S -p ''`; the password is never printed,
   placed in argv, or copied into evidence.
2. Never SIGKILL `shadowd`. Active-resource daemon SIGKILL is prohibited on
   ordinary devices. The zero-resource daemon lifecycle case uses clean
   `launchctl bootout`, never a raw signal or ambiguous process match.
3. Before any graceful daemon shutdown, prove no client owner is alive, the
   ledger is absent or empty, the latest run logs record every release, and
   every allowlisted control path is visible. Ambiguity is STOP.
4. Bind every client signal to the exact PID and captured start identity.
   Refuse PID reuse, an ambiguous match, or a stale identity.
5. A failed install or restore is not evidence. Preserve the last known
   package, preferences, logs, ledger, and exact rollback artifact until the
   device is restored or the row is marked STOP.
6. Raw producer reports own observations. Driver manifests own transport and
   artifacts. A stale report, mismatched nonce, or mismatched probe revision
   is invalid even when its observations look correct.
7. Stock mode is invalid on a jailbroken device. Missing stock hardware blocks
   release validation, not implementation completion.
8. Optional active daemon-crash or jetsam recovery belongs only on explicitly
   disposable hardware with an independent recovery anchor. It is outside the
   release gate and records `NOT-RUN` otherwise.

## Known device row

Facts observed read-only on 2026-08-13. Re-check them with `preflight` and
`inventory`; current container UUIDs and hashes are evidence, not constants.

| Field | Known value / contract |
|---|---|
| Row ID | `iphone9,3-ios15.8.3-dopamine-rootless` |
| Endpoint | `mobile@10.0.1.160`; set it explicitly in `SHADOW_DEVICE` |
| Test credential | `SHADOW_DEVICE_PASSWORD` is required; `alpine` is the current test-rig example |
| Hardware | iPhone9,3; A10; arm64 |
| OS | iOS 15.8.3, build 19H386 |
| Jailbreak | Dopamine rootless; jailbreak root `/var/jb` |
| SSH options | `StrictHostKeyChecking=no`, `IdentitiesOnly=yes`, `PreferredAuthentications=password`, `PubkeyAuthentication=no` |
| Privilege context | Root login refusal was observed before this plan; it is contextual evidence only and is never retried. `sudo -n` was denied; password on stdin to `sudo -S -p ''` succeeded. |
| Present tools | `uiopen`, `sbdidlaunch`, `uicache`, `ldid`, `dpkg`, `dpkg-query`, `plutil`, `launchctl`, `sha256sum`, `find`, `grep`, `tr`, `head`, `tail`, `cut`, `sed`, `sort`, `xargs`, `ps` |
| `plutil` syntax | Procursus: `plutil -key KEY FILE`; do not assume macOS subcommands |
| Absent tools | `appinst`, TrollStore/`installipa` helpers, `awk`, `pgrep`, `sysctl` |
| Packages | `me.jjolano.shadow` 4.0.0; harness 1.0.0-10+debug; dyldprobe 1.0.0 |
| Rootless bundles | `/var/jb/Applications/ShadowHarness.app`; `/var/jb/Applications/dyldprobe.app` |
| Bundle IDs | `me.jjolano.shadow.harness`; `me.jjolano.dyldprobe` |
| Data containers | Discover by scanning `/var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist` and reading `MCMMetadataIdentifier`; require exactly one match |
| Daemon | root process under `system/me.jjolano.shadow` |
| Current daemon evidence | Client connection dies immediately after acquire; daemon then releases all allowlisted resources; ledger absent. This supports an XPC-reply correlation defect but does not prove VISSHADOW lookup behavior. |
| Installed baseline hash prefixes | shadowd `ebc0db...`; ShadowCore `42e789...`; harness `8267e9...`; dyldprobe `b3b22f...` |

The installed hash prefixes above identify only the observed baseline. Never
accept them as candidate hashes.

## Evidence and tool contract

### Required run identity and evidence layout

Set and export this named environment once per run. The password is never
printed, copied into argv, written to a command file, or included in evidence.

```sh
export SHADOW_RUN_ID=20260813T120000Z-a1b2c3
export SHADOW_EVIDENCE_ROOT="artifacts/stealth/$SHADOW_RUN_ID"
export SHADOW_ROW_ID=iphone9,3-ios15.8.3-dopamine-rootless
export SHADOW_DEVICE=mobile@10.0.1.160
export SHADOW_DEVICE_PASSWORD=REDACTED
export SHADOW_TASK_ID=TOOL-01
rtk bash tests/stealth-device.sh preflight
```

The first five variables are immutable run identity. `SHADOW_TASK_ID` is a
required per-task routing value: set it to the literal current task ID before
that task's first driver call, and do not change it until the task completes.
It is recorded in every manifest but not in `run.json`. The driver rejects an
unknown task ID, a device whose SSH user is
not exactly `mobile`, an evidence root not exactly
`artifacts/stealth/$SHADOW_RUN_ID`, or a later device invocation whose run ID,
primary row ID, endpoint, row type, device facts, or driver revision differs
from `run.json`. `import-stock` is the sole row exception: it may register the
operator-supplied stock row under the same run/revision without changing the
primary row. The driver never attempts a root login.

`preflight` creates the run directory exclusively and writes the immutable
run anchor plus the durable cleanup journal before any mutation:

- `run.json`: run ID, primary row ID/type (`stock` or `jailbroken`), evidence
  root, primary endpoint, source, jailbreak name/version or `none`, OS
  version, build, architecture, SHA-256 `driver_revision`, and creation time;
- `host/<task>/task.json`: immutable task ID, run ID, and `probe_revision`.
  The first command for a task creates it from the current repository bytes;
  every later command for that task must match it. Different tasks may have
  different revisions because implementation changes are the purpose of the
  run;
- `cleanup.jsonl`: append-only write-ahead log. Before every device mutation,
  append and fsync `{event_id,action,target,prior_state,state:"pending"}`;
  after it, append and fsync the same event as `completed`; after verified
  restoration, append and fsync it as `restored`. Never rewrite prior lines.

If `run.json` exists, `preflight` verifies its bytes and ownership instead of
replacing it. Every later evidence-producing command verifies the run anchor,
current source/driver revision, current task anchor, and journal ownership.
`restore` must remain available after source or driver drift: it validates the
immutable run/row/endpoint fields, loads the frozen task revision from the
existing task anchor, and uses it only to replay that run's journal. It replays
pending or completed-but-not-restored events in reverse order, idempotently
appends `restored` records, fsyncs each append, then inventories and verifies
exact package/preferences/service/file state. Cross-run or cross-row artifacts
are rejected first; revision drift still blocks all new evidence.

```text
artifacts/stealth/$SHADOW_RUN_ID/
  run.json
  cleanup.jsonl
  scopes/<scope-id>.json
  host/<task>/task.json
  device/<row>/<task>/<nonce>/
  decisions/<gate>.json
  completion.md
```

Each command writes stdout and stderr to separate files before it atomically
writes its JSON manifest. `collect` verifies that every path stays inside the
run root, every artifact exists, every hash matches, and every artifact owns
the same run ID, row ID, nonce where applicable, and its task anchor's probe
revision.

### Repository path resolution and verification commands

Every task below names a literal current repository path. When an applicable
hook is not named literally, execute the task's printed `rtk rg --files ...`
discovery command and require exactly one match before editing. Zero or
multiple matches are STOP; unresolved labels are not executable paths.

Use these complete host commands wherever printed; do not invoke repository
shell scripts directly because they may be mode `0644`:

```sh
rtk make -C tests test adversary detector benign
rtk sh tests/verify-hook-matrix.sh
rtk sh tests/verify-syscall-meta.sh
rtk bash build.sh quick
rtk bash build.sh rootless
rtk bash build.sh rootful
rtk bash tools/dyldprobe/build.sh
rtk make -C tools/hookprobe THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:15.0
rtk sh tests/MaintainerScriptTests.sh
```

### Host driver: `tests/stealth-device.sh`

This is the only device orchestration script. It may use the installed host
`sshpass -e`, OpenSSH, SCP, shell builtins, and repository build scripts; add no
package or library. It exposes exactly these commands:

```text
selftest
preflight
inventory
import-stock <raw-report> <metadata-json>
build <rootless|rootful>
install-deb <path> <package-id>
install-hookprobe <path>
set-mode <bundle-id> <stock|uninjected|injected>
launch <bundle-id> <cold|warm> <nonce>
pull-report <bundle-id> <relative-document-path> <nonce>
run-hookprobe <mode> <nonce>
daemon-status
daemon-term-safe
client-kill-safe <pid> <lstart>
restore
collect
```

`import-stock` is the only added top-level command. No other command may be
added. After the environment above is exported, exact driver invocations are:

```sh
rtk bash tests/stealth-device.sh selftest
rtk bash tests/stealth-device.sh preflight
rtk bash tests/stealth-device.sh inventory
rtk bash tests/stealth-device.sh import-stock STOCK_REPORT STOCK_METADATA
rtk bash tests/stealth-device.sh build rootless
rtk bash tests/stealth-device.sh build rootful
rtk bash tests/stealth-device.sh install-deb PACKAGE_PATH me.jjolano.shadow
rtk bash tests/stealth-device.sh install-hookprobe HOOKPROBE_PATH
rtk bash tests/stealth-device.sh set-mode BUNDLE_ID stock
rtk bash tests/stealth-device.sh set-mode BUNDLE_ID uninjected
rtk bash tests/stealth-device.sh set-mode BUNDLE_ID injected
rtk bash tests/stealth-device.sh launch BUNDLE_ID cold NONCE
rtk bash tests/stealth-device.sh launch BUNDLE_ID warm NONCE
rtk bash tests/stealth-device.sh pull-report BUNDLE_ID RELATIVE_DOCUMENT_PATH NONCE
rtk bash tests/stealth-device.sh run-hookprobe MODE NONCE
rtk bash tests/stealth-device.sh daemon-status
rtk bash tests/stealth-device.sh daemon-term-safe
rtk bash tests/stealth-device.sh client-kill-safe "$PID" "$LSTART"
rtk bash tests/stealth-device.sh restore
rtk bash tests/stealth-device.sh collect
```

Common behavior:

- require the five immutable run variables plus the current `SHADOW_TASK_ID`,
  validate the task ID against the task index, parse `SHADOW_DEVICE`, and require its
  user component to equal `mobile` exactly;
- apply all four mandatory SSH options to SSH and SCP; use `SSHPASS` only in
  the driver process environment and redact it from debug/error output;
- ordinary observations run as mobile; package install, preference writes,
  signals, and lifecycle mutations use mobile SSH plus checked sudo;
- never invoke an absent device tool; transfer raw `ps`, `find`, `plutil`, and
  hash output and parse it on the host when the device shell cannot do so;
- `launch ... cold ...` finds any exact bundle process, safely terminates it
  by separately parsed PID and quoted `lstart`, proves absence, launches, and
  requires a new PID/start identity. It records that launched identity before
  returning; `restore` terminates that exact process before restoring its
  context, preferences, or package. `launch ... warm ...` requires the same
  exact suspended PID/start, foregrounds it with `uiopen`, and proves the
  identity is unchanged; otherwise its raw result is `UNSUPPORTED`, never a
  fabricated sample. Record transition, pre/post PID/start/state, and cleanup;
- recognize only the literal hookprobe modes in the table below, including
  privileged lifecycle cases, without adding top-level commands;
- journal every mutation before execution as specified above. `restore`
  reverse-replays unresolved events and fails if the final inventory differs.

`run-hookprobe` accepts only these literal mode names and transitions:

| Mode | Required observed transition |
|---|---|
| `vnode-held-lease` | visible before -> acquired/held -> target and unrelated observations while held -> acknowledged release -> visible after |
| `lifecycle-client-normal-exit` | acquired/held -> client exits 0 -> owner absent -> release log -> ledger absent/empty -> controls visible |
| `lifecycle-client-sigkill-arm` | acquired/held -> report exact PID and `lstart` -> `client-kill-safe "$PID" "$LSTART"` -> owner absent -> release log -> ledger absent/empty -> controls visible |
| `lifecycle-suspend-resume` | acquired/held -> client suspended -> resources remain held -> client resumed -> release acknowledged -> zero resources; if no safe automation exists, raw result is `UNSUPPORTED` and blocks only the suspend/resume lifecycle claim |
| `lifecycle-connection-invalid-reacquire` | acquired/held -> test client cancels its connection while daemon stays running -> invalid connection discarded -> new connection acquired -> lease reacquired -> release acknowledged |
| `lifecycle-daemon-zero-resource-restart` | zero owners/ledger/resources proved -> clean bootout -> job/process absent -> clean-exit log -> restart -> job has a new process start identity -> controls remain visible |
| `lifecycle-backend-absent` | backend-free candidate launch -> no job, exact executable, client, ledger, or activation log appears |
| `lifecycle-backend-absent-springboard-restart` | zero resources/restore pending proved false -> SpringBoard restart -> reconnect -> backend remains absent -> unrelated controls recover |
| `lifecycle-backend-absent-userspace-reboot` | zero resources/restore pending proved false -> userspace reboot -> reconnect -> inventory matches the same row/candidate -> backend remains absent -> unrelated controls recover |
| `identity` | canonical internal identity remains truthful; every copied/symlinked/prefix/basename/case/embedded variant is filtered |
| `regression-matrix` | every applicable Landed/Remaining probe plus positive, benign, and unrelated controls produces one nonce-bound row |

`XPC_ERROR_CONNECTION_INTERRUPTED` cannot be produced by terminating a live
daemon. Its interrupted -> reconnecting -> reacquired transition is tested in
the `tests/ShadowdShims.m` host simulation. Device daemon restart evidence is
the distinct invalid/reacquire transition above.

Command-specific behavior:

- `selftest` substitutes fake SSH/SCP/sudo binaries and never contacts a
  device. Cover non-mobile user refusal; transport failure; failed sudo; stale
  report; zero/multiple containers; PID reuse; failed restore;
  cross-run/cross-row/cross-revision rejection; stock self-claim on a
  jailbroken row; inventory command error; and refusal to signal an ambiguous
  or stale process.
- `preflight` records endpoint identity, required options, privilege results,
  present/absent tools, rootless root, device/OS/build, and safe writable
  scratch behavior using only the configured mobile session. The historical
  root refusal in Known device row is copied as context, not probed. Run every
  mobile command through the bootstrap `sh`, never the account login shell,
  and detach SSH/SCP stdin so journal replay loops cannot be consumed by a
  transport subprocess.
- `inventory` emits component-keyed JSON under `inventory.components`, with
  exactly five stable keys: `shadowd`, `ShadowCore`, `harness`, `dyldprobe`,
  and `hookprobe`. Each value contains `key`, `expected_presence`,
  `pid_expected`,
  `resolved_exact_path`, `discovery_status` (`one-match`, `zero-match`,
  `expected-absent`, or `error`), `artifact_sha256`, `pid_status`, `pids`, and
  `process_start_identity`. Obtain process rows only with
  `ps -o pid=,lstart=,comm=`. `zero-match` is a failing unexpected absence;
  zero PIDs are valid for process-capable components only when
  `pid_expected=false`; a command that expects a live process sets it true.
  Non-process components use `pid_status=not-applicable` and `pids=null`, not
  an empty list; a command error is always `error`.
- `preflight`, `inventory`, and `install-deb` record exact dpkg states for the
  main, Harness, and dyldprobe packages, reject every transitional package
  state, and preserve `dpkg --audit` as raw evidence. Known virtual-package
  md5sum warnings do not dirty the database. Any managed package state other
  than `installed` or `absent` is STOP. `install-deb`
  additionally requires both its target and `me.jjolano.shadow` to be fully
  installed before upload. This gate covers the observed device state where
  the main package was already `half-configured`; normal rollback must never
  use `--force-depends` to conceal a dirty database.
- `import-stock REPORT METADATA` accepts an operator-supplied raw stock report
  and metadata JSON only. Metadata must declare row ID/type, OS/build/arch,
  jailbreak=`none`, nonce, probe revision, producer, artifact hash, and
  collection source. The report must contain matching `run_id`, `row_id`,
  `row_type`, `requested_mode`, nonce, revision, observations, and canary and
  pass its producer schema. The driver copies both unchanged, records
  `source=manual-stock`, leaves transport fields explicitly `not-applicable`,
  and never fabricates SSH, launch, PID, cleanup, or restore facts.
- `build` delegates to `./build.sh rootless|rootful`, records the exact new
  package paths and hashes, and rejects stale outputs.
- `install-deb` uploads one measured file and verifies its remote hash. Before
  every upgrade whose installed prerm is not yet proven safe, it requires all
  clients launched so far released, absent/empty ledger, run-specific release
  log lines, and target plus unrelated allowlist paths visible. VNODE-02 has
  no future probe clients; VNODE-04 additionally requires every VNODE-03 and
  VNODE-03L client released. Through mobile SSH plus checked sudo it then runs
  `launchctl bootout system/me.jjolano.shadow`, requires exit 0, requires
  `launchctl print system/me.jjolano.shadow` to show no job, requires
  `ps -o pid=,lstart=,comm=` to show no exact `shadowd` executable, and requires
  a new scoped `shadowd exiting` line when the precheck had an exact live PID.
  A loaded-idle job with no `pid =` field and no matching `ps` row is a separate
  safe branch: bootout must still remove the job, but no exit line is invented
  because no process ran. Any missing or ambiguous proof
  is STOP before `dpkg`; the old package and recovery artifact stay installed.
  Only after those checks may it run checked-sudo `dpkg`, then verify package
  ID/version and installed payload hashes.
- `install-hookprobe` performs the same upload/hash/install checks for the
  task-built executable or package and records its installed path/hash.
- `set-mode` first backs up the preferences plist. `uninjected` sets the
  bundle dictionary to `App_Disabled=true`, `App_Enabled=false`; `injected`
  sets `App_Disabled=false`, `App_Enabled=true`. Modify plist bytes with host
  Python stdlib, install them with checked sudo, signal cfprefsd only through
  `launchctl`, allow 15 seconds for SpringBoard launch services to settle,
  wait for readback, and record backup/restore. Reject `stock` on
  any jailbroken row.
- `launch` rejects stale nonce or identity state and implements only the
  cold/warm transitions above. A cold automated ShadowHarness or dyldprobe run
  executes the signed bundle binary directly as `mobile`, sets its discovered
  container as `CFFIXED_USER_HOME`, `HOME`, and `TMPDIR`, passes only the exact
  `--shadow-headless-producer` argv flag, and detaches all three standard file
  descriptors. The uninjected control additionally sets `_MSSafeMode=1`; the
  injected lane does not. The producer writes before UIKit and then waits for
  exact-PID cleanup. Other launches and warm foreground transitions use
  `uiopen --bundleid BUNDLE`. Before either path, the driver atomically installs
  the measured nonce/run/row/revision context file, requires the nonce report
  path absent, and write-ahead journals both paths. `restore` removes the exact
  report and removes or restores context; injection mode still comes from
  Shadow preferences. `ActivePrewarm=1`, suspension, command exit, passcode,
  or display state alone proves nothing.
- `pull-report` scans metadata plists, uses device `plutil -key
  MCMMetadataIdentifier`, requires exactly one matching writable data
  container, resolves the nonce-relative Documents path, and waits up to 30
  seconds for the launch callback to publish it. It requires the nonce in
  filename and body and SCPs only that file. A timeout records a SETUP-FAIL
  manifest plus exact process state before returning nonzero; it never becomes
  behavioral evidence.
- `run-hookprobe` captures stdout, stderr, transport exit, producer exit,
  request nonce, mode, process identity, and cleanup. Privileged lifecycle
  modes use checked sudo inside this command; ordinary probe modes do not.
  Before either disruptive REL-03 action it requires
  `SHADOW_ALLOW_DISRUPTIVE=$SHADOW_RUN_ID` and an operator-created
  `$SHADOW_EVIDENCE_ROOT/disruptive-authorization.json` with matching
  `run_id`, `row_id`, `actions`, and `timestamp`; record its SHA-256. Missing
  or mismatched authorization produces `NOT-RUN` and blocks that claim.
- `daemon-status` records job/process identity, client owners, ledger state,
  allowlist visibility, and the matching log window without changing state.
- `daemon-term-safe` refuses unless zero live owners, absent/empty ledger,
  matching release logs, and visible allowlist controls are all proven. It
  uses clean `launchctl bootout`, exact job/process absence, and either a new
  clean-exit log for an exact live PID or a recorded loaded-idle/no-PID branch;
  it never sends a raw process signal.
- `client-kill-safe` re-reads start identity immediately before the requested
  test signal, rejects protected/system/ambiguous identities, and records the
  post-signal identity result.
- `collect` validates the run's manifest/file graph; it does not reinterpret
  probe observations.

Every command manifest contains these validator-owned fields; inapplicable
values are explicit `null` or `not-applicable`, never omitted:

```text
schema_version, run_id, row_id, row_type, source, command, nonce, endpoint,
task_id,
jailbreak.name, jailbreak.version, os_version, os_build, architecture,
requested_mode, observed_mode, probe_revision,
inventory.components,
artifacts[].role, artifacts[].path, artifacts[].sha256,
stdout.path, stdout.sha256, stderr.path, stderr.sha256,
exit.command, exit.transport, exit.producer,
pid, process_start_identity,
launch.transition, launch.pre_pid, launch.pre_lstart, launch.pre_state,
launch.post_pid, launch.post_lstart, launch.post_state,
cleanup.event_ids, cleanup.journal_sha256, cleanup.result, cleanup.artifacts,
restore.result, restore.artifacts, authorization.sha256,
reconnect.expected_disconnect, reconnect.elapsed_seconds, reconnect.result
```

Component inventory stays under its keyed object; no validator parses human
log lines.

### Raw reports and probe revision

Converted Harness, dyldprobe, hookprobe, and imported stock raw reports
contain only producer provenance and observations:

```text
schema_version, producer, run_id, row_id, row_type, requested_mode,
nonce, probe_revision,
canary, observations, producer_exit
```

The producer writes atomically and includes the nonce in filename and body.
The driver never edits a raw report. Its manifest supplies endpoint,
transport, artifact identity, PID/start identity, cleanup, and restore;
`report` requires all shared raw/manifest provenance fields to match exactly.

`driver_revision` is the SHA-256 of `tests/stealth-device.sh` and must remain
stable after TOOL-01. `probe_revision` is task-scoped: it is the SHA-256 of a
sorted manifest of repository-relative
task-relevant files. Generate the file list from tracked/staged and untracked
non-ignored paths plus explicit Makefile/control/build inputs. Each sorted row
contains path, worktree status, and SHA-256 of current contents; a deleted
tracked path has an explicit deletion marker. Thus staged, unstaged, and
untracked bytes are represented. Stock, uninjected, and injected comparisons
require the same probe revision and the task-defined nonce relationship.
Artifact hashes may be equal across modes. ORA-01's fixed-name text and
existing hookprobe logs are immutable `legacy-baseline` blobs, not current
report-schema artifacts.

### Validator: `tests/stealth_validate.py`

This Python-standard-library file is the only validator/aggregator. It exposes
exactly:

```text
selftest
report <raw-report> <driver-manifest>
activation --scope <scope-json> <manifest-dir>
dyld --scope <scope-json> <stock-dir> <uninjected-dir> <injected-dir>
vnode <manifest-dir>
lifecycle --scope <scope-json> <manifest-dir>
matrix --scope <scope-json> <multi-row-root>
release --scope <scope-json> <evidence-root>
```

Exact validator invocations are:

```sh
rtk python3 tests/stealth_validate.py selftest
rtk python3 tests/stealth_validate.py report RAW_REPORT DRIVER_MANIFEST
rtk python3 tests/stealth_validate.py activation --scope SCOPE_JSON MANIFEST_DIR
rtk python3 tests/stealth_validate.py dyld --scope SCOPE_JSON STOCK_DIR UNINJECTED_DIR INJECTED_DIR
rtk python3 tests/stealth_validate.py vnode MANIFEST_DIR
rtk python3 tests/stealth_validate.py lifecycle --scope SCOPE_JSON MANIFEST_DIR
rtk python3 tests/stealth_validate.py matrix --scope SCOPE_JSON MULTI_ROW_ROOT
rtk python3 tests/stealth_validate.py release --scope "$SHADOW_EVIDENCE_ROOT/scopes/release-v1.json" "$SHADOW_EVIDENCE_ROOT"
```

Every partial validator call uses an immutable versioned scope at
`$SHADOW_EVIDENCE_ROOT/scopes/<scope_id>.json` containing exactly
`schema_version`, `scope_id`, `run_id`, `task_revisions`,
`required_task_ids`, `case_ids`, `regression_ids`, and `row_ids`. The release
scope is the exact set-union of accepted partial scopes, including the union of
their `task_revisions` maps; a duplicate task key must have the same revision.
It is loaded from the common evidence root; a row directory is never a release
root. Matrix input is always a multi-row root containing row-keyed children.

- `selftest` builds temporary passing/failing fixtures for missing fields,
  stale/mismatched nonce, mismatched revision, bad hash, failed transport,
  failed cleanup/restore, component-key drift, unexpected zero PIDs, command
  error, invalid stock-on-jailbreak, manual stock metadata mismatch,
  cross-run artifacts and raw/manifest provenance mismatch, equal artifact
  hashes, exact legacy exit/status rejection, scope omission/drift/union
  mismatch, and every row/flavor-scoped terminal release status.
- `report` validates ownership boundaries, nonce, probe revision, producer
  exit, artifact hash, canary requirements, transport, cleanup, and restore.
  It rejects a `legacy-baseline` blob with exit `3` and JSON
  `status="LEGACY_SCHEMA"`; any other exit or reason fails ORA-01. It also
  rejects any stock self-claim
  from a jailbroken row, every cross-run/revision pairing, and a raw report
  whose row differs from its own driver manifest. Explicitly declared stock
  and jailbroken comparison rows may differ in row ID.
- `activation` requires ten injected cold launches with identical ctor,
  post-load, and post-detector inventories and verdicts.
- `dyld` requires normalized agreement across public dyld APIs,
  `TASK_DYLD_INFO` memory, address/UUID fields, add/remove events, concurrency,
  and at least nine public callback registrations.
- `vnode` requires before/held/after target and unrelated rows for the exact
  allowlist across `open`, `openat`, `stat`, `access`, and the actual iOS
  `getdirentries64` ABI, including packed records, record lengths, offsets or
  cookies, EOF, and small-buffer behavior. `UNSUPPORTED` raw enumeration
  blocks that enumeration claim and release surface.
- `lifecycle` requires every release lifecycle case listed in REL-03, exact
  PID/start binding, lease/ledger/log transitions, and restore results.
- `matrix` requires all applicable regression-ledger rows plus positive and
  unrelated controls. A symbol/selector proven absent may be explicit N/A;
  an unmeasured applicable row fails.
- `release` may emit `RELEASE VALIDATED — ROOTLESS ROW <id>` for a passing
  rootless row, but that is never the project status. Overall status remains
  `IMPLEMENTATION COMPLETE — RELEASE BLOCKED` until a rootless device row, a
  rootful device row, and a stock control row all pass the final union scope;
  only then may it emit global `IMPLEMENTATION COMPLETE — RELEASE VALIDATED`.
  Any implementation failure emits `IMPLEMENTATION INCOMPLETE`.

## Task index and waves

| Wave | Task | Kind | Dependencies | Output/gate |
|---:|---|---|---|---|
| 1 | TOOL-01 | host implementation | none | device driver |
| 2 | TOOL-02 | host implementation | TOOL-01 | validator |
| 3 | ORA-01 | host/device evidence | TOOL-01, TOOL-02 | frozen baseline |
| 4 | ORA-02 | host/device implementation | ORA-01 | truthful harness |
| 5 | ORA-03 | host/device implementation | ORA-02 | testable dyldprobe |
| 6 | ORA-04 | evidence/checkpoint | ORA-03 | oracle status |
| 7 | VNODE-01 | host implementation | TOOL-02, ORA-01 | correlated lease |
| 8 | VNODE-02 | build/device install | VNODE-01, ORA-04 | vnode-only lineage |
| 9 | VNODE-03 | device decision | VNODE-02 | VISSHADOW evidence; REMOVE |
| 10 | VNODE-03L | pre-removal lifecycle evidence | VNODE-03 | lifecycle lineage and zero resources |
| 11 | VNODE-04 | source/package/device | VNODE-03L | backend removed |
| 12 | HOOK-01 | host implementation/audit | VNODE-04 | owned Core/filesystem ledger |
| 12 | CAP-01 | research/STOP | VNODE-04 | VFS capability gate |
| 13 | HOOK-02 | host implementation/audit | HOOK-01 | owned C/ABI ledger |
| 14 | HOOK-03 | host implementation/audit | HOOK-02 | owned dyld/ObjC ledger |
| 15 | HOOK-04 | host implementation/audit | HOOK-03 | owned Foundation/UI ledger |
| 16 | ACT-01 | host implementation | HOOK-04 | immutable activation |
| 17 | ID-01 | host implementation | ACT-01 | exact caller identity |
| 18 | DYLD-01 | host implementation | ID-01, ORA-03 | dyld fidelity |
| 19 | HOOK-05 | host audit | DYLD-01 | exact union ledger |
| 20 | REL-01 | host packaging | HOOK-05, CAP-01 | final release candidates |
| 21 | REL-01I | device install | REL-01 | exact rootless lineage installed |
| 22 | ACT-02 | device evidence | REL-01I | activation gate |
| 23 | ID-02 | device evidence | ACT-02, REL-01I | identity gate |
| 24 | DYLD-02 | device evidence | ID-02, REL-01I | dyld gate |
| 25 | REL-02 | device evidence | DYLD-02, REL-01I | multi-row matrix |
| 26 | REL-03 | host/device evidence | REL-02, VNODE-03L | lifecycle synthesis |
| 27 | REL-04 | report | REL-03 | row/flavor and project status |

Same-wave tasks have no shared source files. Device tasks are serialized
because they share preferences, installed packages, and service state.

## Phase 0-6 traceability matrix

| Phase | Required outcome | Task IDs | Evidence | Failure / rollback | DoD and report field |
|---:|---|---|---|---|---|
| 0 | Truthful oracle lineage and immutable legacy/current distinction | TOOL-01, TOOL-02, ORA-01..04 | `run.json`, `cleanup.jsonl`, scopes, legacy blobs, converted raw reports, `GATE-ORACLE.json` | STOP before mutation; journaled restore if touched; missing manual stock blocks release only | DoD oracle/report schema; completion `GATE-ORACLE`, Declared rows |
| 1 | Validate XPC/VISSHADOW, capture pre-removal lifecycle, then remove it safely | VNODE-01, VNODE-02, VNODE-03, VNODE-03L, VNODE-04 | correlated replies, nonce-bound ABI probe, lifecycle manifests, first-upgrade shutdown proof, `GATE-VISSHADOW*.json` | failed proof is STOP; no dpkg; retain old package/recovery | DoD vnode/removal; completion Vnode decision/removal and lifecycle lineage |
| 2 | Deterministic activation, observed filesystem/scheme gap closure, and escalation persistence cleanup | HOOK-01, HOOK-02, HOOK-04, ACT-01, ACT-02 | regression rows, ten-launch activation set, timing/preferences/log evidence, `GATE-ACTIVATION.json` | first divergence blocks activation/release; restore exact preferences/package | DoD activation/gaps; completion `GATE-ACTIVATION`, Regression |
| 3 | Exact canonical caller identity | ID-01, ID-02 | adversarial identity fixtures and device rows, `GATE-IDENTITY.json` | any over-trust is STOP; retain failing artifact | DoD caller identity; completion `GATE-IDENTITY`, Claims |
| 4 | dyld public/direct-memory/callback fidelity | ORA-03, HOOK-03, DYLD-01, DYLD-02 | TASK_DYLD_INFO, public API, callback, ObjC, concurrency rows, `GATE-DYLD.json` | coherence failure is STOP; restore package/preferences | DoD dyld fidelity; completion `GATE-DYLD`, Claims |
| 5 | Kernel capability research ends at a documented provider or STOP | CAP-01 | `GATE-VFS.json` with provider/API/version/install/remove facts | STOP is expected when no provider exists; no kernel mutation | DoD CAP-01; completion `GATE-VFS`, Unsupported surfaces |
| 6 | Immutable final candidates, installed lineage, multi-row differential/lifecycle evidence, and scoped release decision | HOOK-05, REL-01, REL-01I, REL-02..04 | exact ledger union, final package/probe hashes, stock import, multi-row scopes, lifecycle evidence, row/flavor statuses | failing applicable row is incomplete; missing rootful device or stock row yields release-blocked; journaled restore | DoD release; every completion report section |

## Tasks

### TOOL-01 — Implement the single host device driver

**ID / kind / dependencies:** `TOOL-01`; host implementation; none.
**Read first:** this plan's Known device row and tool contract; `build.sh`;
`Makefile`; `control`; `layout/DEBIAN/prerm`; `layout/DEBIAN/postinst`;
`ShadowHarness/Makefile`; `ShadowHarness/control`;
`tools/dyldprobe/Makefile`; `tools/dyldprobe/control`;
`tools/hookprobe/Makefile`.
**Files / symbols:** create `tests/stealth-device.sh`; command dispatcher,
SSH/SCP argv builder, manifest writer, PID/start verifier, cleanup journal.

**Action:** implement exactly the listed CLI and behaviors, including immutable
`run.json`, append-only/fsynced `cleanup.jsonl`, reverse idempotent restore,
five-key inventory, dpkg state/audit gating, import provenance, cold/warm identity transitions,
disruptive-authorization validation, and pre-dpkg safe shutdown. Use existing
host tools and known-present device commands. Keep privileged lifecycle
actions inside this driver.

**Must not:** add commands, dependencies, root SSH, `appinst`, device `awk` or
`pgrep`, embedded passwords, broad cleanup, or inline task-specific programs.
**Host verify:** `rtk bash tests/stealth-device.sh selftest`.
**Device verify:** with the required environment exported exactly once as
shown above, run `rtk bash tests/stealth-device.sh preflight`, then
`rtk bash tests/stealth-device.sh inventory`.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/TOOL-01/` and
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/TOOL-01/`.

**Binary acceptance:** selftest covers every named fake failure; known-row
preflight and component-keyed inventory both exit 0; no password occurs in
stdout, stderr, or JSON; a half-configured package is refused before upload.

**Failure / STOP / rollback:** tool or privilege mismatch is STOP before
mutation; run `restore` after any partially completed device action.

### TOOL-02 — Implement the stdlib validator

**ID / kind / dependencies:** `TOOL-02`; host implementation; TOOL-01.
**Read first:** `$SHADOW_EVIDENCE_ROOT/run.json`;
`$SHADOW_EVIDENCE_ROOT/cleanup.jsonl`; this plan's raw-report, scope, validator,
gate, regression-ledger, lifecycle, and completion-status contracts.
**Files / symbols:** create `tests/stealth_validate.py`; exact command
dispatcher and validation functions for the eight listed subcommands.

**Action:** validate only documented raw, manifest, and versioned scope fields.
Require exact raw/manifest provenance equality. Reject legacy blobs with the
exact exit/status contract, stock self-claims from jailbroken rows, stale
pairings, partial calls without `--scope`, and release scopes not equal to the
partial-scope union. Validate manual stock provenance without fabricated
transport. Keep row/flavor status distinct from project status.

**Must not:** add packages, YAML/schema frameworks, another script, inferred
defaults, score-based claims, or producer-written transport facts.
**Host verify:** `rtk python3 tests/stealth_validate.py selftest`.
**Device verify:** none; later tasks feed it device evidence.
**Evidence path:**
`$SHADOW_EVIDENCE_ROOT/host/TOOL-02/selftest.{stdout,stderr,exit}`.

**Binary acceptance:** selftest exits 0 and its built-in mutations make every
owning subcommand reject its invalid fixture.

**Failure / STOP / rollback:** validator failure blocks all evidence gates;
no device mutation occurs.

### ORA-01 — Freeze host and known-device baselines

**ID / kind / dependencies:** `ORA-01`; host/device evidence; TOOL-01,
TOOL-02.
**Read first:** `tests/Makefile`; `tests/verify-hook-matrix.sh`;
`tests/verify-syscall-meta.sh`; `ShadowHarness/Battery.h`;
`ShadowHarness/Battery.m`; `ShadowHarness/StatusViewController.m`;
`tools/dyldprobe/main.m`; `tools/hookprobe/main.m`; Known device row.
**Files / symbols:** evidence only; no source edits.

**Action:** record git state and probe revision; run the exact host commands;
run preflight/inventory; collect current Harness/dyldprobe fixed-name text,
current hookprobe logs, daemon log, ledger, and allowlist visibility without
changing preferences. Store the fixed-name text and hookprobe logs unchanged
as artifact role `legacy-baseline`. Submit each to validator `report`; require
exit `3` and JSON `status="LEGACY_SCHEMA"`, and fail on any other exit/reason.
Preserve known `sileo://`, `zbra://`, filesystem, inactive-hook, and
immediate-release results as failures/control facts, not passes. Conversion to
current raw-report schema belongs only to ORA-02/ORA-03; ORA-01 never requires
current-schema validation.

**Must not:** reinterpret a score, treat installed hash prefixes as candidate
hashes, hardcode a container UUID, or fill a stock lane from jailbroken data.
**Host verify:** `rtk make -C tests test adversary detector benign`;
`rtk sh tests/verify-hook-matrix.sh`;
`rtk sh tests/verify-syscall-meta.sh`; for each captured legacy pair run
`rtk python3 tests/stealth_validate.py report RAW_REPORT DRIVER_MANIFEST`,
capture its exit/JSON, and assert exact exit `3` plus `LEGACY_SCHEMA`.
**Device verify:** `rtk bash tests/stealth-device.sh inventory`;
`rtk bash tests/stealth-device.sh daemon-status`;
`rtk bash tests/stealth-device.sh collect`.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/ORA-01/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-01/`.

**Binary acceptance:** every attempted command has a manifest and exit;
immutable legacy blobs are captured and rejected exactly as `LEGACY_SCHEMA`;
unavailable stock is exactly `UNVERIFIED`.

**Failure / STOP / rollback:** transport/setup failure is STOP with no
behavior change; call `restore` if inventory discovered pending run state.

### ORA-02 — Make ShadowHarness report truthful outcomes

**ID / kind / dependencies:** `ORA-02`; host/device implementation; ORA-01.
**Read first:** `ShadowHarness/Battery.h`; `ShadowHarness/Battery.m`;
`ShadowHarness/StatusViewController.m`; `ShadowHarness/AppDelegate.m`;
`ShadowHarness/main.m`; `ShadowHarness/Makefile`; `ShadowHarness/control`; and
`ShadowCore.dylib/dylib.x`; `tests/verify-hook-matrix.sh`; and
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-01/`.
**Files / symbols:** `ShadowHarness/Battery.h`; `ShadowHarness/Battery.m`
(`ShdwBatteryRows`, summary, injection state);
`ShadowHarness/StatusViewController.m` (`diagnosticsString`, atomic file
write); `ShadowHarness/AppDelegate.m`; `ShadowHarness/Makefile`;
`ShadowCore.dylib/dylib.x` (`shdw_detector_detected`);
`tests/verify-hook-matrix.sh`; `tests/stealth_validate.py` selftest fixtures.

**Action:** derive PASS/FAIL/SKIP/SETUP-FAIL totals from named rows; failed
positive controls are SETUP-FAIL; injected mode requires an explicit canary;
uninjected may report CONTROL-INACTIVE. Add schema, producer, mode, nonce,
probe revision, observations, and producer exit. Write
`Documents/ShadowDiagnostics-<nonce>.json` atomically. Raw output includes
run/row/type/requested-mode provenance, nonce, revision, observations, and
canary; driver-only transport/artifact facts remain absent. Read provenance
from the driver-owned measured context file in Documents so sandbox denial or
CFPreferences caching cannot silently suppress the report.
Detector escalation must perform no synchronous preferences I/O: hooks can
fire from inside CFPrefs and recursive `NSUserDefaults` access aborts the
process before `main`. `main` emits the report before `UIApplicationMain`; the
exact `--shadow-headless-producer` lane returns `2` when that write fails and
otherwise waits for the driver's exact-PID termination. Normal icon launches
retain the UIKit path and never enter this headless branch.

**Must not:** infer injection from the filtered dyld list, hide failing rows,
write transport/artifact facts, retain the fixed report filename, or add a
harness-only concealment rule.
**Host verify:** `rtk python3 tests/stealth_validate.py selftest`;
`rtk bash build.sh rootless`;
`rtk make -C tests test adversary detector benign`.
**Device verify:** because this device's installed 4.0.0 binaries do not match
any retained 4.0.0 package, first run the driver's exact-backup atomic swap:
`rtk bash tests/stealth-device.sh install-component ShadowCore .theos/_/var/jb/Library/MobileSubstrate/DynamicLibraries/ShadowCore.dylib` (or the
same already-hashed `candidate` artifact from a restored prior attempt when an
unrelated build clean removed staging), then run
`rtk bash tests/stealth-device.sh install-deb build/me.jjolano.shadow.harness_1.0.0_iphoneos-arm64.deb me.jjolano.shadow.harness` (the identical
package under `ShadowHarness/packages/` is valid when a concurrent build clean
removed only the aggregate `build/` copy);
the driver must freeze an exact metadata-matching recovery package before
this supporting-package upgrade. Then, for each of `uninjected` and `injected`, run
`rtk bash tests/stealth-device.sh set-mode me.jjolano.shadow.harness MODE`,
`rtk bash tests/stealth-device.sh launch me.jjolano.shadow.harness cold NONCE`,
`rtk bash tests/stealth-device.sh pull-report me.jjolano.shadow.harness ShadowDiagnostics-NONCE.json NONCE`,
then `rtk python3 tests/stealth_validate.py report RAW_REPORT DRIVER_MANIFEST`.
**Evidence path:**
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-02/<mode>/<nonce>/`.

**Binary acceptance:** uninjected is CONTROL-INACTIVE with passing controls;
injected has a positive canary and does not reproduce the CFPrefs recursive
lock crash; forcing one named failure fails the aggregate and restoring it
returns the prior result.

For the forced-failure check, export
`SHADOW_FORCE_FAILURE_ID='<exact observations.rows[].id from the passing injected report>'`
only for a second injected `launch`/`pull-report` pair. Require that exact row
to be `FAIL`, aggregate `FAIL`, and producer exit `1`; unset the variable and
rerun the same injected probe under a fresh nonce, requiring the original row
status and aggregate to return. An unknown ID is `SETUP-FAIL`, not a passing
control.

**Failure / STOP / rollback:** any missing canary/report/restore is STOP;
driver `restore` returns exact preferences.

### ORA-03 — Make dyldprobe testable on the known rootless device

**ID / kind / dependencies:** `ORA-03`; host/device implementation; ORA-02.
**Read first:** `tools/dyldprobe/main.m`; `tools/dyldprobe/Makefile`;
`tools/dyldprobe/build.sh`; `tools/dyldprobe/control`;
`tools/dyldprobe/Resources/Info.plist`; `Shadow.dylib/dylib.x`;
`tools/hookprobe/main.m`.
**Files / symbols:** `tools/dyldprobe/main.m` (`ProbeReport`, direct-memory
section, app launch/report); its Makefile/build/control as needed;
`Shadow.dylib/dylib.x` loader exception.

**Action:** write nonce-named atomic reports in `NSDocumentDirectory`; add
run/row/type/requested-mode provenance, nonce, revision, producer exit, and
explicit runtime canary without driver-owned transport/artifact fields.
Replace the current dlsym-based direct-memory claim with true
`task_info(mach_task_self(), TASK_DYLD_INFO, ...)`, validated format/address/
size and bounded null-`infoArray` retry, while retaining the dlsym case as a
separate public-symbol observation. Add `me.jjolano.dyldprobe` as the second
exact loader exception beside ShadowHarness. Use per-app `App_Disabled` and
`App_Enabled` to produce uninjected and injected runs from the rootless deb.

**Must not:** require IPA installation on the known device, infer mode from
install path, invent stock signing credentials/tools, broaden the loader
exception, or write `/var/mobile/Documents/dyldprobe-report.txt`.
**Host verify:** `rtk bash tools/dyldprobe/build.sh`;
`rtk bash build.sh rootless`.
**Device verify:** first run
`rtk bash tests/stealth-device.sh install-deb build/me.jjolano.shadow_4.0.0_iphoneos-arm64.deb me.jjolano.shadow`
and
`rtk bash tests/stealth-device.sh install-deb tools/dyldprobe/packages/me.jjolano.dyldprobe_1.0.0_iphoneos-arm64.deb me.jjolano.dyldprobe`;
the driver must freeze exact metadata-matching recovery packages for both
upgrades before installing either candidate. Then
for each of `uninjected` and `injected`, run
`rtk bash tests/stealth-device.sh set-mode me.jjolano.dyldprobe MODE`,
`rtk bash tests/stealth-device.sh launch me.jjolano.dyldprobe cold NONCE`,
`rtk bash tests/stealth-device.sh pull-report me.jjolano.dyldprobe dyldprobe-NONCE.json NONCE`,
then `rtk python3 tests/stealth_validate.py report RAW_REPORT DRIVER_MANIFEST`.
**Evidence path:**
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-03/<mode>/<nonce>/`.

**Binary acceptance:** both modes share probe revision; uninjected is
CONTROL-INACTIVE; injected canary passes; TASK_DYLD_INFO address/format/size
are independent of the public dlsym observation.

**Failure / STOP / rollback:** install, mode, report, or restore failure is
STOP; restore preferences and the previous package.

### ORA-04 — Capture the oracle and timing gate

**ID / kind / dependencies:** `ORA-04`; evidence plus stock checkpoint;
ORA-02, ORA-03.
**Read first:** `$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-02/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-03/`;
`docs/STEALTH-VALIDATION-RESEARCH.md`.
**Files / symbols:** `ShadowHarness/Battery.m` and
`tools/dyldprobe/main.m` only if a required timing field is absent; evidence
otherwise.

**Action:** capture at least 30 cold and 30 warm monotonic samples for each
declared row and detect discrete first-probe/install/persistence spikes. A
stock export is accepted only with operator-supplied metadata JSON and raw
report whose nonce and probe revision match. Import it with `import-stock`;
the driver records `source=manual-stock` without inventing transport. Continue
implementation when stock is unavailable, but record
`IMPLEMENTATION COMPLETE — RELEASE BLOCKED` if all code work passes.

**Must not:** use a universal millisecond threshold, call jailbroken
uninjected data stock, install an IPA on the known device, or discard outliers.
**Host verify:** for each pair run
`rtk python3 tests/stealth_validate.py report RAW_REPORT DRIVER_MANIFEST`, then
run `rtk python3 tests/stealth_validate.py matrix --scope "$SHADOW_EVIDENCE_ROOT/scopes/oracle-v1.json" "$SHADOW_EVIDENCE_ROOT/device"`.
**Device verify:** for each mode and timing nonce run
`rtk bash tests/stealth-device.sh set-mode me.jjolano.shadow.harness MODE`;
`rtk bash tests/stealth-device.sh launch me.jjolano.shadow.harness cold NONCE`;
`rtk bash tests/stealth-device.sh launch me.jjolano.shadow.harness warm WARM_NONCE`;
`rtk bash tests/stealth-device.sh pull-report me.jjolano.shadow.harness ShadowDiagnostics-NONCE.json NONCE`;
when a warm launch is supported, pull its nonce report with
`rtk bash tests/stealth-device.sh pull-report me.jjolano.shadow.harness ShadowDiagnostics-WARM_NONCE.json WARM_NONCE`;
`rtk bash tests/stealth-device.sh set-mode me.jjolano.dyldprobe MODE`;
`rtk bash tests/stealth-device.sh launch me.jjolano.dyldprobe cold NONCE`;
`rtk bash tests/stealth-device.sh launch me.jjolano.dyldprobe warm WARM_NONCE`;
`rtk bash tests/stealth-device.sh pull-report me.jjolano.dyldprobe dyldprobe-NONCE.json NONCE`;
when a warm launch is supported, pull its nonce report with
`rtk bash tests/stealth-device.sh pull-report me.jjolano.dyldprobe dyldprobe-WARM_NONCE.json WARM_NONCE`;
repeat with literal `cold` and `warm` launch arguments for 30 samples each;
warm is `UNSUPPORTED` unless the exact suspended PID/start survives. When
stock files exist, run
`rtk bash tests/stealth-device.sh import-stock STOCK_REPORT STOCK_METADATA`.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/device/<row>/ORA-04/` and
`$SHADOW_EVIDENCE_ROOT/decisions/GATE-ORACLE.json`.

**Binary acceptance:** known device controls are valid and distributions are
saved; full oracle GO requires a matching stock row. Missing stock produces
implementation-continuable, release-blocked evidence.

**Failure / STOP / rollback:** malformed controls or restore failure is STOP;
missing stock is not an implementation rollback.

### VNODE-01 — Fix XPC reply correlation and lease lifecycle

**ID / kind / dependencies:** `VNODE-01`; host implementation; TOOL-02,
ORA-01.
**Read first:** `protocol.h`; `ShadowCore.dylib/hooks/FileHiding/vnode.x`;
`shadowd/main.m` (`shdw_xpc_reply`, `handle_xpc_message`, `handle_connection`);
`tests/ShadowdShims.m`; `tests/shadowd/RecoveryHarness.m`; `tests/Makefile`.
**Files / symbols:** `shadowd/main.m`;
`ShadowCore.dylib/hooks/FileHiding/vnode.x`; `protocol.h` only if required
without adding operations; `tests/ShadowdShims.m`;
`tests/shadowd/RecoveryHarness.m`; `tests/Makefile`.

**Action:** create every reply with `xpc_dictionary_create_reply(request)`
and send the correlated dictionary. Retain one live connection after acquire;
on interruption reconnect and reacquire before reporting active; on invalid
discard the unusable connection; make release acknowledged, repeat-safe, and
safe after interruption. Test request ID correlation, successful lease
retention, reconnect/reacquire, duplicate release, and owner-death cleanup.

**Must not:** add operations, a privileged control plane, client-supplied
PID/path, or a second lease identity.
**Host verify:** `rtk make -C tests test adversary detector benign`;
`rtk bash build.sh quick`.
**Device verify:** none in this host task; VNODE-03 runs the exact installed
candidate device command.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/VNODE-01/`; device proof is
VNODE-03.

**Binary acceptance:** host tests pass and source/device logs show one request
paired to one reply; no immediate post-acquire disconnect/release occurs.

**Failure / STOP / rollback:** correlation or lifecycle uncertainty blocks
VNODE-02; no kernel state is intentionally created by host tests.

### VNODE-02 — Build and install exact vnode test lineage

**ID / kind / dependencies:** `VNODE-02`; build/device install; VNODE-01,
ORA-04.
**Read first:** `$SHADOW_EVIDENCE_ROOT/host/VNODE-01/`; `Makefile`;
`shadowd/Makefile`; `tools/hookprobe/Makefile`; `tools/hookprobe/main.m`;
`layout/DEBIAN/prerm`; `layout/DEBIAN/postinst`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/TOOL-01/`.
**Files / symbols:** `tools/hookprobe/main.m` request/mode/report dispatch;
`layout/DEBIAN/prerm`; `layout/DEBIAN/postinst`; create
`tests/MaintainerScriptTests.sh`; `tests/Makefile`; build artifacts.

**Action:** add literal `vnode-held-lease` and VNODE-03L lifecycle producers
with raw run/row/type/requested-mode provenance and nonce-bound
target/unrelated observations. Rewrite `layout/DEBIAN/prerm`
and `layout/DEBIAN/postinst` as POSIX shell using `/bin/ps`, a shell counter
loop, and exact executable-path matching; use `launchctl` service lifecycle,
never `pgrep`, `seq`, or raw ambiguous `kill`. In
`tests/MaintainerScriptTests.sh`, fake the known device command set without
`pgrep`/`seq` and cover rootless `/var/jb/usr/libexec/shadowd`, rootful
`/usr/libexec/shadowd`, basename/prefix decoys, already-absent service,
graceful clean exit, timeout, and abort-before-dpkg; assert no raw
kill/pgrep/seq invocation. Build fresh rootless Shadow and
hookprobe, record probe revision and hashes. Because the installed old prerm
runs on the first upgrade, `install-deb` must complete the manual clean
bootout proof in the tool contract before invoking `dpkg`; this avoids relying
on the old prerm. Install those exact candidates, then inventory hashes.

**Must not:** use stale packages, `pgrep`, `seq`, device `awk`, a root login,
SIGKILL `shadowd`, `appinst`, ambiguous executable matching, or install a
package whose recovery artifact is missing.
**Host verify:** `rtk sh tests/MaintainerScriptTests.sh`;
`rtk make -C tests test adversary detector benign`;
`rtk bash build.sh rootless`;
`rtk make -C tools/hookprobe THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:15.0`.
**Device verify:** run
`rtk bash tests/stealth-device.sh install-deb PACKAGE_PATH me.jjolano.shadow`;
`rtk bash tests/stealth-device.sh install-hookprobe HOOKPROBE_PATH`;
`rtk bash tests/stealth-device.sh inventory`;
`rtk bash tests/stealth-device.sh daemon-status`. All must name candidate
hashes, not baseline prefixes.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/VNODE-02/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-02/`.

**Binary acceptance:** maintainer fixtures cover every named branch and
forbidden command; built/uploaded/installed package and hookprobe hashes match
exactly for vnode evidence/removal only. This lineage is never final behavior
proof. Daemon is ready and the measured rollback deb remains retained.

**Failure / STOP / rollback:** install/post-check failure restores the exact
previous package and preferences; failed rollback is STOP with device state
recorded.

### VNODE-03 — Run the only valid VISSHADOW A/B proof

**ID / kind / dependencies:** `VNODE-03`; device decision; VNODE-02.
**Read first:** `$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-02/`;
`shadowd/main.m`; `docs/PER-PROCESS-VFS-HIDING.md`; this plan's driver vnode
manifest contract.
**Files / symbols:** evidence only unless `tools/hookprobe/main.m` lacks one of
the exact observations.

**Action:** first compile a probe including `<sys/syscall.h>` and requiring
`SYS_getdirentries64`, then use exactly
`syscall(SYS_getdirentries64, fd, buf, size, &basep)` with a correctly typed
`basep`. If the constant is missing or compilation fails, record
`raw_enumeration=UNSUPPORTED` and block that claim; never substitute another
API. With one nonce/request, record target and
unrelated before/held/after results for every allowlist path using raw `open`,
`openat`, `stat`, `access`, and `getdirentries64`. For enumeration preserve
the raw packed records and record each record length/name, input/output
offset or cookie, bytes returned, EOF transition, and a deliberately small
buffer result. Keep the lease client alive during target and unrelated held
observations. If the raw API is unavailable, record
`raw_enumeration=UNSUPPORTED`; do not substitute another enumeration call.
Validate with `vnode`, then record ineffective, global, or target-only.

**Must not:** infer behavior from VISSHADOW readback, daemon logs, or client
success; claim per-target behavior from VISSHADOW; run unrelated observations
after releasing the lease; substitute `getdirentries` for unavailable
`getdirentries64`; or create a KEEP-GLOBAL path.
**Host verify:**
`rtk python3 tests/stealth_validate.py vnode "$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-03"`.
**Device verify:**
`rtk bash tests/stealth-device.sh run-hookprobe vnode-held-lease "$NONCE"`;
`rtk bash tests/stealth-device.sh daemon-status`.
**Evidence path:**
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-03/$NONCE/` and
`$SHADOW_EVIDENCE_ROOT/decisions/GATE-VISSHADOW-EVIDENCE.json`.

**Binary acceptance:** all five APIs have nonce/revision-matched target and
unrelated before/held/after rows; `getdirentries64` also has packed-record,
length, offset/cookie, EOF, and small-buffer proof. `UNSUPPORTED` blocks the
enumeration claim and release surface while allowing other implementation
work to continue.

**Failure / STOP / rollback:** ineffective means REMOVE; global means REMOVE;
target-only still means REMOVE because the unchanged-observer goal cannot be
proved by this global flag. Missing/ambiguous evidence is STOP before removal.

### VNODE-03L — Capture bounded pre-removal lifecycle evidence

**ID / kind / dependencies:** `VNODE-03L`; host/device evidence; VNODE-03.
**Read first:** `tests/ShadowdShims.m`; `tests/shadowd/RecoveryHarness.m`;
`tools/hookprobe/main.m`; `shadowd/main.m`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-03/`.
**Files / symbols:** `tools/hookprobe/main.m` lifecycle report dispatch;
`tests/ShadowdShims.m` interrupted-event simulation;
`tests/shadowd/RecoveryHarness.m` only when its existing recovery seam owns a
missing zero-resource assertion; evidence manifests.

**Action:** while the backend still exists, run this bounded sequence and
restore zero resources after each case: `lifecycle-client-normal-exit`;
`lifecycle-client-sigkill-arm` followed only by exact
`client-kill-safe "$PID" "$LSTART"`; `lifecycle-suspend-resume`;
`lifecycle-connection-invalid-reacquire`; and
`lifecycle-daemon-zero-resource-restart`. The SIGKILL case targets only the
test client after the driver rechecks its `ps -o pid=,lstart=,comm=` identity.
Host-simulate `XPC_ERROR_CONNECTION_INTERRUPTED`; do not claim that a live
daemon restart emitted it. Client-cancel invalid/reacquire and clean daemon
restart are separate device evidence. Before daemon bootout/restart, prove zero
owners, absent/empty ledger, run-specific release log lines, and visible
target/unrelated controls. If suspend/resume cannot be automated safely,
record `UNSUPPORTED`; it blocks only that lifecycle claim, not core
implementation.

**Must not:** SIGKILL `shadowd`; signal a client without exact PID/start
identity; restart a daemon with resources; conflate connection interrupted
with invalid; continue after cleanup/restore ambiguity; or broaden this task
beyond the five named cases.
**Host verify:** `rtk make -C tests test adversary detector benign`;
`rtk python3 tests/stealth_validate.py lifecycle --scope "$SHADOW_EVIDENCE_ROOT/scopes/vnode-lifecycle-v1.json" "$SHADOW_EVIDENCE_ROOT"`.
**Device verify:** run, with a fresh nonce for each case,
`rtk bash tests/stealth-device.sh run-hookprobe lifecycle-client-normal-exit NONCE`;
`rtk bash tests/stealth-device.sh run-hookprobe lifecycle-client-sigkill-arm NONCE`,
then `rtk bash tests/stealth-device.sh client-kill-safe "$PID" "$LSTART"`;
`rtk bash tests/stealth-device.sh run-hookprobe lifecycle-suspend-resume NONCE`;
`rtk bash tests/stealth-device.sh run-hookprobe lifecycle-connection-invalid-reacquire NONCE`;
`rtk bash tests/stealth-device.sh run-hookprobe lifecycle-daemon-zero-resource-restart NONCE`;
then `rtk bash tests/stealth-device.sh restore` and
`rtk bash tests/stealth-device.sh collect`.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/VNODE-03L/` and
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-03L/`.

**Binary acceptance:** every supported case has exact expected transitions,
PID/start identities where applicable, release log, ledger, allowlist,
cleanup, and restore facts; final state has zero resources. The validator
records suspend/resume `UNSUPPORTED` only with the scoped claim block.

**Failure / STOP / rollback:** identity, zero-resource, transport, or restore
ambiguity is STOP before the next case; preserve the VNODE-02 recovery package
and all lifecycle evidence.

### VNODE-04 — Remove VISSHADOW through the package safety path

**ID / kind / dependencies:** `VNODE-04`; source/package/device; VNODE-03L.
**Read first:** `$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-03/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-03L/`;
`ShadowCore.dylib/hooks/FileHiding/vnode.x`; `shadowd/main.m`; `protocol.h`;
`tests/ShadowdShims.m`; `tests/shadowd/RecoveryHarness.m`; `Makefile`;
`layout/DEBIAN/prerm`; `layout/DEBIAN/postinst`; enumerate candidates with
`rtk rg --files Makefile control layout ShadowSettings.bundle ShadowCore.dylib shadowd tests`, then run
`rtk rg -l 'VISSHADOW|shadowd|me\.jjolano\.shadow' build/ packages/ ShadowHarness/packages/ tools/dyldprobe/build/ "$SHADOW_EVIDENCE_ROOT/artifacts/"`; require
exactly one owner for each setting, UI key, job, payload, and test artifact.
**Files / symbols:** remove `protocol.h`;
`ShadowCore.dylib/hooks/FileHiding/vnode.x`; `shadowd/main.m`;
`shadowd/Makefile`; the exact setting/UI/job/test files returned by the
discovery command; edit `Makefile`, `layout/DEBIAN/prerm`, and
`layout/DEBIAN/postinst`; retain `tests/MaintainerScriptTests.sh` coverage.

**Action:** after every VNODE-03/VNODE-03L client has released, require zero
owners, absent/empty ledger, run-specific release log lines, and visible
target/unrelated controls. Build a backend-free package whose prerm/postinst
retain the VNODE-02 POSIX `/bin/ps`, shell-counter, exact-executable behavior.
Before `dpkg`, `install-deb` must use mobile SSH plus checked sudo to run
`launchctl bootout system/me.jjolano.shadow` and require: exit 0; subsequent
`launchctl print system/me.jjolano.shadow` has no job;
`ps -o pid=,lstart=,comm=` has no exact `shadowd` executable; and the scoped
log contains a new `shadowd exiting` line when the precheck had a live PID.
When launchd reports a loaded job with no PID and `ps` has no matching row,
record the loaded-idle branch and require clean job removal without fabricating
an exit log. Refuse all ambiguity. Only then install the
backend-free package, inventory the live device, and verify controls unchanged.

**Must not:** add a privileged control plane; signal an active-resource daemon;
SIGKILL `shadowd`; use raw ambiguous `kill`; erase a nonempty ledger; call
`dpkg` before the shutdown proof; remove the ruleset watcher; or claim success
from source scans alone.
**Host verify:** `rtk sh tests/MaintainerScriptTests.sh`;
`rtk make -C tests test adversary detector benign`;
`rtk sh tests/verify-hook-matrix.sh`;
`rtk sh tests/verify-syscall-meta.sh`;
`rtk bash build.sh rootless`; `rtk bash build.sh rootful`;
`rtk rg -n 'VISSHADOW|shadowd|me\.jjolano\.shadow' Makefile control layout ShadowSettings.bundle ShadowCore.dylib shadowd tests` and classify every result as removed artifact, required maintainer-script migration logic, or failure.
**Device verify:** `rtk bash tests/stealth-device.sh daemon-status`;
`rtk bash tests/stealth-device.sh install-deb PACKAGE_PATH me.jjolano.shadow`;
`rtk bash tests/stealth-device.sh inventory`;
`rtk bash tests/stealth-device.sh run-hookprobe lifecycle-backend-absent NONCE`;
`rtk bash tests/stealth-device.sh collect`.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/VNODE-04/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-04/`;
`$SHADOW_EVIDENCE_ROOT/decisions/GATE-VISSHADOW.json`.

**Binary acceptance:** package install used the graceful prerm path; no daemon
process/job/payload, vnode client/protocol/setting/UI/package reference, or
ledger remains; ordinary controls match baseline. Gate is `REMOVED`.

**Failure / STOP / rollback:** bootout, job/process-absence, required clean-exit-log, or
prerm proof failure means STOP with no `dpkg`; retain the old package and
recovery artifact. A later install failure restores the VNODE-02 exact package
only when the same safety prerequisites still hold. Otherwise STOP with
recovery state.

### HOOK-01 — Verify/fix shared Core and filesystem contracts

**ID / kind / dependencies:** `HOOK-01`; host implementation/audit; VNODE-04.
**Read first:** owned rows `CORE-01,CORE-03,CORE-04,CORE-05,CORE-08,CORE-09,
FILE-01,FILE-02,FILE-03,FILE-04,FILE-05,FILE-09` below;
`Shadow.framework/Core.m`; `Shadow.framework/Core+Utilities.m`;
`Shadow.framework/Backend.m`; `Shadow.framework/Ruleset.m`;
`Shadow.framework/layout/Library/Shadow/Rulesets/JailbreakMisc.plist`;
`ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x`;
`ShadowCore.dylib/hooks/FileHiding/NSFileManager.x`;
`ShadowCore.dylib/hooks/FileHiding/NSString.x`;
`ShadowCore.dylib/hooks/FileHiding/NSURL.x`; `tests/Makefile`.
**Files / symbols:** only the literal files above whose ledger probes fail;
the owning test must be exactly one of `tests/PolicyTests.m`,
`tests/RestrictionTests.m`, or `tests/main.m`, as named by the failing probe.

**Action:** turn exactly the twelve owned rows above into host/device probe
IDs; run existing tests first; fix only the shared seam that fails; keep
return/errno/output/side-effect and benign control contracts. Do not claim
rows owned by later HOOK tasks.

**Must not:** add per-probe literals, duplicate path/policy helpers, revive
removed hooks, or mark an applicable unmeasured row PASS.
**Host verify:** `rtk make -C tests test adversary detector benign`;
`rtk sh tests/verify-hook-matrix.sh`.
**Device verify:** deferred to REL-02 matrix, with stable probe IDs.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/HOOK-01/ledger.json`.

**Binary acceptance:** exactly the twelve owned rows are host PASS with named
device probes or explicit symbol/selector N/A; no future owner's row is
accepted here.

**Failure / STOP / rollback:** first failing applicable row blocks its surface
claim and downstream release; revert only the task's failing behavioral edit.

### HOOK-02 — Verify/fix C, syscall, Mach, and ABI contracts

**ID / kind / dependencies:** `HOOK-02`; host implementation/audit; HOOK-01.
**Read first:** owned rows `C-01` through `C-17`;
`ShadowCore.dylib/hooks/FileHiding/libc.x`;
`ShadowCore.dylib/hooks/FileHiding/libc_lowlevel.x`;
`ShadowCore.dylib/hooks/FileHiding/syscall.x`;
`ShadowCore.dylib/hooks/FileHiding/sandbox.x`;
`ShadowCore.dylib/hooks/Runtime/mem.x`;
`ShadowCore.dylib/hooks/Runtime/mach.x`;
`ShadowCore.dylib/hooks/AntiDebug/libc_antidebugging.x`;
`ShadowCore.dylib/hooks/Environment/libc_envvar.x`;
`ShadowCore.dylib/hooks/FileHiding/RawSyscalls.def`;
`tests/verify-hook-matrix.sh`; `tests/verify-syscall-meta.sh`.
**Files / symbols:** only a literal file above whose `C-*` probe fails; the
owning test must be exactly one of `tests/PolicyTests.m`, `tests/main.m`,
`tests/verify-hook-matrix.sh`, or `tests/verify-syscall-meta.sh`, as named by
the failing probe.

**Action:** exercise exactly the seventeen owned `C-*` rows with exact return,
errno, output buffer,
side effect, fd reuse, and control behavior. Preserve single-source hook and
raw-syscall registries.

**Must not:** use blanket errno answers, untyped variadics, hand-synced syscall
sets, or claim raw inline-svc coverage beyond the probed userspace dispatcher.
**Host verify:** `rtk make -C tests test adversary detector benign`;
`rtk sh tests/verify-hook-matrix.sh`;
`rtk sh tests/verify-syscall-meta.sh`; `rtk bash build.sh quick`.
**Device verify:** deferred to REL-02; raw siblings require device results.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/HOOK-02/ledger.json`.

**Binary acceptance:** exactly the seventeen owned C rows are host PASS with
device probe IDs; descriptor and syscall metadata checks pass.

**Failure / STOP / rollback:** first ABI/metadata failure blocks build and its
claim; do not weaken a positive control to pass.

### HOOK-03 — Verify/fix dyld and Objective-C landed contracts

**ID / kind / dependencies:** `HOOK-03`; host implementation/audit; HOOK-02.
**Read first:** owned rows `CORE-02,CORE-06,DY-01` through `DY-12`;
`ShadowCore.dylib/hooks/Runtime/dyld.x`;
`ShadowCore.dylib/hooks/Runtime/objc.x`;
`ShadowCore.dylib/hooks/Runtime/objc_hidetweakclasses.x`;
`ShadowCore.dylib/hooks/Runtime/objc_methodimpl.x`;
`ShadowCore.dylib/hooks/ranges.h`;
`ShadowCore.dylib/hooks/Environment/NSBundle.x`; `tools/dyldprobe/main.m`.
**Files / symbols:** only a literal file above whose `DY-*` probe fails; the
owning test is `tests/main.m` or `tools/dyldprobe/main.m`, exactly as named by
the failing probe.

**Action:** cover exactly the fourteen owned rows and preserve agreement among public APIs,
direct TASK_DYLD_INFO memory, Objective-C metadata, dladdr/dlsym/CFBundle, and
caller identity. Keep the memory patch independent of the old VISSHADOW work.

**Must not:** trust `/System` broadly, trust names without mapped identity,
revive NX hooks, preference-gate required direct-memory consistency, or invoke
callbacks on Shadow's behalf.
**Host verify:** `rtk make -C tests test adversary detector benign`;
`rtk sh tests/verify-hook-matrix.sh`;
`rtk sh tests/verify-syscall-meta.sh`;
`rtk bash tools/dyldprobe/build.sh`; `rtk bash build.sh quick`.
**Device verify:** DYLD-02 and REL-02.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/HOOK-03/ledger.json`.

**Binary acceptance:** exactly the fourteen owned rows have host PASS and
device probe IDs; public and direct-memory schemas share normalized identity.

**Failure / STOP / rollback:** first coherence/identity failure blocks dyld
claims; preserve the last passing mirror implementation.

### HOOK-04 — Verify/fix Foundation/UI and detector cleanup contracts

**ID / kind / dependencies:** `HOOK-04`; host implementation/audit; HOOK-03.
**Read first:** owned rows `CORE-07,FILE-06,FILE-07,FILE-08,FILE-10,N-01`
through `N-10`, plus hook-output audit IDs below;
`ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x`;
`ShadowCore.dylib/hooks/FileHiding/NSFileManager.x`;
`ShadowCore.dylib/hooks/FileHiding/NSString.x`;
`ShadowCore.dylib/hooks/FileHiding/NSURL.x`;
`ShadowCore.dylib/hooks/Environment/AppEnvironment.x`;
`ShadowCore.dylib/hooks/Environment/DeviceCheck.x`;
`ShadowCore.dylib/hooks/Environment/DeviceCheckHooks.m`;
`ShadowCore.dylib/hooks/Environment/NSBundle.x`;
`ShadowCore.dylib/hooks/AntiDebug/iokit.x`;
`ShadowCore.dylib/hooks/Runtime/ThreadImage.x`;
`ShadowCore.dylib/HookCoordinator.m`; `ShadowCore.dylib/dylib.x`;
`Shadow.framework/layout/Library/Shadow/Rulesets/JailbreakMisc.plist`.
**Files / symbols:** only a literal file above whose `N-*` probe fails; the
owning test is `tests/main.m` or `tests/CoordinatorTests.m`, exactly as named
by the failing probe.

**Action:** cover exactly the fifteen owned landed rows, explicitly reproduce and close filesystem,
`sileo://`, and `zbra://` gaps at shared policy/hook seams. Remove synchronous
detector-triggered preference/date/disk logging and core-hook installation;
detector escalation may only record in memory and request predeclared optional
units idempotently. For `AUD-FIX-IOKIT-EMPTY`, add source assertion, host test,
and stable device probe proving the landed empty-result behavior. Record
`AUD-RES-ENVIRON`, `AUD-RES-IOKIT-REGISTRY`, and
`AUD-RES-NSFILEVERSION` as residuals; do not claim or implement them here.

**Must not:** special-case harness names/schemes, synchronously complete async
APIs, install core groups only after a detector fires, or persist release-mode
detector telemetry.
**Host verify:** `rtk make -C tests test adversary detector benign`;
`rtk sh tests/verify-hook-matrix.sh`;
`rtk sh tests/verify-syscall-meta.sh`; `rtk bash build.sh quick`.
**Device verify:** ACT-02 and REL-02 include scheme, timing, persistence, and
benign controls.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/HOOK-04/ledger.json`.

**Binary acceptance:** exactly the fifteen owned landed rows pass/N/A;
`AUD-FIX-IOKIT-EMPTY` has source, host, and device proof IDs. The three
residual audit IDs remain explicit release exclusions.

**Failure / STOP / rollback:** unresolved named gaps block activation and
release; restore prior shared policy if the fix changes benign controls.

### ACT-01 — Make startup activation immutable and idempotent

**ID / kind / dependencies:** `ACT-01`; host implementation; HOOK-04.
**Read first:** `Shadow.framework/HookConfiguration.m`;
`ShadowCore.dylib/HookCoordinator.h`; `ShadowCore.dylib/HookCoordinator.m`;
`ShadowCore.dylib/dylib.x`; `tests/CoordinatorTests.m`;
`$SHADOW_EVIDENCE_ROOT/host/HOOK-04/ledger.json`.
**Files / symbols:** `Shadow.framework/HookConfiguration.m`;
`ShadowCore.dylib/HookCoordinator.h`; `ShadowCore.dylib/HookCoordinator.m`;
`ShadowCore.dylib/dylib.x`; `tests/CoordinatorTests.m`.

**Action:** compute effective preferences/capabilities once, install every
core ctor unit before app probes, add only genuinely late UIKit units on image
load, and keep repeated events idempotent. Remove the inverted/dead compile
flag split so one coordinator path is active with the existing legacy
installers as its table, not a parallel planner. Detector events may request
only the predeclared optional escalation set.

**Must not:** add a coordinator, maintain two live install paths, write prefs
or logs during detector escalation, or retain any vnode unit/key.
**Host verify:** `rtk make -C tests test adversary detector benign`;
`rtk sh tests/verify-hook-matrix.sh`;
`rtk sh tests/verify-syscall-meta.sh`; `rtk bash build.sh quick`.
**Device verify:** ACT-02.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/ACT-01/`.

**Binary acceptance:** ctor/UIKit/escalation plans have exact order,
capability gating, zero duplicates, no dead group, and no vnode reference;
repeated event tests are byte-stable.

**Failure / STOP / rollback:** planner/install mismatch blocks device work;
restore last single-path coordinator state.

### ID-01 — Enforce canonical caller identity

**ID / kind / dependencies:** `ID-01`; host implementation; ACT-01.
**Read first:** `ShadowCore.dylib/hooks/hooks.h` caller predicate;
`ShadowCore.dylib/hooks/ranges.h`;
`ShadowCore.dylib/hooks/Runtime/dyld.x`; `Shadow.framework/Core.m`; find all
call sites with
`rtk rg -n 'SHADOW_INTERNAL_SCOPE|caller.*range|range.*caller' ShadowCore.dylib Shadow.framework`
and record the complete result set before editing.
**Files / symbols:** `ShadowCore.dylib/hooks/hooks.h`;
`ShadowCore.dylib/hooks/ranges.h`; `ShadowCore.dylib/hooks/Runtime/dyld.x`;
`Shadow.framework/Core.m`; `tools/hookprobe/main.m`; `tests/PolicyTests.m`.

**Action:** trust only canonical installed Shadow image paths plus their
mapped address ranges or explicit `SHADOW_INTERNAL_SCOPE`. Treat copied,
symlinked, prefix/basename/case variants, embedded frameworks, and
ShadowCoreCompat lookalikes as external. Fail to filtered behavior when
identity/range refresh is unavailable; apply the one predicate to all call
sites.

**Must not:** trust HookKit/ElleKit/Substrate/system frames by name, conflate
hidden artifact with trusted caller, or patch callers independently.
**Host verify:** `rtk make -C tests test adversary detector benign`;
`rtk sh tests/verify-hook-matrix.sh`;
`rtk sh tests/verify-syscall-meta.sh`; `rtk bash build.sh quick`.
**Device verify:** ID-02.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/ID-01/`.

**Binary acceptance:** every adversarial fixture is untrusted; canonical
internal scope remains truthful and recursion/deadlock tests pass.

**Failure / STOP / rollback:** any over-trust or internal deadlock blocks all
caller-sensitive claims; restore the last passing classifier.

### DYLD-01 — Complete dyld callback and cross-view fidelity

**ID / kind / dependencies:** `DYLD-01`; host implementation; ID-01, ORA-03.
**Read first:** `ShadowCore.dylib/hooks/Runtime/dyld.x`;
`ShadowCore.dylib/hooks/Runtime/objc.x`; `tools/dyldprobe/main.m`;
`tests/hdr/mach-o/dyld.h`; `docs/STEALTH-VALIDATION-RESEARCH.md`.
**Files / symbols:** `ShadowCore.dylib/hooks/Runtime/dyld.x`;
`ShadowCore.dylib/hooks/Runtime/objc.x`; `tools/dyldprobe/main.m`;
`tests/hdr/mach-o/dyld.h`; `tests/main.m`.

**Action:** remove any fixed public callback ceiling. Register at least nine
add-image callbacks and prove each receives exact existing-image replay and
later add/remove events. `DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT == 8` is not a
public callback cap. Normalize image path/header/slide/UUID/address across
public APIs, TASK_DYLD_INFO memory, dladdr/dlsym, and ObjC. Publish coherent
snapshots during concurrent load/unload with bounded retry on null infoArray.

**Must not:** call app callbacks from Shadow, cap callbacks at eight, replace
TASK_DYLD_INFO with dlsym, retain torn count/array publication, or claim
deferred private APIs.
**Host verify:** `rtk bash tools/dyldprobe/build.sh`;
`rtk make -C tests test adversary detector benign`;
`rtk sh tests/verify-hook-matrix.sh`;
`rtk sh tests/verify-syscall-meta.sh`; `rtk bash build.sh quick`.
**Device verify:** DYLD-02.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/DYLD-01/`.

**Binary acceptance:** host fixtures register more than eight callbacks with
exact-once replay/add/remove accounting and normalized cross-view records.

**Failure / STOP / rollback:** callback loss, duplication, torn reads, or
cross-view disagreement blocks dyld claims; retain failing evidence.

### HOOK-05 — Freeze deferred and remaining verification ledger

**ID / kind / dependencies:** `HOOK-05`; host audit; DYLD-01.
**Read first:** every row in the regression ledger below;
`$SHADOW_EVIDENCE_ROOT/host/HOOK-01/ledger.json` through
`$SHADOW_EVIDENCE_ROOT/host/HOOK-04/ledger.json`;
`ShadowCore.dylib/HookCoordinator.m`; `ShadowCore.dylib/hooks/hooks.h`;
`ShadowCore.dylib/hooks/Runtime/dyld.x`; `tests/verify-hook-matrix.sh`.
**Files / symbols:** create
`$SHADOW_EVIDENCE_ROOT/host/HOOK-05/regression-ledger.json`; edit only
`tools/hookprobe/main.m`, `tests/verify-hook-matrix.sh`, and the literal owning
test file named in a failed HOOK-01..04 ledger when a landed row lacks a probe.

**Action:** produce exactly one machine-readable row for this canonical set:
`CORE-01,CORE-02,CORE-03,CORE-04,CORE-05,CORE-06,CORE-07,CORE-08,CORE-09`;
`FILE-01,FILE-02,FILE-03,FILE-04,FILE-05,FILE-06,FILE-07,FILE-08,FILE-09,FILE-10`;
`C-01,C-02,C-03,C-04,C-05,C-06,C-07,C-08,C-09,C-10,C-11,C-12,C-13,C-14,C-15,C-16,C-17`;
`DY-01,DY-02,DY-03,DY-04,DY-05,DY-06,DY-07,DY-08,DY-09,DY-10,DY-11,DY-12`;
`N-01,N-02,N-03,N-04,N-05,N-06,N-07,N-08,N-09,N-10`;
`D-01,D-02,D-03,D-04,D-05,D-06,D-07,D-08,R-01,R-02`. Require 68
unique rows, no duplicate IDs, and no extra IDs. Each row records category
(`Landed`, `Deferred`, or `Remaining`), applicability, literal source path and
symbol, host result, device probe ID, evidence artifact, and release
consequence. Require the HOOK-01..04 landed sets to be pairwise disjoint,
their union to equal all 58 landed IDs, and every landed row to have exactly
one of those owners; then require exact 68-row set/count after D/R rows. Also
require the exact four-ID hook-output-audit set. Repair
`tests/verify-hook-matrix.sh` so loop failures cannot be lost through a piped
`while` subshell; add `--selftest-drift`, whose synthetic mismatch must exit
nonzero. Trace rows to REL-02. Preserve Deferred/residual items as unsupported.

**Must not:** omit rows, convert deferred work to PASS, treat missing hardware
as code failure, or claim unsupported private/raw surfaces.
**Host verify:**
`rtk python3 tests/stealth_validate.py matrix --scope "$SHADOW_EVIDENCE_ROOT/scopes/hook-ledger-v1.json" "$SHADOW_EVIDENCE_ROOT"`;
`rtk make -C tests test adversary detector benign`;
`rtk sh tests/verify-hook-matrix.sh`;
`rtk sh tests/verify-hook-matrix.sh --selftest-drift`;
`rtk sh tests/verify-syscall-meta.sh`; `rtk bash build.sh quick`.
**Device verify:** REL-02 fills applicable device results.
**Evidence path:**
`$SHADOW_EVIDENCE_ROOT/host/HOOK-05/regression-ledger.json`.

**Binary acceptance:** the four owner sets are disjoint, union to the exact 58
landed IDs, and each landed row has one owner; the full ledger has exact
set/count 68 and the output audit has its exact four IDs. Normal verification
passes and synthetic drift exits nonzero.

**Failure / STOP / rollback:** any missing/duplicate row is implementation
incomplete; no device rollback applies.

### REL-01 — Freeze final release candidates and probe lineage

**ID / kind / dependencies:** `REL-01`; host packaging; HOOK-05, CAP-01.
**Read first:** HOOK-05 ledger/output audit; all ACT-01, ID-01, and DYLD-01
host evidence; `build.sh`; packaging files; maintainer scripts and tests.
**Files / symbols:** final artifacts under `build/`, `packages/`,
`ShadowHarness/packages/`, `tools/dyldprobe/build/`, and
`$SHADOW_EVIDENCE_ROOT/artifacts/`; `$SHADOW_EVIDENCE_ROOT/host/REL-01/`.

**Action:** from one recorded probe revision, clean-build and freeze the main
rootless and rootful packages plus their matching rootless hookprobe, harness,
and dyldprobe. Record exact paths, SHA-256, flavor, architecture, payload,
control scripts, and probe revision. Scan only the literal candidate paths
above with `rtk rg -l 'VISSHADOW|shadowd|protocol\.h' build/ packages/
ShadowHarness/packages/ tools/dyldprobe/build/
"$SHADOW_EVIDENCE_ROOT/artifacts/"` and classify every hit. The earlier
VNODE-02 package/probe is vnode/removal evidence only, never final proof.

**Host verify:** run the complete host command list; specifically
`rtk sh tests/MaintainerScriptTests.sh`; normal and `--selftest-drift`
hook-matrix checks; rootless/rootful builds; dyldprobe build; and rootless
hookprobe build with the exact command in the tool contract.
**Device verify:** none; REL-01I installs the frozen rootless hashes.
**Binary acceptance:** final manifest freezes unique rootless/rootful package
hashes and the matching hookprobe hash from the same revision; payload/scripts
are inspected and contain no active backend component.
**Failure / STOP / rollback:** a failed flavor is unverified and cannot satisfy
R-01; no device mutation occurs.

### REL-01I — Install exact final rootless lineage on the known device

**ID / kind / dependencies:** `REL-01I`; device install; REL-01.
**Read first:** REL-01 manifest; current inventory; cleanup journal; package
safety contract.
**Files / symbols:** evidence only under
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/REL-01I/`.

**Action:** use the journaled safety path to install the exact frozen REL-01
rootless package and matching hookprobe on the known row. Verify uploaded,
installed payload, and executable hashes against REL-01; inventory and collect
before any final behavior proof. Reject the VNODE-02 lineage even if paths or
versions match.
**Host verify:** `rtk python3 tests/stealth_validate.py report RAW_REPORT DRIVER_MANIFEST` for the install lineage manifest.
**Device verify:** `rtk bash tests/stealth-device.sh install-deb REL01_ROOTLESS_PACKAGE me.jjolano.shadow`;
`rtk bash tests/stealth-device.sh install-hookprobe REL01_HOOKPROBE`;
`rtk bash tests/stealth-device.sh inventory`; `rtk bash tests/stealth-device.sh collect`.
**Binary acceptance:** REL-01 source/upload/install hashes and revision match
exactly for package and hookprobe; cleanup journal has no unresolved event.
**Failure / STOP / rollback:** mismatch is STOP; reverse-journal restore returns
the prior measured package/preferences/service state.

### ACT-02 — Prove deterministic activation and timing

**ID / kind / dependencies:** `ACT-02`; device evidence; REL-01I.
**Read first:** `$SHADOW_EVIDENCE_ROOT/host/ACT-01/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-04/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/REL-01I/`.
**Files / symbols:** evidence only; add missing diagnostic fields only in
`ShadowCore.dylib/HookCoordinator.m` and `ShadowHarness/Battery.m`.

**Action:** run ten injected cold launches with identical settings. Capture
ctor, post-image-load, and post-detector inventories, canary, named verdicts,
preference bytes, monotonic timing, and exact REL-01 package/probe lineage. Do
not discard a divergent run or consume the VNODE-02 candidate.

**Must not:** retry away failure, change tolerance after results, persist a
detector log, or use a package/probe hash not installed by REL-01I.
**Host verify:**
`rtk python3 tests/stealth_validate.py activation --scope "$SHADOW_EVIDENCE_ROOT/scopes/activation-v1.json" "$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ACT-02"`.
**Device verify:** repeat ten times with a fresh nonce:
`rtk bash tests/stealth-device.sh set-mode me.jjolano.shadow.harness injected`;
`rtk bash tests/stealth-device.sh launch me.jjolano.shadow.harness cold NONCE`;
`rtk bash tests/stealth-device.sh pull-report me.jjolano.shadow.harness ShadowDiagnostics-NONCE.json NONCE`.
Then run
`rtk bash tests/stealth-device.sh run-hookprobe regression-matrix NONCE` and
`rtk bash tests/stealth-device.sh restore`.
**Evidence path:**
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ACT-02/` and
`$SHADOW_EVIDENCE_ROOT/decisions/GATE-ACTIVATION.json`.

**Binary acceptance:** all ten inventories/verdicts match; core units exist at
ctor; no new discrete timing/persistence fingerprint appears.

**Failure / STOP / rollback:** first divergence is STOP; restore prefs and
package before analysis.

### ID-02 — Prove caller identity on device

**ID / kind / dependencies:** `ID-02`; device evidence; ACT-02, REL-01I.
**Read first:** `$SHADOW_EVIDENCE_ROOT/host/ID-01/`;
`tools/hookprobe/main.m`; `tests/PolicyTests.m`.
**Files / symbols:** `tools/hookprobe/main.m` only if the literal `identity`
mode is missing.

**Action:** run canonical, copied, symlinked, matching-basename, embedded,
case/prefix, and late-loaded images through filesystem, dyld, ObjC, process,
and URL-scheme paths on the exact REL-01I lineage; record image path, mapped
range, caller address, and result.

**Must not:** relax trust for a failing control, infer identity from filename,
or omit internal-scope truth controls.
**Host verify:**
`rtk python3 tests/stealth_validate.py report RAW_REPORT DRIVER_MANIFEST`;
`rtk python3 tests/stealth_validate.py matrix --scope "$SHADOW_EVIDENCE_ROOT/scopes/identity-v1.json" "$SHADOW_EVIDENCE_ROOT/device"`.
**Device verify:**
`rtk bash tests/stealth-device.sh run-hookprobe identity "$NONCE"`;
`rtk bash tests/stealth-device.sh restore`.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ID-02/`;
`$SHADOW_EVIDENCE_ROOT/decisions/GATE-IDENTITY.json`.

**Binary acceptance:** every adversarial caller receives filtered results on
all applicable surfaces; canonical internal operations remain truthful and
benign behavior matches baseline.

**Failure / STOP / rollback:** first leaked adversarial caller is STOP for
identity and dependent claims; driver restores state.

### DYLD-02 — Prove dyld fidelity on device

**ID / kind / dependencies:** `DYLD-02`; device evidence; ID-02, REL-01I.
**Read first:** `$SHADOW_EVIDENCE_ROOT/host/DYLD-01/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-03/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-04/`.
**Files / symbols:** evidence only unless `tools/dyldprobe/main.m` omits a
required normalized field.

**Action:** collect uninjected and injected rootless dyldprobe reports; add
stock when separately available. Exercise at least nine callbacks, concurrent
load/unload, public views, TASK_DYLD_INFO memory, dladdr/dlsym, ObjC, UUID,
address, retry, canary, and exact REL-01I lineage fields.

**Must not:** infer stock, install IPA on the known device, accept fewer than
nine callbacks, or treat missing private/deferred surfaces as implemented.
**Host verify:** when stock exists run
`rtk python3 tests/stealth_validate.py dyld --scope "$SHADOW_EVIDENCE_ROOT/scopes/dyld-v1.json" STOCK_DIR UNINJECTED_DIR INJECTED_DIR`;
otherwise run `rtk python3 tests/stealth_validate.py report RAW_REPORT DRIVER_MANIFEST`
for each jailbroken mode and record the release block.
**Device verify:** for each of `uninjected` and `injected`, run
`rtk bash tests/stealth-device.sh set-mode me.jjolano.dyldprobe MODE`;
`rtk bash tests/stealth-device.sh launch me.jjolano.dyldprobe cold NONCE`;
`rtk bash tests/stealth-device.sh pull-report me.jjolano.dyldprobe dyldprobe-NONCE.json NONCE`;
then `rtk bash tests/stealth-device.sh restore`.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/DYLD-02/`;
`$SHADOW_EVIDENCE_ROOT/decisions/GATE-DYLD.json`.

**Binary acceptance:** available modes pass cross-view/callback/concurrency
checks; full GO additionally requires stock. Missing stock blocks release only.

**Failure / STOP / rollback:** device coherence failure is STOP; missing stock
is release-blocked; restore preferences.

### CAP-01 — Gate process-aware kernel capability research

**ID / kind / dependencies:** `CAP-01`; research/decision; VNODE-04.
**Read first:** `docs/PER-PROCESS-VFS-HIDING.md`;
`docs/STEALTH-VALIDATION-RESEARCH.md`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-03/`; record every external
first-party jailbreak source as exact URL, version, retrieval date, and hash in
`$SHADOW_EVIDENCE_ROOT/host/CAP-01/sources.json` before using it.
**Files / symbols:** evidence/decision only; no kernel implementation.

**Action:** record kernel read, write, call, and persistent VFS hook as four
independent capabilities. Dopamine/palera1n presently document no supported
persistent process-aware VFS hook API; KRW/kcall is insufficient. Record
`GATE-VFS=STOP` unless a first-party install/remove/lifecycle facility is
documented for the exact row.

**Must not:** implement a trampoline, patchfinder, MACF/vnode-op/syscall-table
replacement, or infer persistent hooks from KRW/kcall.
**Host verify:**
`rtk python3 -m json.tool "$SHADOW_EVIDENCE_ROOT/decisions/GATE-VFS.json"`;
`rtk python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); want={"kernel_read","kernel_write","kernel_call","persistent_vfs_hook"}; assert set(d["capabilities"])==want; assert all({"provider","api","version","install","removal","status"} <= set(v) for v in d["capabilities"].values())' "$SHADOW_EVIDENCE_ROOT/decisions/GATE-VFS.json"`.
**Device verify:** none for the documented STOP row. A positive provider halts
this plan for a follow-up before any persistent device mutation.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/decisions/GATE-VFS.json`.

**Binary acceptance:** current documented state yields STOP with a complete
matrix. STOP completes this task and limits claims; it does not make userspace
implementation incomplete.

**Failure / STOP / rollback:** if a future first-party facility exists, stop
and write a follow-up plan. Do not add implementation tasks here.

### REL-02 — Run the three-way regression matrix

**ID / kind / dependencies:** `REL-02`; device evidence; DYLD-02, REL-01I.
**Read first:** `$SHADOW_EVIDENCE_ROOT/host/REL-01/`;
`$SHADOW_EVIDENCE_ROOT/host/HOOK-05/regression-ledger.json`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-02/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/ORA-03/`; Known device row.
**Files / symbols:** evidence only; a probe omission returns to the literal
source/test pair recorded in
`$SHADOW_EVIDENCE_ROOT/host/HOOK-05/regression-ledger.json`.

**Action:** install the exact candidate and run every applicable ledger probe
for uninjected and injected modes. Reinstall and verify the exact REL-01
hookprobe hash before collecting any row. Accept stock only through
`import-stock STOCK_REPORT STOCK_METADATA`; require the operator-supplied
metadata and raw report to match nonce and probe revision. Include positive,
benign, unrelated-process/service, package-manager, loader, and launchd
controls. R-01 rootful is satisfied only by a rootful device row running the
full matrix; a host rootful build is lineage, never R-01 proof. Missing
rootful-device or stock-control rows keeps project status release-blocked.

**Must not:** install IPA on the known device, substitute uninjected for stock,
declare a row with missing applicable probes, or infer from aggregate scores.
**Host verify:**
`rtk python3 tests/stealth_validate.py matrix --scope "$SHADOW_EVIDENCE_ROOT/scopes/regression-v1.json" "$SHADOW_EVIDENCE_ROOT/device"`.
**Device verify:** `rtk bash tests/stealth-device.sh install-deb REL01_ROOTLESS_PACKAGE me.jjolano.shadow`;
`rtk bash tests/stealth-device.sh install-hookprobe REL01_HOOKPROBE` and require
its installed SHA-256 to equal the REL-01 manifest;
for each `MODE` in `uninjected` and `injected`, run
`rtk bash tests/stealth-device.sh set-mode me.jjolano.shadow.harness MODE`;
`rtk bash tests/stealth-device.sh launch me.jjolano.shadow.harness cold NONCE`;
`rtk bash tests/stealth-device.sh pull-report me.jjolano.shadow.harness ShadowDiagnostics-NONCE.json NONCE`;
`rtk bash tests/stealth-device.sh set-mode me.jjolano.dyldprobe MODE`;
`rtk bash tests/stealth-device.sh launch me.jjolano.dyldprobe cold NONCE`;
`rtk bash tests/stealth-device.sh pull-report me.jjolano.dyldprobe dyldprobe-NONCE.json NONCE`;
run
`rtk bash tests/stealth-device.sh run-hookprobe regression-matrix NONCE`;
when stock files exist run
`rtk bash tests/stealth-device.sh import-stock STOCK_REPORT STOCK_METADATA`;
then `rtk bash tests/stealth-device.sh restore` and
`rtk bash tests/stealth-device.sh collect`.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/device/<row>/REL-02/`.

**Binary acceptance:** applicable rows pass with controls and exact REL-01
lineage. The known row may earn `RELEASE VALIDATED — ROOTLESS ROW <id>` only
for its scoped flavor. R-01 remains unverified until a rootful device matrix
passes; project release stays blocked until rootful-device and stock-control
rows also pass.

**Failure / STOP / rollback:** applicable failure blocks its claim/release;
missing stock blocks release validation; driver restores preferences/package.

### REL-03 — Run the lifecycle release matrix

**ID / kind / dependencies:** `REL-03`; host/device evidence; REL-02,
VNODE-03L.
**Read first:** `$SHADOW_EVIDENCE_ROOT/host/VNODE-03L/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-03L/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/VNODE-04/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/REL-02/`;
`tests/ShadowdShims.m`; `tests/shadowd/RecoveryHarness.m`.
**Files / symbols:** evidence manifests only. If backend-absent producers are
missing, edit only `tools/hookprobe/main.m`; host simulation fixes, if needed,
belong only in `tests/ShadowdShims.m` or `tests/shadowd/RecoveryHarness.m`.

**Action:** do not recreate removed daemon lifecycle. Consume VNODE-03L's
client normal-exit, exact client SIGKILL, suspend/resume, invalid/reacquire,
zero-resource daemon restart, and host-interrupted simulation manifests;
consume the PID-reuse and corrupt/partial-ledger host results from VNODE-01/03L.
On the exact backend-free REL-01 candidate run `lifecycle-backend-absent`,
`lifecycle-backend-absent-springboard-restart`, and
`lifecycle-backend-absent-userspace-reboot` to prove no daemon, job, exact
executable, client, ledger, or activation returns across restarts. Each
privileged restart requires
`SHADOW_ALLOW_DISRUPTIVE=$SHADOW_RUN_ID` plus an operator-created
`$SHADOW_EVIDENCE_ROOT/disruptive-authorization.json` containing matching
`run_id`, `row_id`, `actions`, and `timestamp`; the driver validates and
records its hash. Before each action append+fsync the pending cleanup WAL
event and prove zero resources/no unresolved restore. Missing env/file yields
`NOT-RUN` and blocks that lifecycle claim. Capture expected SSH disconnect as
a separate event, poll reconnect for at most 180 seconds, and never infer
success from disconnect. After reconnect revalidate row/candidate hashes,
package state, cleanup journal, inventory, and controls. Jetsam remains
disposable-only `NOT-RUN`; scoped suspend/resume `UNSUPPORTED` blocks only its
claim.

**Must not:** reinstall the backend to generate evidence; issue raw signal
commands; SIGKILL `shadowd`; signal ambiguous PIDs; label a device restart as
`XPC_ERROR_CONNECTION_INTERRUPTED`; reboot with resources/restore pending; or
count jetsam as required.
**Host verify:** `rtk make -C tests test adversary detector benign`;
`rtk python3 tests/stealth_validate.py lifecycle --scope "$SHADOW_EVIDENCE_ROOT/scopes/release-lifecycle-v1.json" "$SHADOW_EVIDENCE_ROOT"`.
**Device verify:**
`rtk bash tests/stealth-device.sh run-hookprobe lifecycle-backend-absent NONCE`;
`rtk bash tests/stealth-device.sh run-hookprobe lifecycle-backend-absent-springboard-restart NONCE`;
`rtk bash tests/stealth-device.sh run-hookprobe lifecycle-backend-absent-userspace-reboot NONCE`;
then after reconnection run `rtk bash tests/stealth-device.sh inventory`,
`rtk bash tests/stealth-device.sh restore`, and
`rtk bash tests/stealth-device.sh collect`.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/host/REL-03/`;
`$SHADOW_EVIDENCE_ROOT/device/$SHADOW_ROW_ID/REL-03/`.

**Binary acceptance:** pre-removal VNODE-03L and post-removal REL-03 cases
aggregate under one scope. Every authorized case has exact identities,
transition, disconnect/reconnect facts, candidate/package revalidation,
controls, and journaled cleanup/restore PASS; unauthorized disruptive cases
are `NOT-RUN` and block only their named claims.

**Failure / STOP / rollback:** identity, zero-resource, transport, reconnect,
or restore ambiguity is STOP before the next destructive case; preserve the
current recovery artifact and state.

### REL-04 — Decide release status and publish the completion report

**ID / kind / dependencies:** `REL-04`; report; REL-03.
**Read first:** `$SHADOW_EVIDENCE_ROOT/run.json`;
`$SHADOW_EVIDENCE_ROOT/decisions/`;
`$SHADOW_EVIDENCE_ROOT/host/HOOK-05/regression-ledger.json`;
`$SHADOW_EVIDENCE_ROOT/host/REL-01/`;
`$SHADOW_EVIDENCE_ROOT/device/`; Definition of Done below.
**Files / symbols:** `$SHADOW_EVIDENCE_ROOT/completion.md`;
`$SHADOW_EVIDENCE_ROOT/decisions/final-status.json`.

**Action:** run validator `release` on the common evidence root and final union
scope. Copy its row/flavor statuses and distinct project status; name exact
rows/mechanisms, link raw/manifest/hash lineage, and list Deferred plus
`AUD-RES-ENVIRON`, `AUD-RES-IOKIT-REGISTRY`, and
`AUD-RES-NSFILEVERSION` under release exclusions. A passing known rootless row
may get its scoped status, while missing rootful-device or stock-control rows
keeps project status implementation-complete/release-blocked.

**Must not:** say releaseable from host tests, omit STOPs/residuals, claim
per-process kernel hiding, or turn missing hardware into implementation
failure.
**Host verify:**
`rtk python3 tests/stealth_validate.py release --scope "$SHADOW_EVIDENCE_ROOT/scopes/release-v1.json" "$SHADOW_EVIDENCE_ROOT"`.
**Device verify:** none; consumes completed evidence.
**Evidence path:** `$SHADOW_EVIDENCE_ROOT/completion.md` and
`$SHADOW_EVIDENCE_ROOT/decisions/final-status.json`.

**Binary acceptance:** each declared row/flavor has exactly one allowed status
and every claim links raw+manifest+REL-01 hashes. Global validation appears
only when rootless device, rootful device, and stock control rows all pass.

**Failure / STOP / rollback:** missing/failing implementation tasks produce
`IMPLEMENTATION INCOMPLETE`; no device mutation occurs.

## Regression ledger: HOOK-FIX Landed contracts

Every row is explicit input to HOOK-01 through HOOK-05 and REL-02. An
applicable row without binary device evidence blocks that surface claim.

| ID | Contract | Primary files/symbols | Task |
|---|---|---|---|
| CORE-01 | Operation-aware canonical paths; writes do not require target existence; rootless aliases agree | `Shadow.framework/Core.m`; `ShadowCore.dylib/policy/PathPolicy.m` | HOOK-01 |
| CORE-02 | Only canonical Shadow ranges or internal scope see truth | `Shadow.framework/Core.m`; `ShadowCore.dylib/hooks/hooks.h`; `ShadowCore.dylib/hooks/ranges.h` | HOOK-03 |
| CORE-03 | Shared Cocoa error factory preserves domain/code/path-or-URL userInfo | `Shadow.framework/Core+Utilities.m`; `ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x` | HOOK-01 |
| CORE-04 | Scheme matching is case-insensitive in Backend and Ruleset | `Shadow.framework/Backend.m`; `Shadow.framework/Ruleset.m` | HOOK-01 |
| CORE-05 | Hidden bundle-ID predicate is shared and case-insensitive | `Shadow.framework/Core.m`; `Shadow.framework/Backend.m`; `ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x` | HOOK-01 |
| CORE-06 | Protected image/class/bundle names are exact, generation-aware, allocation-safe | `Shadow.framework/Core.m`; `ShadowCore.dylib/hooks/Runtime/objc.x` | HOOK-03 |
| CORE-07 | Safe groups/defaults, env hooks, and detector plan are consistent | `Shadow.framework/HookConfiguration.m`; `ShadowCore.dylib/HookCoordinator.m`; `ShadowCore.dylib/dylib.x` | HOOK-04 |
| CORE-08 | Ruleset generation invalidates decision and directory caches | `Shadow.framework/Backend.m`; `Shadow.framework/Ruleset.m`; `Shadow.framework/Core.m`; `ShadowCore.dylib/hooks/FileHiding/libc.x` | HOOK-01 |
| CORE-09 | Static rules cover Shadow and jailbreak artifacts without dpkg dependence | `Shadow.framework/layout/Library/Shadow/Rulesets/JailbreakMisc.plist` | HOOK-01 |
| FILE-01 | `NSFileAppendOnly` spoofs remain deleted | `ShadowCore.dylib/hooks/FileHiding/NSFileManager.x` | HOOK-01 |
| FILE-02 | Existence/readability/contents preflight before original and clear outputs on denial | `ShadowCore.dylib/hooks/FileHiding/NSFileManager.x` | HOOK-01 |
| FILE-03 | Enumerator direct/fast paths, ownership, attributes, and error handler filter consistently | `ShadowCore.dylib/hooks/FileHiding/NSFileManager.x` | HOOK-01 |
| FILE-04 | Symlink source/destination and resolved targets are checked | `ShadowCore.dylib/hooks/FileHiding/libc.x`; `ShadowCore.dylib/hooks/FileHiding/NSFileManager.x` | HOOK-01 |
| FILE-05 | NSURL resolved/resource/bookmark results filter and clear outputs | `ShadowCore.dylib/hooks/FileHiding/NSURL.x` | HOOK-01 |
| FILE-06 | Blocked NSURLSession returns a real cancelled task and one async error | `ShadowCore.dylib/hooks/FileHiding/NSURL.x` | HOOK-04 |
| FILE-07 | NSURLRequest constructor hooks remain absent | `ShadowCore.dylib/hooks/FileHiding/NSURL.x` | HOOK-04 |
| FILE-08 | NSFileVersion objects and async completions preserve contracts | `ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x` | HOOK-04 |
| FILE-09 | setAttributes, URLForDirectory, mounts, and app-group container surfaces are covered | `ShadowCore.dylib/hooks/FileHiding/NSFileManager.x` | HOOK-01 |
| FILE-10 | Foundation error/write-intent sweep covers collections/data/string writers | `ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x`; `ShadowCore.dylib/hooks/FileHiding/NSString.x` | HOOK-04 |
| C-01 | Shared dirfd resolver covers linkat/symlinkat/renameat/mkdirat/utimensat/fchmodat | `ShadowCore.dylib/hooks/FileHiding/libc.x` | HOOK-02 |
| C-02 | Mount sanitizer compacts records/counts and covers statfs/getfsstat/getmntinfo family | `ShadowCore.dylib/hooks/FileHiding/libc.x` | HOOK-02 |
| C-03 | `.jbroot` matches an exact component | `ShadowCore.dylib/hooks/FileHiding/libc.x` | HOOK-02 |
| C-04 | readlinkat/realpath classify returned targets and preserve allocation/buffer semantics | `ShadowCore.dylib/hooks/FileHiding/libc.x` | HOOK-02 |
| C-05 | readdir fails closed on unresolved valid vnode and invalidates on fd/ruleset change | `ShadowCore.dylib/hooks/FileHiding/libc.x` | HOOK-02 |
| C-06 | getenv filters DYLD/safe-mode/jailbreak/PATH with stable storage | `ShadowCore.dylib/hooks/Environment/libc_envvar.x` | HOOK-02 |
| C-07 | sysctl validates MIB and preserves KERN_PROC size/short-buffer semantics | `ShadowCore.dylib/hooks/FileHiding/libc_lowlevel.x`; `ShadowCore.dylib/hooks/FileHiding/syscall.x` | HOOK-02 |
| C-08 | getppid is caller-gated and invokes the stored original | `ShadowCore.dylib/hooks/FileHiding/libc_lowlevel.x` | HOOK-02 |
| C-09 | stat64 and protected/authenticated open siblings share policy | `ShadowCore.dylib/hooks/FileHiding/libc.x`; `ShadowCore.dylib/hooks/FileHiding/libc_lowlevel.x` | HOOK-02 |
| C-10 | csops clears only allowed bits and pre-rejects MARKKILL without side effects | `ShadowCore.dylib/hooks/FileHiding/syscall.x` | HOOK-02 |
| C-11 | vm_region skips restricted intervals without protection contradictions | `ShadowCore.dylib/hooks/Runtime/mem.x` | HOOK-02 |
| C-12 | Elevated Mach ports are hidden/deallocated; bootstrap matcher is exact/shared | `ShadowCore.dylib/hooks/Runtime/mach.x` | HOOK-02 |
| C-13 | sandbox_check decodes known arity and unknown forms call original | `ShadowCore.dylib/hooks/FileHiding/sandbox.x` | HOOK-02 |
| C-14 | exec/spawn/fork wrappers are typed; no blanket ENOSYS or wrong spawn ABI | `ShadowCore.dylib/hooks/FileHiding/sandbox.x`; `ShadowCore.dylib/hooks/FileHiding/libc_lowlevel.x` | HOOK-02 |
| C-15 | signal/bsd_signal/sigaction aliases sanitize only successful outputs | `ShadowCore.dylib/hooks/AntiDebug/libc_antidebugging.x` | HOOK-02 |
| C-16 | raw openat/fstatat/csops/sysctl and `__syscall` share one metadata/policy registry | `ShadowCore.dylib/hooks/FileHiding/RawSyscalls.def`; `ShadowCore.dylib/hooks/FileHiding/syscall.x` | HOOK-02 |
| C-17 | Exported sysctlbyname/csops_audittoken/_NSGetEnviron/system/popen/bootstrap/sandbox siblings are covered | `ShadowCore.dylib/hooks/FileHiding/libc_lowlevel.x`; `ShadowCore.dylib/hooks/FileHiding/syscall.x`; `ShadowCore.dylib/hooks/Runtime/mach.x`; `ShadowCore.dylib/hooks/FileHiding/sandbox.x` | HOOK-02 |
| DY-01 | Own-range collector contains only Shadow-owned artifacts | `ShadowCore.dylib/hooks/Runtime/dyld.x`; `ShadowCore.dylib/hooks/ranges.h` | HOOK-03 |
| DY-02 | NXMapGet/NXHashGet hooks remain absent | `ShadowCore.dylib/hooks/Runtime/objc.x` | HOOK-03 |
| DY-03 | Method getter APIs return NULL for protected method/class/IMP without invalid casts | `ShadowCore.dylib/hooks/Runtime/objc.x` | HOOK-03 |
| DY-04 | objc image/class lookup/list/copy/enumeration views agree | `ShadowCore.dylib/hooks/Runtime/objc.x` | HOOK-03 |
| DY-05 | dlsym policy, thread-local dlerror, and RTLD_NEXT caller capture agree | `ShadowCore.dylib/hooks/Runtime/dyld.x` | HOOK-03 |
| DY-06 | dladdr zeroes restricted output and returns stock-like failure | `ShadowCore.dylib/hooks/Runtime/dyld.x` | HOOK-03 |
| DY-07 | `/System` blanket admission remains removed | `ShadowCore.dylib/hooks/Runtime/dyld.x` | HOOK-03 |
| DY-08 | all_image_infos patch is not preference-gated and agrees with TASK_DYLD_INFO | `ShadowCore.dylib/hooks/Runtime/dyld.x`; `tools/dyldprobe/main.m` | HOOK-03 |
| DY-09 | imp_getBlock inspects the block invoke pointer | `ShadowCore.dylib/hooks/Runtime/objc.x` | HOOK-03 |
| DY-10 | CFBundle symbol lookup uses the same symbol policy | `ShadowCore.dylib/hooks/Runtime/dyld.x`; `ShadowCore.dylib/hooks/Environment/NSBundle.x` | HOOK-03 |
| DY-11 | objc_setHook proxies chain old values and method metadata filters agree | `ShadowCore.dylib/hooks/Runtime/objc.x` | HOOK-03 |
| DY-12 | dlopen token/rpath resolution uses explicit caller identity | `ShadowCore.dylib/hooks/Runtime/dyld.x` | HOOK-03 |
| N-01 | NSThread class stack APIs filter addresses and symbols | `ShadowCore.dylib/hooks/Runtime/ThreadImage.x` | HOOK-04 |
| N-02 | isMacCatalystApp plus environment/arguments use correct ABI/lifecycle | `ShadowCore.dylib/hooks/Environment/AppEnvironment.x` | HOOK-04 |
| N-03 | LSApplicationWorkspace uses the shared bundle-ID predicate | `ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x` | HOOK-04 |
| N-04 | NSAttributedString blocked loaders complete asynchronously with stock-like error | `ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x` | HOOK-04 |
| N-05 | DeviceCheck support hooks are encoding-aware; no attestation-forgery claim | `ShadowCore.dylib/hooks/Environment/DeviceCheck.x`; `ShadowCore.dylib/hooks/Environment/DeviceCheckHooks.m` | HOOK-04 |
| N-06 | UIApplication openURL variants deny without LaunchServices side effects and complete async | `ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x` | HOOK-04 |
| N-07 | UIImage variants use exact protected basenames/bundles | `ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x` | HOOK-04 |
| N-08 | NSBundle metadata/load-state preserves nonnull/stock contracts | `ShadowCore.dylib/hooks/Environment/NSBundle.x` | HOOK-04 |
| N-09 | NSString completion/write and WebKit loaders preserve async/error semantics | `ShadowCore.dylib/hooks/FileHiding/NSString.x`; `ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x` | HOOK-04 |
| N-10 | Collection file loading/writing errors and missing variants are normalized | `ShadowCore.dylib/hooks/FileHiding/FoundationFileHiding.x` | HOOK-04 |

## HOOK-OUTPUT-AUDIT

| ID | Disposition | Required evidence / release consequence |
|---|---|---|
| AUD-FIX-IOKIT-EMPTY | landed; HOOK-04 | source assertion + host test + REL-02 device probe for stock-like empty IOKit result |
| AUD-RES-ENVIRON | residual | final report exclusion: direct raw `environ` symbol reads |
| AUD-RES-IOKIT-REGISTRY | residual | final report exclusion: unmodeled IOKit registry properties |
| AUD-RES-NSFILEVERSION | residual | final report exclusion: unverified NSFileVersion variants |

## Regression ledger: Deferred contracts

These remain explicit unsupported surfaces. HOOK-05 records them; this plan
does not implement them.

| ID | Deferred contract | Release consequence |
|---|---|---|
| D-01 | dyld tail-branch callback thunks, `_dyld_objc_notify_register`, `objc_addLoadImageFunc`, process-info/snapshot APIs, NSAddImage family, growable mirror, notifier-inline rebuild | no claim for each deferred dyld/private surface |
| D-02 | recursive copy/move/remove/trash descendant preflight | no recursive-descendant claim |
| D-03 | NSFileWrapper full containment | no full NSFileWrapper containment claim |
| D-04 | NSFileHandle fd-based surfaces | no fd-based Foundation claim |
| D-05 | LaunchServices/MobileInstallation payload-content filtering | no payload-content claim |
| D-06 | late-loaded detector-class hook retry | no late-loaded detector-class claim |
| D-07 | DCDevice/AppAttest async generation APIs | no forged attestation/generation claim |
| D-08 | wordexp, pid_for_task, mach_port_names, task_get_exception_ports upgrades | conservative pass-through; no concealment claim |

## Regression ledger: Remaining verification

| ID | Required verification | Release consequence |
|---|---|---|
| R-01 | Full rootless/rootful adversarial matrix: aliases/nonexistent writes; enumeration/errors; dyld/ObjC; mount/csops/raw syscall/spawn/sandbox/bootstrap/vm/fd reuse; Foundation/UI; ABI/error fingerprints; benign smoke; detector suite | rootful requires a passing rootful device row; host build never satisfies it |
| R-02 | Legacy armv7/armv7s packaging with staged dependencies | missing dependencies/build makes rootful legacy claim UNVERIFIED; never infer from rootless |

## Gate rules

- `GATE-ORACLE`: code/probes may proceed with valid known-device controls;
  release validation requires stock.
- `GATE-VISSHADOW`: all VNODE-03 outcomes lead through VNODE-03L to VNODE-04
  removal. Only verified installed absence is `REMOVED`.
- `GATE-ACTIVATION`, `GATE-IDENTITY`, `GATE-DYLD`: GO only on their binary
  device checks; missing stock limits release status where applicable.
- `GATE-VFS`: STOP is the expected completed outcome without a documented
  first-party persistent process-aware hook API. No kernel implementation
  follows in this plan.
- A rootless device row may receive only its named row status. Global
  validation requires passing rootless-device, rootful-device, and stock-control
  rows under the final union scope; one row never yields global validation.

## Definition of Done

- [ ] TOOL-01 and TOOL-02 selftests pass; the driver uses only the exact CLI.
- [ ] Immutable `run.json` and append-only/fsynced `cleanup.jsonl` exist;
      every mutation has pending/completed/restored events and reverse
      idempotent restore ends with a matching inventory.
- [ ] Inventory has exactly the five component keys and distinguishes
      one-match, unexpected zero-match, expected absence, command error, and
      binary presence from per-command PID expectation; PID rows use
      `ps -o pid=,lstart=,comm=`.
- [ ] Raw reports carry exact run/row/type/requested-mode/nonce/revision,
      observations, and canary; TOOL-02 matches provenance to driver manifests.
- [ ] ORA-01 legacy fixed-name/log blobs remain immutable and their expected
      validator rejection passes; converted producers validate only afterward.
- [ ] Harness truthful aggregation and explicit canaries pass.
- [ ] dyldprobe uses real TASK_DYLD_INFO and rootless deb injection via the
      exact loader exception; no known-device IPA install is required.
- [ ] VNODE-01 correlation passes; VNODE-03 captures the real iOS
      `getdirentries64` ABI or blocks enumeration as `UNSUPPORTED`; VNODE-03L
      completes bounded lifecycle evidence; VNODE-04 removes the backend only
      after clean bootout proof and `tests/MaintainerScriptTests.sh` passes.
- [ ] No active daemon/protocol/client/setting/UI/package reference remains;
      no active-resource shadowd SIGKILL occurred.
- [ ] Deterministic activation, named filesystem/scheme gaps, caller identity,
      more-than-eight callbacks, dyld cross-view fidelity, and detector
      persistence/timing checks pass.
- [ ] The four HOOK owner sets are disjoint and union to all 58 landed rows;
      the full ledger has exact set/count 68; output audit has its four IDs.
- [ ] REL-03 coherently aggregates VNODE-03L pre-removal and post-removal
      cases; disruptive actions require matching env/file authorization, WAL,
      bounded reconnect, and post-reconnect lineage/state revalidation.
- [ ] CAP-01 records STOP or names a documented provider; no handwritten
      kernel hook exists.
- [ ] REL-01 freezes final rootless/rootful and matching hookprobe hashes;
      REL-01I installs exact rootless lineage before ACT/ID/DYLD/REL evidence.
- [ ] Every partial aggregation uses its versioned `--scope`; release uses the
      exact union scope and common evidence root; matrix input is multi-row.
- [ ] Row/flavor statuses never imply project validation; global validation
      requires rootless device, rootful device, and stock control rows.

## Completion report template

```text
# Stealth hardening completion report

Project status: IMPLEMENTATION COMPLETE — RELEASE VALIDATED |
                IMPLEMENTATION COMPLETE — RELEASE BLOCKED |
                IMPLEMENTATION INCOMPLETE
Row status: RELEASE VALIDATED — ROOTLESS ROW <id> | BLOCKED | FAILED
Evidence root:
Run ID:
Task revision-map hash:
Final union scope ID/hash:
Commit/worktree state:

## Gates
GATE-ORACLE:
GATE-VISSHADOW:
GATE-ACTIVATION:
GATE-IDENTITY:
GATE-DYLD:
GATE-VFS:

## Candidate lineage
Flavor/row | package path/SHA-256 | installed SHA-256 | probe SHA-256 | status

## Declared rows
Row | type/flavor | stock | uninjected | injected | shared revision | status

## Vnode decision/removal
Held-lease target/unrelated A/B evidence:
getdirentries64 ABI/packed-record/EOF/small-buffer status:
Observed outcome: ineffective | global | target-only
Pre-removal lifecycle evidence:
Removal package/prerm evidence:
Installed daemon/job/client/setting/package absence:

## Regression and lifecycle
Landed applicable PASS/N/A/FAIL counts:
Deferred rows recorded:
Remaining rows complete:
Lifecycle VNODE-03L + backend-absent cases:
Disruptive authorization hash/reconnect result:
Jetsam: NOT-RUN | disposable evidence

## Claims and residuals
Claim | mechanism | row | raw report | driver manifest | result
Unsupported/deferred surfaces:
Release exclusions: AUD-RES-ENVIRON, AUD-RES-IOKIT-REGISTRY,
                    AUD-RES-NSFILEVERSION

## Failures and restore
Task:
Observed assertion:
Restore/rollback result:
Cleanup journal final hash/unresolved event count:
Residual device state:
```

## Source coverage audit

| Source | ID | Requirement | Tasks | Status |
|---|---|---|---|---|
| GOAL | G-01 | Target matches stock on declared surfaces without changing unrelated observers | ORA, ACT, ID, DYLD, REL | COVERED |
| REQ | SCOPE-01..06 | Original six items | mapped table above | COVERED |
| RESEARCH | VFS-01 | Correlated XPC request/reply and retained connection lifetime | VNODE-01 | COVERED |
| RESEARCH | VFS-02 | Held-lease target/unrelated raw ABI A/B is the only VISSHADOW proof | VNODE-03 | COVERED |
| RESEARCH | VFS-03 | VISSHADOW cannot satisfy per-process unchanged-observer goal | VNODE-03, VNODE-04 | COVERED |
| RESEARCH | VFS-04 | No documented Dopamine/palera1n persistent VFS hook API; KRW/kcall insufficient | CAP-01 | COVERED |
| RESEARCH | DYLD-01 | TASK_DYLD_INFO, null-array retry, callback semantics, no eight-callback cap | ORA-03, DYLD-01/02 | COVERED |
| RESEARCH | LIFE-01 | PID/start identity and connection/daemon/reboot lifecycle | VNODE-01, VNODE-03L, REL-03 | COVERED |
| CONTEXT | DEVICE-01 | Known endpoint/auth/tool/package/container facts | TOOL-01, ORA-01 | COVERED |
| CONTEXT | SAFE-01 | mobile SSH + checked sudo; no root SSH; no active-resource shadowd SIGKILL | TOOL-01, VNODE-04, REL-03 | COVERED |
| CONTEXT | EVIDENCE-01 | One driver, one stdlib validator, versioned manifests, matching nonce/revision | TOOL-01, TOOL-02 | COVERED |
| CONTEXT | RELEASE-01 | Implementation completion distinct from release validation | TOOL-02, ORA-04, CAP-01, REL-04 | COVERED |

No source item is unplanned. The removed privileged control-plane design and
zero-resource daemon SIGKILL experiment are obsolete, intentionally excluded,
and not release requirements.
