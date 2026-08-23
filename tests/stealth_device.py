#!/usr/bin/env python3
"""Device evidence driver.  The shell entrypoint deliberately only execs this."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import plistlib
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Iterable, NoReturn


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = pathlib.Path(__file__).resolve()
TASK_LABEL = re.compile(r"^[A-Z][A-Z0-9]*-[0-9]{2}[A-Z0-9]*$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
ROW_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._,-]*$")
NONCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CORE_COMMANDS = {
    "selftest", "preflight", "inventory", "import-stock", "launch",
    "pull-report", "run-hookprobe", "collect", "restore",
}
SSH_OPTIONS = (
    "-o", "StrictHostKeyChecking=no",
    "-o", "IdentitiesOnly=yes",
    "-o", "PreferredAuthentications=password",
    "-o", "PubkeyAuthentication=no",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=10",
    "-o", "ConnectionAttempts=1",
)


class DriverError(RuntimeError):
    pass


class UsageError(DriverError):
    pass


def fail(message: str) -> NoReturn:
    raise DriverError(message)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fsync_parent(path: pathlib.Path) -> None:
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_bytes(path: pathlib.Path, value: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(4)}")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        fsync_parent(path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def atomic_json(path: pathlib.Path, value: Any, mode: int = 0o600) -> None:
    atomic_bytes(
        path,
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        mode,
    )


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON object required: {path}")
    return value


def owned_regular(path: pathlib.Path) -> None:
    try:
        info = path.lstat()
    except OSError:
        fail(f"missing or unsafe anchor: {path}")
    if not path.is_file() or path.is_symlink() or info.st_uid != os.getuid():
        fail(f"missing or unsafe anchor: {path}")


def text(value: str | bytes) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def as_exit(value: Any) -> Any:
    return int(value) if isinstance(value, str) and value.isdigit() else value


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def require_token(value: str, name: str, expression: re.Pattern[str] = NONCE) -> None:
    if not expression.fullmatch(value):
        fail(f"invalid {name}")


def remote_path(value: str) -> str:
    if not value.startswith("/") or "\x00" in value or "\n" in value or "\r" in value:
        fail("unsafe remote path")
    return value


@dataclass
class Context:
    run_id: str
    evidence_rel: str
    row_id: str
    device: str
    password: str
    task_id: str
    evidence: pathlib.Path
    driver_revision: str
    task_revision: str = ""


@dataclass
class Capture:
    directory: pathlib.Path
    stdout: pathlib.Path
    stderr: pathlib.Path


@dataclass
class Result:
    code: int
    stdout: str = ""
    stderr: str = ""


class Driver:
    def __init__(self, context: Context):
        self.ctx = context
        self.capture: Capture | None = None
        self.last_transport = 0.0

    def transport_gap(self) -> None:
        # The device SSH daemon can stall a rapid follow-up session after a long query.
        try:
            gap = max(0.0, float(os.environ.get("SHADOW_SSH_GAP", "5")))
        except ValueError:
            fail("invalid SHADOW_SSH_GAP")
        delay = gap - (time.monotonic() - self.last_transport)
        if delay > 0:
            time.sleep(delay)

    @classmethod
    def from_environ(cls) -> "Driver":
        required = (
            "SHADOW_RUN_ID", "SHADOW_EVIDENCE_ROOT", "SHADOW_ROW_ID",
            "SHADOW_DEVICE", "SHADOW_DEVICE_PASSWORD", "SHADOW_TASK_ID",
        )
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            fail(f"{missing[0]} is required")
        run_id = os.environ["SHADOW_RUN_ID"]
        evidence_rel = os.environ["SHADOW_EVIDENCE_ROOT"]
        row_id = os.environ["SHADOW_ROW_ID"]
        device = os.environ["SHADOW_DEVICE"]
        password = os.environ["SHADOW_DEVICE_PASSWORD"]
        task_id = os.environ["SHADOW_TASK_ID"]
        require_token(run_id, "SHADOW_RUN_ID", RUN_ID)
        require_token(row_id, "SHADOW_ROW_ID", ROW_ID)
        if not TASK_LABEL.fullmatch(task_id):
            fail(f"invalid SHADOW_TASK_ID: {task_id}")
        expected = f"artifacts/stealth/{run_id}"
        if evidence_rel != expected:
            fail(f"SHADOW_EVIDENCE_ROOT must equal {expected}")
        user, marker, host = device.partition("@")
        if user != "mobile" or not marker or not host or any(ch.isspace() for ch in device):
            fail("SHADOW_DEVICE user must be exactly mobile")
        if "\n" in password or "\r" in password:
            fail("device password must be one line")
        evidence = (ROOT / evidence_rel).resolve()
        try:
            evidence.relative_to(ROOT / "artifacts" / "stealth")
        except ValueError:
            fail("evidence path escaped repository")
        return cls(Context(
            run_id, evidence_rel, row_id, device, password, task_id, evidence,
            worktree_revision(),
        ))

    @property
    def run_anchor(self) -> pathlib.Path:
        return self.ctx.evidence / "run.json"

    @property
    def journal(self) -> pathlib.Path:
        return self.ctx.evidence / "cleanup.jsonl"

    @property
    def task_dir(self) -> pathlib.Path:
        return self.ctx.evidence / "host" / self.ctx.task_id

    def command_path(self, name: str) -> str:
        return os.environ.get(name, name.removeprefix("SHADOW_").lower())

    def _run(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
        stdout: pathlib.Path | None = None,
        stderr: pathlib.Path | None = None,
        append: bool = False,
        timeout: int = 60,
    ) -> Result:
        opened: list[Any] = []
        try:
            out_target: Any = subprocess.PIPE if stdout is None else stdout.open("ab" if append else "wb")
            err_target: Any = subprocess.PIPE if stderr is None else stderr.open("ab" if append else "wb")
            if stdout is not None:
                opened.append(out_target)
            if stderr is not None:
                opened.append(err_target)
            try:
                options: dict[str, Any] = {
                    "text": True,
                    "stdout": out_target,
                    "stderr": err_target,
                    "env": {**os.environ, "SSHPASS": self.ctx.password},
                    "timeout": timeout,
                    "check": False,
                }
                if input_text is None:
                    options["stdin"] = subprocess.DEVNULL
                else:
                    options["input"] = input_text
                completed = subprocess.run(argv, **options)
            except subprocess.TimeoutExpired:
                return Result(124)
            return Result(
                completed.returncode,
                "" if stdout is not None else text(completed.stdout),
                "" if stderr is not None else text(completed.stderr),
            )
        except OSError as exc:
            return Result(127, "", str(exc))
        finally:
            for handle in opened:
                handle.close()

    def remote(
        self,
        command: str,
        *,
        privileged: bool = False,
        stdout: pathlib.Path | None = None,
        stderr: pathlib.Path | None = None,
        append: bool = False,
        timeout: int | None = None,
    ) -> Result:
        sshpass = os.environ.get("SHADOW_SSHPASS_BIN", "sshpass")
        ssh = os.environ.get("SHADOW_SSH_BIN", "ssh")
        wrapped = f"sh -c {shlex.quote(command)}"
        if privileged:
            wrapped = f"sudo -S -p '' {wrapped}"
        self.transport_gap()
        result = self._run(
            [sshpass, "-e", ssh, *SSH_OPTIONS, self.ctx.device, wrapped],
            input_text=self.ctx.password + "\n" if privileged else None,
            stdout=stdout,
            stderr=stderr,
            append=append,
            timeout=timeout or int(os.environ.get("SHADOW_SSH_TIMEOUT", "60")),
        )
        self.last_transport = time.monotonic()
        return result

    def scp_from(self, remote: str, destination: pathlib.Path, *, stderr: pathlib.Path | None = None) -> Result:
        remote_path(remote)
        scp = os.environ.get("SHADOW_SCP_BIN", "scp")
        sshpass = os.environ.get("SHADOW_SSHPASS_BIN", "sshpass")
        self.transport_gap()
        result = self._run(
            [sshpass, "-e", scp, *SSH_OPTIONS, f"{self.ctx.device}:{remote}", str(destination)],
            stderr=stderr,
            timeout=int(os.environ.get("SHADOW_SCP_TIMEOUT", "300")),
        )
        self.last_transport = time.monotonic()
        return result

    def scp_to(self, source: pathlib.Path, remote: str, *, stderr: pathlib.Path | None = None) -> Result:
        remote_path(remote)
        scp = os.environ.get("SHADOW_SCP_BIN", "scp")
        sshpass = os.environ.get("SHADOW_SSHPASS_BIN", "sshpass")
        self.transport_gap()
        result = self._run(
            [sshpass, "-e", scp, *SSH_OPTIONS, str(source), f"{self.ctx.device}:{remote}"],
            stderr=stderr,
            timeout=int(os.environ.get("SHADOW_SCP_TIMEOUT", "300")),
        )
        self.last_transport = time.monotonic()
        return result

    def verify_run_anchor(self, *, require_driver: bool = True) -> dict[str, Any]:
        owned_regular(self.run_anchor)
        owned_regular(self.journal)
        run = read_json(self.run_anchor)
        expected = {
            "run_id": self.ctx.run_id,
            "primary_row_id": self.ctx.row_id,
            "primary_endpoint": self.ctx.device,
            "evidence_root": self.ctx.evidence_rel,
            "primary_row_type": "jailbroken",
        }
        if require_driver:
            expected["driver_revision"] = self.ctx.driver_revision
        for key, value in expected.items():
            if run.get(key) != value:
                fail(f"run anchor mismatch: {key}")
        return run

    def build_revision_manifest(self, output: pathlib.Path) -> str:
        try:
            raw = subprocess.check_output(
                ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            fail(f"cannot enumerate worktree: {exc}")
        excluded = (
            self.ctx.evidence_rel.rstrip("/") + "/",
            "artifacts/stealth/",
            "build/",
            "packages/",
            ".theos/",
        )
        rows: list[str] = []
        for raw_path in sorted({item.decode("utf-8", "surrogateescape") for item in raw.split(b"\0") if item}):
            if raw_path.startswith(excluded):
                continue
            path = ROOT / raw_path
            if path.is_file():
                digest = sha256_file(path)
            elif path.exists():
                continue
            else:
                digest = "DELETED"
            rows.append(f"{digest}\t{raw_path}\n")
        body = "".join(rows).encode()
        atomic_bytes(output, body)
        return hashlib.sha256(body).hexdigest()

    def write_task_anchor(self) -> None:
        self.task_dir.mkdir(parents=True, exist_ok=True)
        manifest = self.task_dir / "revision.manifest"
        staged = self.task_dir / f".revision.{os.getpid()}.{secrets.token_hex(4)}"
        revision = self.build_revision_manifest(staged)
        anchor = self.task_dir / "task.json"
        if anchor.exists():
            try:
                existing = read_json(anchor)
                for key, value in {
                    "run_id": self.ctx.run_id,
                    "task_id": self.ctx.task_id,
                    "probe_revision": revision,
                }.items():
                    if existing.get(key) != value:
                        fail(f"task anchor mismatch: {key}")
            finally:
                staged.unlink(missing_ok=True)
        else:
            os.replace(staged, manifest)
            fsync_parent(manifest)
            atomic_json(anchor, {
                "schema_version": 1,
                "run_id": self.ctx.run_id,
                "task_id": self.ctx.task_id,
                "probe_revision": revision,
            })
        self.ctx.task_revision = revision

    def load_task_anchor(self) -> None:
        anchor = self.task_dir / "task.json"
        owned_regular(anchor)
        value = read_json(anchor)
        if value.get("run_id") != self.ctx.run_id or value.get("task_id") != self.ctx.task_id:
            fail("task anchor mismatch")
        revision = value.get("probe_revision")
        if not isinstance(revision, str) or not SHA256.fullmatch(revision):
            fail("task anchor mismatch: probe_revision")
        self.ctx.task_revision = revision

    def prepare_existing(self) -> dict[str, Any]:
        run = self.verify_run_anchor()
        self.write_task_anchor()
        return run

    def prepare_restore(self) -> dict[str, Any]:
        run = self.verify_run_anchor(require_driver=False)
        self.load_task_anchor()
        return run

    def capture_dir(self, nonce: str, command: str, side: str = "device") -> Capture:
        token = nonce or f"{command}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}-{secrets.token_hex(3)}"
        require_token(token, "evidence nonce")
        root = self.ctx.evidence / "host" / self.ctx.task_id if side == "host" else (
            self.ctx.evidence / "device" / self.ctx.row_id / self.ctx.task_id
        )
        directory = root / token / command
        if directory.exists() or directory.is_symlink():
            fail("evidence capture already exists")
        directory.mkdir(parents=True)
        capture = Capture(directory, directory / "stdout.txt", directory / "stderr.txt")
        capture.stdout.touch(mode=0o600)
        capture.stderr.touch(mode=0o600)
        self.capture = capture
        return capture

    def require_capture(self) -> Capture:
        if self.capture is None:
            fail("internal error: missing evidence capture")
        return self.capture

    def journal_event(self, event_id: str, action: str, target: str, prior: str, state: str) -> None:
        row = {
            "event_id": event_id,
            "action": action,
            "target": target,
            "prior_state": prior,
            "state": state,
            "timestamp": iso_now(),
        }
        fd = os.open(self.journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def new_event(self) -> str:
        return f"{self.ctx.run_id}-{self.ctx.task_id}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}-{secrets.token_hex(4)}"

    def latest_events(self) -> tuple[list[str], dict[str, dict[str, Any]]]:
        order: list[str] = []
        latest: dict[str, dict[str, Any]] = {}
        for line in self.journal.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            try:
                row = json.loads(line)
                event_id = row["event_id"]
            except (TypeError, KeyError, json.JSONDecodeError) as exc:
                fail(f"invalid cleanup journal: {exc}")
            if event_id not in latest:
                order.append(event_id)
            latest[event_id] = row
        return order, latest

    def artifact(self, role: str, path: pathlib.Path) -> dict[str, str]:
        try:
            path.resolve().relative_to(self.ctx.evidence.resolve())
        except ValueError:
            fail(f"artifact path escaped evidence: {path}")
        if not path.is_file() or path.is_symlink():
            fail(f"missing or unsafe artifact: {path}")
        return {"role": role, "path": str(path), "sha256": sha256_file(path)}

    def manifest(
        self,
        command: str,
        *,
        nonce: str = "",
        requested: str = "not-applicable",
        observed: str = "not-applicable",
        transport: Any = 0,
        producer: Any = "not-applicable",
        inventory: dict[str, Any] | None = None,
        artifacts: Iterable[tuple[str, pathlib.Path]] = (),
        source: str = "device-driver",
    ) -> pathlib.Path:
        capture = self.require_capture()
        run = read_json(self.run_anchor)
        value = {
            "schema_version": 1,
            "run_id": run["run_id"],
            "row_id": run["primary_row_id"],
            "row_type": run["primary_row_type"],
            "source": source,
            "command": command,
            "task_id": self.ctx.task_id,
            "nonce": None if nonce in {"", "not-applicable"} else nonce,
            "endpoint": run["primary_endpoint"],
            "jailbreak": run["jailbreak"],
            "os_version": run["os_version"],
            "os_build": run["os_build"],
            "architecture": run["architecture"],
            "requested_mode": requested,
            "observed_mode": observed,
            "probe_revision": self.ctx.task_revision,
            "inventory": inventory or {"components": {}},
            "artifacts": [self.artifact(role, path) for role, path in artifacts],
            "stdout": {"path": str(capture.stdout), "sha256": sha256_file(capture.stdout)},
            "stderr": {"path": str(capture.stderr), "sha256": sha256_file(capture.stderr)},
            "exit": {
                "command": as_exit(transport),
                "transport": as_exit(transport),
                "producer": as_exit(producer),
            },
            "pid": None,
            "process_start_identity": None,
            "launch": {
                "transition": "not-applicable",
                "pre_pid": None,
                "pre_lstart": None,
                "pre_state": "not-applicable",
                "post_pid": None,
                "post_lstart": None,
                "post_state": "not-applicable",
            },
            "cleanup": {
                "event_ids": [],
                "journal_sha256": None,
                "result": "not-applicable",
                "artifacts": [],
            },
            "restore": {"result": "not-applicable", "artifacts": []},
            "authorization": {"sha256": None},
            "reconnect": {
                "expected_disconnect": False,
                "elapsed_seconds": None,
                "result": "not-applicable",
            },
        }
        path = capture.directory / "manifest.json"
        atomic_json(path, value)
        return path

    def patch_manifest(self, path: pathlib.Path, **changes: Any) -> None:
        value = read_json(path)
        value.update(changes)
        atomic_json(path, value)

    def verify_device_identity(self) -> None:
        result = self.remote(
            "a=$(dpkg --print-architecture); case \"$a\" in iphoneos-arm64) printf 'arm64\\n';; *) printf '%s\\n' \"$a\";; esac; sw_vers -productVersion; sw_vers -buildVersion"
        )
        if result.code:
            fail("device identity query failed")
        run = read_json(self.run_anchor)
        expected = "\n".join((run["architecture"], run["os_version"], run["os_build"])) + "\n"
        if result.stdout != expected:
            fail("device identity changed")

    def require_host_tools(self) -> None:
        for name, default in (
            ("SHADOW_SSHPASS_BIN", "sshpass"),
            ("SHADOW_SSH_BIN", "ssh"),
            ("SHADOW_SCP_BIN", "scp"),
        ):
            command = os.environ.get(name, default)
            if not shutil.which(command):
                fail(f"missing host command: {command}")

    def capture_packages(self, required: str = "") -> tuple[dict[str, Any], list[str], pathlib.Path, pathlib.Path, list[str]]:
        capture = self.require_capture()
        status = capture.directory / "package-status.tsv"
        audit = capture.directory / "dpkg-audit.txt"
        package_script = """
for package in me.jjolano.shadow me.jjolano.shadow.harness me.jjolano.dyldprobe; do
  row=$(dpkg-query -W -f='${Version}\\t${db:Status-Status}' "$package" 2>/dev/null || true)
  if [ -n "$row" ]; then
    version=$(printf '%s\\n' "$row" | cut -f1); state=$(printf '%s\\n' "$row" | cut -f2)
    printf 'PACKAGE\\t%s\\t%s\\t%s\\n' "$package" "$version" "$state"
  else
    printf 'PACKAGE\\t%s\\tnull\\tabsent\\n' "$package"
  fi
done
dpkg-query -W -f='DPKG\\t${Package}\\t${db:Status-Status}\\n'
"""
        first = self.remote(package_script, stdout=status, stderr=capture.stderr, append=True)
        second = self.remote("dpkg --audit", privileged=True, stdout=audit, stderr=capture.stderr, append=True)
        with capture.stdout.open("ab") as handle:
            if status.exists():
                handle.write(status.read_bytes())
        packages: dict[str, Any] = {}
        states: dict[str, str] = {}
        for line in status.read_text(errors="replace").splitlines() if status.exists() else ():
            fields = line.split("\t")
            if len(fields) == 4 and fields[0] == "PACKAGE":
                packages[fields[1]] = {"version": None if fields[2] == "null" else fields[2], "status": fields[3]}
            elif len(fields) == 3 and fields[0] == "DPKG":
                states[fields[1]] = fields[2]
        expected = {
            "me.jjolano.shadow",
            "me.jjolano.shadow.harness",
            "me.jjolano.dyldprobe",
        }
        errors: list[str] = []
        if first.code or second.code:
            errors.append("package database transport failed")
        if set(packages) != expected:
            errors.append("package-status key drift")
        bad = sorted(name for name, row in packages.items() if row["status"] not in {"installed", "absent"})
        if bad:
            errors.append("package database is not ready: " + ",".join(bad))
        pending = sorted(name for name, state in states.items() if state not in {"installed", "not-installed", "config-files"})
        if pending:
            errors.append("dpkg has transitional packages: " + ",".join(pending))
        if required:
            for package in {required, "me.jjolano.shadow"}:
                if packages.get(package, {}).get("status") != "installed":
                    errors.append(f"required package is not installed: {package}")
        return packages, pending, status, audit, errors

    def preflight(self) -> pathlib.Path:
        self.require_host_tools()
        self.ctx.evidence.parent.mkdir(parents=True, exist_ok=True)
        new = not self.ctx.evidence.exists()
        if new:
            self.ctx.evidence.mkdir(mode=0o700)
            self.journal.touch(mode=0o600)
        if not self.ctx.evidence.is_dir() or self.ctx.evidence.is_symlink():
            fail("unsafe evidence root")
        if not new and not self.run_anchor.exists():
            fail("existing evidence root has no run anchor")
        capture = self.capture_dir("", "preflight")
        facts_script = """
set -eu
printf 'hardware\\t'; uname -m
printf 'architecture\\t'; a=$(dpkg --print-architecture); case "$a" in iphoneos-arm64) printf 'arm64\\n';; *) printf '%s\\n' "$a";; esac
printf 'os_version\\t'; sw_vers -productVersion
printf 'os_build\\t'; sw_vers -buildVersion
if [ -d /var/jb ]; then printf 'jailbreak_root\\t/var/jb\\n'; else printf 'jailbreak_root\\tnone\\n'; fi
printf 'scratch_writable\\t'; if [ -w /tmp ]; then printf 'yes\\n'; else printf 'no\\n'; fi
job=$(launchctl print system/me.jjolano.shadow 2>/dev/null || true)
if [ -n "$job" ]; then printf 'shadowd_job\\tpresent\\n'; else printf 'shadowd_job\\tabsent\\n'; fi
job_pid=$(printf '%s\\n' "$job" | sed -n 's/^[[:space:]]*pid = //p' | head -1)
case "$job_pid" in ''|*[!0-9]*) printf 'shadowd_pid_expected\\tfalse\\n' ;; *) printf 'shadowd_pid_expected\\ttrue\\n' ;; esac
for p in /var/mobile/Library/Preferences/me.jjolano.shadow.plist /var/jb/var/mobile/Library/Preferences/me.jjolano.shadow.plist /Library/PreferenceBundles/ShadowSettings.bundle /var/jb/Library/PreferenceBundles/ShadowSettings.bundle; do
  printf 'control\\t%s\\t' "$p"; if [ -e "$p" ]; then printf 'visible\\n'; else printf 'absent\\n'; fi
  if [ -f "$p" ]; then printf 'control_hash\\t%s\\t%s\\n' "$p" "$(sha256sum "$p" | cut -d' ' -f1)"; fi
done
for tool in uiopen sbdidlaunch uicache ldid dpkg dpkg-query plutil launchctl sha256sum find grep tr head tail cut sed sort xargs ps readlink; do
  printf 'tool.%s\\t' "$tool"; command -v "$tool" 2>/dev/null || printf 'absent'; printf '\\n'
done
for tool in appinst installipa awk pgrep sysctl; do
  printf 'absent.%s\\t' "$tool"; command -v "$tool" 2>/dev/null || printf 'absent'; printf '\\n'
done
component() {
  if [ -f "$2" ]; then printf 'component\\t%s\\tpresent\\t%s\\n' "$1" "$(sha256sum "$2" | cut -d' ' -f1)"
  else printf 'component\\t%s\\tabsent\\tnull\\n' "$1"; fi
}
component shadowd /var/jb/usr/libexec/shadowd
component ShadowCore /var/jb/usr/lib/ShadowCore.dylib
component harness /var/jb/Applications/ShadowHarness.app/ShadowHarness
component dyldprobe /var/jb/Applications/dyldprobe.app/dyldprobe
component hookprobe /var/jb/usr/bin/hookprobe
printf 'dopamine_package\\t'; dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null | grep -i dopamine | head -1 || printf 'unknown\\n'
"""
        sudo = self.remote("id -u", privileged=True, stderr=capture.stderr)
        if sudo.code or sudo.stdout.strip() != "0":
            fail("checked sudo failed")
        remote = self.remote(facts_script, stdout=capture.stdout, stderr=capture.stderr)
        if remote.code:
            atomic_json(capture.directory / "bootstrap-failure.json", {
                "command": "preflight", "status": "SETUP-FAIL", "exit": remote.code,
            })
            fail("preflight transport failed")
        packages, pending, status, audit, package_errors = self.capture_packages()
        if package_errors:
            fail("; ".join(package_errors))
        facts: dict[str, str] = {}
        controls: dict[str, str] = {}
        control_hashes: dict[str, str] = {}
        components: dict[str, Any] = {}
        for line in capture.stdout.read_text(errors="replace").splitlines():
            fields = line.split("\t")
            if len(fields) == 3 and fields[0] == "control":
                controls[fields[1]] = fields[2]
            elif len(fields) == 3 and fields[0] == "control_hash":
                control_hashes[fields[1]] = fields[2]
            elif len(fields) == 4 and fields[0] == "component":
                components[fields[1]] = {
                    "presence": fields[2],
                    "sha256": None if fields[3] == "null" else fields[3],
                }
            elif len(fields) >= 2 and not fields[0].startswith(("PACKAGE", "DPKG")):
                facts[fields[0]] = fields[1]
        required = {
            "hardware", "architecture", "os_version", "os_build", "jailbreak_root",
            "scratch_writable", "shadowd_job", "shadowd_pid_expected",
        }
        expected_components = {"shadowd", "ShadowCore", "harness", "dyldprobe", "hookprobe"}
        if not required <= set(facts):
            fail("incomplete device facts")
        if facts["jailbreak_root"] != "/var/jb":
            fail("known row is not rootless /var/jb")
        tools = {key[5:]: value for key, value in facts.items() if key.startswith("tool.")}
        absent = {key[7:]: value for key, value in facts.items() if key.startswith("absent.")}
        if any(value == "absent" for value in tools.values()):
            fail("required device tool missing")
        if set(components) != expected_components:
            fail("incomplete baseline components")
        if set(packages) != {
            "me.jjolano.shadow", "me.jjolano.shadow.harness", "me.jjolano.dyldprobe",
        } or pending:
            fail("package database is not ready")
        if not self.run_anchor.exists():
            atomic_json(self.run_anchor, {
                "schema_version": 1,
                "run_id": self.ctx.run_id,
                "primary_row_id": self.ctx.row_id,
                "primary_row_type": "jailbroken",
                "evidence_root": self.ctx.evidence_rel,
                "primary_endpoint": self.ctx.device,
                "source": "device-preflight",
                "jailbreak": {
                    "name": "Dopamine",
                    "version": facts.get("dopamine_package", "unknown"),
                    "root": facts["jailbreak_root"],
                },
                "hardware": facts["hardware"],
                "os_version": facts["os_version"],
                "os_build": facts["os_build"],
                "architecture": facts["architecture"],
                "driver_revision": self.ctx.driver_revision,
                "created_at": iso_now(),
                "tools": tools,
                "absent_tools": absent,
                "scratch_writable": facts["scratch_writable"] == "yes",
                "allowlist_controls": controls,
                "allowlist_control_hashes": control_hashes,
                "baseline_components": components,
                "baseline_packages": packages,
                "baseline_service": {
                    "shadowd_job": facts["shadowd_job"],
                    "shadowd_pid_expected": facts["shadowd_pid_expected"] == "true",
                },
            })
        self.verify_run_anchor()
        self.write_task_anchor()
        return self.manifest(
            "preflight",
            artifacts=(("device-facts", capture.stdout), ("package-status", status), ("dpkg-audit", audit)),
        )

    def _inventory_document(
        self,
        raw: pathlib.Path,
        packages: dict[str, Any],
        pending: list[str],
    ) -> tuple[dict[str, Any], list[str]]:
        rows: dict[str, list[str]] = {}
        ps_rows: list[str] = []
        in_ps = False
        ps_error = False
        shadowd_pid = ""
        for line in raw.read_text(errors="replace").splitlines():
            if line == "PS_BEGIN":
                in_ps = True
                continue
            if line == "PS_END":
                in_ps = False
                continue
            if in_ps:
                if line == "__PS_ERROR__":
                    ps_error = True
                elif line.strip():
                    ps_rows.append(line)
                continue
            fields = line.split("\t")
            if len(fields) == 2 and fields[0] == "SHADOWD_JOB_PID":
                shadowd_pid = fields[1]
            elif len(fields) == 7 and fields[0] == "FILE":
                rows[fields[1]] = fields[2:]
        keys = ("shadowd", "ShadowCore", "harness", "dyldprobe", "hookprobe")
        errors: list[str] = []
        if set(rows) != set(keys):
            errors.append("inventory component-key drift")
        expected_packages = {
            "me.jjolano.shadow",
            "me.jjolano.shadow.harness",
            "me.jjolano.dyldprobe",
        }
        if set(packages) != expected_packages:
            errors.append("inventory package-key drift")
        if pending:
            errors.append("dpkg has transitional packages")
        run = read_json(self.run_anchor)
        _, events = self.latest_events()
        hook_expected = (
            run.get("baseline_components", {}).get("hookprobe", {}).get("presence") == "present"
            or any(row.get("action") == "install-hookprobe" and row.get("state") == "completed" for row in events.values())
        )
        components: dict[str, Any] = {}
        for key in keys:
            record = rows.get(key)
            if record is None:
                continue
            expected_s, path, count_s, digest, pid_expected_s = record
            expected = expected_s == "true"
            if key == "hookprobe":
                expected = hook_expected
            pid_expected = pid_expected_s == "true"
            try:
                count = int(count_s)
            except ValueError:
                count = -1
            if count == 1:
                discovery = "one-match"
            elif count == 0 and expected:
                discovery = "zero-match"
                errors.append(f"unexpected component absence: {key}")
            elif count == 0:
                discovery = "expected-absent"
            else:
                discovery = "error"
                errors.append(f"invalid component count: {key}")
            pids: list[int] | None
            starts: list[str] | None
            if key == "ShadowCore":
                pid_status, pids, starts = "not-applicable", None, None
            elif ps_error:
                pid_status, pids, starts = "error", [], []
                errors.append("ps failed")
            else:
                found: list[tuple[int, str]] = []
                suffix = path[path.find("/Applications/"):] if "/Applications/" in path else path
                for line in ps_rows:
                    fields = line.strip().split()
                    if len(fields) < 3 or not fields[0].isdigit():
                        continue
                    command = fields[-1]
                    matches = command == path or command.endswith(suffix)
                    if key == "shadowd":
                        matches = fields[0] == shadowd_pid and command in {"(shadowd)", "shadowd", path}
                    if key == "hookprobe":
                        matches = command in {"(hookprobe)", "hookprobe", path} or command.endswith("/hookprobe")
                    if matches:
                        found.append((int(fields[0]), " ".join(fields[1:-1])))
                pids = [pid for pid, _ in found]
                starts = [start for _, start in found]
                if len(found) > 1:
                    pid_status = "error"
                    errors.append(f"ambiguous process: {key}")
                elif len(found) == 1:
                    pid_status = "one-match"
                elif pid_expected:
                    pid_status = "zero-match"
                    errors.append(f"missing process: {key}")
                else:
                    pid_status = "expected-absent"
            components[key] = {
                "key": key,
                "expected_presence": expected,
                "pid_expected": pid_expected,
                "resolved_exact_path": path if count == 1 else None,
                "discovery_status": discovery,
                "artifact_sha256": None if digest == "null" else digest,
                "pid_status": pid_status,
                "pids": pids,
                "process_start_identity": starts,
            }
        document = {
            "components": components,
            "package_database": {
                "packages": packages,
                "transitional_packages": pending,
                "dpkg_audit": "recorded",
            },
            "status": "PASS" if not errors else "FAIL",
        }
        return document, errors

    def inventory(self, preparation: str = "evidence") -> pathlib.Path:
        if preparation == "evidence":
            self.prepare_existing()
        elif preparation == "restore":
            self.prepare_restore()
        else:
            fail("invalid inventory preparation mode")
        self.verify_device_identity()
        capture = self.capture_dir("", "inventory")
        remote_script = """
set -u
file() {
  key=$1; package=$2; exact=$3; pid_expected=$4; expected=false
  if [ "$package" != none ] && dpkg-query -L "$package" 2>/dev/null | grep -F -x "$exact" >/dev/null 2>&1; then expected=true; fi
  if [ -f "$exact" ]; then count=1; else count=0; fi
  digest=null
  if [ "$count" = 1 ]; then digest=$(sha256sum "$exact" | cut -d' ' -f1); fi
  printf 'FILE\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$key" "$expected" "$exact" "$count" "$digest" "$pid_expected"
}
job=$(launchctl print system/me.jjolano.shadow 2>/dev/null || true)
job_pid=$(printf '%s\\n' "$job" | sed -n 's/^[[:space:]]*pid = //p' | head -1)
case "$job_pid" in ''|*[!0-9]*) shadowd_pid=false ;; *) shadowd_pid=true ;; esac
printf 'SHADOWD_JOB_PID\\t%s\\n' "$job_pid"
file shadowd me.jjolano.shadow /var/jb/usr/libexec/shadowd "$shadowd_pid"
file ShadowCore me.jjolano.shadow /var/jb/usr/lib/ShadowCore.dylib false
file harness me.jjolano.shadow.harness /var/jb/Applications/ShadowHarness.app/ShadowHarness false
file dyldprobe me.jjolano.dyldprobe /var/jb/Applications/dyldprobe.app/dyldprobe false
file hookprobe none /var/jb/usr/bin/hookprobe false
printf 'PS_BEGIN\\n'
ps -ax -o pid=,lstart=,comm= 2>/dev/null || printf '__PS_ERROR__\\n'
printf 'PS_END\\n'
"""
        transport = self.remote(remote_script, stdout=capture.stdout, stderr=capture.stderr).code
        packages: dict[str, Any] = {}
        pending: list[str] = []
        status = capture.directory / "package-status.tsv"
        audit = capture.directory / "dpkg-audit.txt"
        package_errors: list[str] = []
        if transport == 0:
            packages, pending, status, audit, package_errors = self.capture_packages()
        if transport:
            inventory = {"components": {}, "status": "SETUP-FAIL"}
            errors = ["inventory transport failed"]
        else:
            inventory, errors = self._inventory_document(capture.stdout, packages, pending)
            errors.extend(package_errors)
        inventory_file = capture.directory / "inventory.json"
        atomic_json(inventory_file, inventory)
        artifacts: list[tuple[str, pathlib.Path]] = [("inventory", inventory_file)]
        if status.exists():
            artifacts.append(("package-status", status))
        if audit.exists():
            artifacts.append(("dpkg-audit", audit))
        manifest = self.manifest(
            "inventory",
            transport=transport,
            producer=0,
            inventory=inventory,
            artifacts=artifacts,
        )
        if errors:
            fail("inventory failed: " + "; ".join(errors))
        return manifest

    def import_stock(self, report: str, metadata: str) -> pathlib.Path:
        self.prepare_existing()
        report_path = pathlib.Path(report).resolve()
        metadata_path = pathlib.Path(metadata).resolve()
        for path in (report_path, metadata_path):
            owned_regular(path)
        raw = read_json(report_path)
        meta = read_json(metadata_path)
        required = {
            "row_id", "row_type", "os_version", "os_build", "architecture",
            "jailbreak", "nonce", "probe_revision", "producer",
            "artifact_sha256", "collection_source",
        }
        if not required <= set(meta):
            fail("stock metadata missing fields")
        if meta["row_type"] != "stock" or meta["jailbreak"] != "none":
            fail("invalid stock provenance")
        if (
            raw.get("run_id") != self.ctx.run_id
            or raw.get("row_id") != meta["row_id"]
            or raw.get("row_type") != "stock"
            or raw.get("requested_mode") != "stock"
        ):
            fail("stock report provenance mismatch")
        for key in ("nonce", "probe_revision", "producer"):
            if raw.get(key) != meta.get(key):
                fail(f"stock {key} mismatch")
        if raw.get("probe_revision") != self.ctx.task_revision:
            fail("stock task revision mismatch")
        if sha256_file(report_path) != meta["artifact_sha256"]:
            fail("stock artifact hash mismatch")
        if not isinstance(raw.get("observations"), (dict, list)) or "canary" not in raw or "producer_exit" not in raw:
            fail("stock report schema mismatch")
        row, nonce = str(meta["row_id"]), str(meta["nonce"])
        require_token(row, "stock row ID", ROW_ID)
        require_token(nonce, "stock nonce")
        directory = self.ctx.evidence / "device" / row / self.ctx.task_id / nonce / "import-stock"
        if directory.exists() or directory.is_symlink():
            fail("evidence capture already exists")
        directory.mkdir(parents=True)
        capture = Capture(directory, directory / "stdout.txt", directory / "stderr.txt")
        capture.stdout.touch(mode=0o600)
        capture.stderr.touch(mode=0o600)
        self.capture = capture
        copied_report, copied_meta = directory / "raw-report.json", directory / "metadata.json"
        atomic_bytes(copied_report, report_path.read_bytes())
        atomic_bytes(copied_meta, metadata_path.read_bytes())
        document = {
            "schema_version": 1,
            "run_id": self.ctx.run_id,
            "row_id": row,
            "row_type": "stock",
            "source": "manual-stock",
            "command": "import-stock",
            "task_id": self.ctx.task_id,
            "nonce": nonce,
            "endpoint": "not-applicable",
            "jailbreak": {"name": "none", "version": "none"},
            "os_version": meta["os_version"],
            "os_build": meta["os_build"],
            "architecture": meta["architecture"],
            "requested_mode": "stock",
            "observed_mode": "stock",
            "probe_revision": meta["probe_revision"],
            "inventory": {"components": {}},
            "artifacts": [self.artifact("raw-report", copied_report), self.artifact("stock-metadata", copied_meta)],
            "stdout": {"path": str(capture.stdout), "sha256": sha256_file(capture.stdout)},
            "stderr": {"path": str(capture.stderr), "sha256": sha256_file(capture.stderr)},
            "exit": {"command": 0, "transport": "not-applicable", "producer": 0},
            "pid": None,
            "process_start_identity": None,
            "launch": {
                "transition": "not-applicable", "pre_pid": None, "pre_lstart": None,
                "pre_state": "not-applicable", "post_pid": None, "post_lstart": None,
                "post_state": "not-applicable",
            },
            "cleanup": {
                "event_ids": [], "journal_sha256": sha256_file(self.journal),
                "result": "not-applicable", "artifacts": [],
            },
            "restore": {"result": "not-applicable", "artifacts": []},
            "authorization": {"sha256": None},
            "reconnect": {"expected_disconnect": False, "elapsed_seconds": None, "result": "not-applicable"},
        }
        destination = directory / "manifest.json"
        atomic_json(destination, document)
        return destination

    @staticmethod
    def executable(bundle: str) -> str:
        values = {
            "me.jjolano.shadow.harness": "/var/jb/Applications/ShadowHarness.app/ShadowHarness",
            "me.jjolano.dyldprobe": "/var/jb/Applications/dyldprobe.app/dyldprobe",
        }
        try:
            return values[bundle]
        except KeyError:
            fail(f"unsupported bundle ID: {bundle}")

    def preferences_remote(self) -> str:
        result = self.remote("test -d /var/jb", privileged=True)
        if result.code == 0:
            return "/var/jb/var/mobile/Library/Preferences/me.jjolano.shadow.plist"
        return "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"

    def current_mode(self, bundle: str) -> str:
        remote = self.preferences_remote()
        fd, name = tempfile.mkstemp(prefix="shadow-prefs-", suffix=".plist")
        os.close(fd)
        path = pathlib.Path(name)
        try:
            if self.scp_from(remote, path).code:
                fail("cannot determine requested mode")
            with path.open("rb") as handle:
                app = plistlib.load(handle).get(bundle, {})
            if not isinstance(app, dict):
                fail("preferences app entry is not a dictionary")
            return "uninjected" if app.get("App_Disabled") else "injected" if app.get("App_Enabled") else "uninjected"
        except (OSError, plistlib.InvalidFileException) as exc:
            fail(f"cannot determine requested mode: {exc}")
        finally:
            path.unlink(missing_ok=True)

    def launch_mode(self, bundle: str) -> str:
        # One-shot controls must not rewrite cached device preferences.
        mode = os.environ.get("SHADOW_LAUNCH_MODE", "")
        if mode:
            if mode not in {"injected", "uninjected"}:
                fail("invalid SHADOW_LAUNCH_MODE")
            return mode
        return self.current_mode(bundle)

    def find_process(self, executable: str) -> tuple[int, str, str, str] | None:
        result = self.remote("ps -ax -o pid=,lstart=,state=,comm=")
        if result.code:
            fail("process discovery failed")
        suffix = executable[executable.find("/Applications/"):] if "/Applications/" in executable else executable
        found: list[tuple[int, str, str, str]] = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0].isdigit() and (parts[-1] == executable or parts[-1].endswith(suffix)):
                found.append((int(parts[0]), " ".join(parts[1:-2]), parts[-2], parts[-1]))
        exact = [row for row in found if row[3] == executable]
        if len(exact) == 1:
            return exact[0]
        if len(found) > 1:
            fail("process discovery is ambiguous")
        return found[0] if found else None

    def process_state(self, pid: int, lstart: str, command: str) -> str:
        current = self.find_process(command)
        if current is None:
            return "absent"
        current_pid, current_start, _, current_command = current
        if current_pid != pid:
            return "absent"
        if current_start != lstart:
            return "reused"
        return "live" if current_command == command else "changed"

    def terminate_process(self, record: tuple[int, str, str, str]) -> None:
        pid, lstart, _, command = record
        current = self.find_process(command)
        if current is None or current[:2] != (pid, lstart):
            fail("process identity changed before termination")
        event = self.new_event()
        prior = f"{lstart}|{command}"
        self.journal_event(event, "launch-terminate", str(pid), prior, "pending")
        if self.remote(f"kill -TERM {pid}", privileged=True).code:
            fail("process termination failed")
        for _ in range(10):
            state = self.process_state(pid, lstart, command)
            if state in {"absent", "reused"}:
                self.journal_event(event, "launch-terminate", str(pid), prior, "completed")
                self.journal_event(event, "launch-terminate", str(pid), prior, "restored")
                return
            if state != "live":
                fail("process identity changed during termination")
            time.sleep(1)
        fail("process did not terminate cleanly")

    def container_for_bundle(self, bundle: str) -> str:
        script = """
for f in /var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist; do
  [ -f "$f" ] || continue
  id=$(plutil -key MCMMetadataIdentifier "$f" 2>/dev/null || true)
  directory=$(dirname "$f")
  printf '%s\\t%s\\n' "$id" "$directory"
done
"""
        result = self.remote(script)
        if result.code:
            fail("container discovery failed")
        matches = [path for line in result.stdout.splitlines() if "\t" in line
                   for ident, path in [line.split("\t", 1)] if ident == bundle]
        if len(matches) != 1 or not matches[0].startswith("/var/mobile/Containers/Data/Application/"):
            fail(f"expected one container, found {len(matches)}")
        return matches[0]

    @staticmethod
    def documents_for_bundle(bundle: str, container: str) -> str:
        return "/var/mobile/Documents" if bundle == "me.jjolano.shadow.harness" else f"{container}/Documents"

    @staticmethod
    def report_name(bundle: str, nonce: str) -> str:
        return f"ShadowDiagnostics-{nonce}.json" if bundle == "me.jjolano.shadow.harness" else f"dyldprobe-{nonce}.json"

    def write_launch_context(
        self,
        bundle: str,
        mode: str,
        nonce: str,
        documents: str,
        stress: str = "",
    ) -> pathlib.Path:
        capture = self.require_capture()
        local = capture.directory / "stealth-context.json"
        value: dict[str, Any] = {
            "schema_version": 1,
            "run_id": self.ctx.run_id,
            "row_id": self.ctx.row_id,
            "requested_mode": mode,
            "nonce": nonce,
            "probe_revision": self.ctx.task_revision,
        }
        forced = os.environ.get("SHADOW_FORCE_FAILURE_ID", "")
        if len(forced) > 200 or "\n" in forced or "\r" in forced:
            fail("forced failure ID is invalid")
        if forced:
            value["force_failure_id"] = forced
        if stress:
            value["dyld_stress_library"] = stress
        atomic_json(local, value)
        remote = f"{documents}/.ShadowStealthContext.json"
        exists = self.remote(f"test -e {shlex.quote(remote)}")
        backup = capture.directory / "stealth-context.before.json"
        if exists.code == 0:
            if self.remote(f"test -f {shlex.quote(remote)} && test ! -L {shlex.quote(remote)}").code:
                fail("unsafe existing launch context file")
            if self.scp_from(remote, backup, stderr=capture.stderr).code:
                fail("cannot back up launch context file")
            prior = f"{backup}|{remote}"
        else:
            prior = f"absent|{remote}"
        event = self.new_event()
        self.journal_event(event, "launch-context-file", remote, prior, "pending")
        if self.scp_to(local, remote, stderr=capture.stderr).code:
            fail("cannot install launch context file")
        if self.remote(f"chmod 600 {shlex.quote(remote)}").code:
            fail("cannot protect launch context file")
        remote_hash = self.remote(f"sha256sum {shlex.quote(remote)} | cut -d' ' -f1")
        if remote_hash.code or remote_hash.stdout.strip() != sha256_file(local):
            fail("launch context hash mismatch")
        self.journal_event(event, "launch-context-file", remote, prior, "completed")
        return local

    def prepare_launch_file(self, remote: str) -> str:
        if self.remote(f"test ! -e {shlex.quote(remote)}").code:
            fail("nonce launch artifact already exists")
        event = self.new_event()
        self.journal_event(event, "launch-report-file", remote, f"absent|{remote}", "pending")
        return event

    def stage_dyld_stress(self, documents: str, nonce: str) -> tuple[str, pathlib.Path]:
        target = f"{documents}/.ShadowDyldStress-{nonce}.dylib"
        source = "/var/jb/Applications/dyldprobe.app/shdwtestlib.dylib"
        if self.remote(f"test -f {shlex.quote(source)} && test ! -L {shlex.quote(source)}", privileged=True).code:
            fail("packaged dyld stress library is missing or unsafe")
        event = self.prepare_launch_file(target)
        if self.remote(
            f"install -o mobile -g mobile -m 0700 {shlex.quote(source)} {shlex.quote(target)}",
            privileged=True,
        ).code:
            fail("cannot stage dyld stress library")
        source_hash = self.remote(f"sha256sum {shlex.quote(source)} | cut -d' ' -f1", privileged=True)
        target_hash = self.remote(f"sha256sum {shlex.quote(target)} | cut -d' ' -f1")
        if source_hash.code or target_hash.code or source_hash.stdout.strip() != target_hash.stdout.strip():
            fail("staged dyld stress library hash mismatch")
        self.journal_event(event, "launch-report-file", target, f"absent|{target}", "completed")
        artifact = self.require_capture().directory / "dyld-stress.tsv"
        atomic_bytes(artifact, f"source\t{source}\ntarget\t{target}\nsha256\t{target_hash.stdout.strip()}\n".encode())
        return target, artifact

    def direct_launch(self, mode: str, executable: str, container: str, output: str) -> str:
        safe = "_MSSafeMode=1 " if mode == "uninjected" else ""
        runner = (
            f"{safe}CFFIXED_USER_HOME={shlex.quote(container)} HOME={shlex.quote(container)} "
            f"TMPDIR={shlex.quote(container + '/tmp')} {shlex.quote(executable)} "
            "--shadow-headless-producer; rc=$?; printf '__SHADOW_HEADLESS_EXIT__%s\\n' \"$rc\""
        )
        return f"nohup /var/jb/bin/sh -c {shlex.quote(runner)} </dev/null >{shlex.quote(output)} 2>&1 &"

    def patch_launch(
        self,
        manifest: pathlib.Path,
        transition: str,
        before: tuple[int, str, str, str] | None,
        after: tuple[int, str, str, str] | None,
        observed: str,
    ) -> None:
        value = read_json(manifest)
        value["launch"] = {
            "transition": transition,
            "pre_pid": before[0] if before else None,
            "pre_lstart": before[1] if before else None,
            "pre_state": before[2] if before else "absent",
            "post_pid": after[0] if after else None,
            "post_lstart": after[1] if after else None,
            "post_state": after[2] if after else "absent",
        }
        value["pid"] = after[0] if after else None
        value["process_start_identity"] = after[1] if after else None
        value["observed_mode"] = observed
        atomic_json(manifest, value)

    def launch(self, bundle: str, transition: str, nonce: str) -> pathlib.Path:
        executable = self.executable(bundle)
        if transition not in {"cold", "warm"}:
            fail("launch transition must be cold or warm")
        require_token(nonce, "nonce")
        self.prepare_existing()
        self.verify_device_identity()
        capture = self.capture_dir(nonce, "launch")
        mode = self.launch_mode(bundle)
        before = self.find_process(executable)
        if transition == "warm":
            if before is None or "T" not in before[2]:
                result = self.manifest("launch", nonce=nonce, requested=mode, observed="UNSUPPORTED")
                self.patch_launch(result, transition, before, before, "UNSUPPORTED")
                return result
        elif before is not None and before[3] == executable:
            self.terminate_process(before)
        container = self.container_for_bundle(bundle)
        documents = self.documents_for_bundle(bundle, container)
        stress, stress_artifact = "", None
        if bundle == "me.jjolano.dyldprobe" and transition == "cold":
            stress, stress_artifact = self.stage_dyld_stress(documents, nonce)
        context = self.write_launch_context(bundle, mode, nonce, documents, stress)
        report_remote = f"{documents}/{self.report_name(bundle, nonce)}"
        report_event = self.prepare_launch_file(report_remote)
        output_remote = f"{documents}/.ShadowStealthLaunch-{nonce}.log"
        output_event = self.prepare_launch_file(output_remote)
        process_event = ""
        if transition == "cold":
            process_event = self.new_event()
            self.journal_event(process_event, "launch-process", executable, f"absent|{executable}", "pending")
        command = self.direct_launch(mode, executable, container, output_remote) if transition == "cold" else f"uiopen --bundleid {shlex.quote(bundle)}"
        transport = self.remote(command, stdout=capture.stdout, stderr=capture.stderr).code
        after: tuple[int, str, str, str] | None = None
        if transport == 0:
            for _ in range(20):
                after = self.find_process(executable)
                if after is not None:
                    break
                time.sleep(1)
        if after is None:
            artifacts: list[tuple[str, pathlib.Path]] = [("launch-context", context)]
            if stress_artifact:
                artifacts.append(("dyld-stress", stress_artifact))
            if self.remote(f"test -f {shlex.quote(output_remote)} && test ! -L {shlex.quote(output_remote)}").code == 0:
                output = capture.directory / "launch-output.log"
                if self.scp_from(output_remote, output, stderr=capture.stderr).code == 0:
                    artifacts.append(("launch-output", output))
            result = self.manifest("launch", nonce=nonce, requested=mode, observed="SETUP-FAIL", transport=transport or 2, producer=0, artifacts=artifacts)
            self.patch_launch(result, transition, before, None, "SETUP-FAIL")
            fail("launched process not found")
        if transition == "warm" and before and before[:2] != after[:2]:
            fail("warm launch changed process identity")
        if transition == "cold":
            self.journal_event(process_event, "launch-process", str(after[0]), f"{after[1]}|{after[3]}", "completed")
        self.journal_event(report_event, "launch-report-file", report_remote, f"absent|{report_remote}", "completed")
        self.journal_event(output_event, "launch-report-file", output_remote, f"absent|{output_remote}", "completed")
        artifacts = [("launch-context", context)]
        if stress_artifact:
            artifacts.append(("dyld-stress", stress_artifact))
        result = self.manifest("launch", nonce=nonce, requested=mode, observed=mode, artifacts=artifacts)
        self.patch_launch(result, transition, before, after, mode)
        return result

    def validate_producer_report(self, report: pathlib.Path, nonce: str) -> dict[str, Any]:
        value = read_json(report)
        expected = {
            "nonce": nonce,
            "run_id": self.ctx.run_id,
            "row_id": self.ctx.row_id,
            "probe_revision": self.ctx.task_revision,
        }
        for key, wanted in expected.items():
            if value.get(key) != wanted:
                fail(f"report provenance mismatch: {key}")
        producer = value.get("producer_exit")
        if not isinstance(producer, int) or isinstance(producer, bool) or producer < 0:
            fail("report producer exit is invalid")
        return value

    def pull_report(self, bundle: str, relative: str, nonce: str) -> pathlib.Path:
        self.executable(bundle)
        require_token(nonce, "nonce")
        relative_path = pathlib.PurePosixPath(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts or not relative_path.parts or nonce not in relative_path.name:
            fail("unsafe relative report path")
        self.prepare_existing()
        self.verify_device_identity()
        capture = self.capture_dir(nonce, "pull-report")
        container = self.container_for_bundle(bundle)
        remote = f"{self.documents_for_bundle(bundle, container)}/{relative_path.as_posix()}"
        wait = self.remote(
            f"i=0; while [ $i -lt 30 ]; do test -f {shlex.quote(remote)} && test -r {shlex.quote(remote)} && exit 0; sleep 1; i=$((i + 1)); done; exit 1",
            stderr=capture.stderr,
        )
        if wait.code:
            mode = "not-applicable"
            try:
                mode = self.current_mode(bundle)
            except DriverError:
                pass
            try:
                process = self.find_process(self.executable(bundle))
            except DriverError:
                process = "ambiguous"
            with capture.stderr.open("a", encoding="utf-8") as handle:
                handle.write(f"nonce report not readable after 30s; process={process or 'absent'}\n")
            self.manifest("pull-report", nonce=nonce, requested=mode, observed="SETUP-FAIL", producer=2)
            fail("nonce report not readable after 30s")
        report = capture.directory / relative_path.name
        transfer = self.scp_from(remote, report, stderr=capture.stderr)
        if transfer.code:
            fail("report transfer failed")
        raw = self.validate_producer_report(report, nonce)
        mode = raw.get("requested_mode", "not-applicable")
        result = self.manifest(
            "pull-report",
            nonce=nonce,
            requested=mode,
            observed=mode,
            producer=raw["producer_exit"],
            artifacts=(("raw-report", report),),
        )
        return result

    def identity_fixture_directory(self) -> str:
        return f"/var/jb/usr/lib/.shadow-hookprobe-identity-{self.ctx.run_id}"

    def check_identity_fixtures(self) -> None:
        directory = self.identity_fixture_directory()
        script = f"""
set -eu
dir={shlex.quote(directory)}
[ -d "$dir" ] && [ ! -L "$dir" ]
[ -d "$dir/Frameworks" ] && [ ! -L "$dir/Frameworks" ]
[ -d "$dir/Frameworks/Shadow.framework" ] && [ ! -L "$dir/Frameworks/Shadow.framework" ]
for path in "$dir/copied.dylib" "$dir/symlink-target.dylib" "$dir/Shadow.dylib" "$dir/Frameworks/Shadow.framework/Shadow" "$dir/shadowcore.dylib" "$dir/ShadowCoreCompat.dylib" "$dir/late.dylib"; do
  [ -f "$path" ] && [ ! -L "$path" ]
done
[ -L "$dir/symlinked.dylib" ] && [ "$(readlink "$dir/symlinked.dylib")" = symlink-target.dylib ]
"""
        if self.remote(script, stderr=self.require_capture().stderr, append=True).code:
            fail("identity fixture setup is absent or unsafe")

    def producer_marker(self, stderr: pathlib.Path, transport: int) -> tuple[int | str, int]:
        markers = [
            line.removeprefix("__SHADOW_PRODUCER_EXIT__")
            for line in stderr.read_text(errors="replace").splitlines()
            if line.startswith("__SHADOW_PRODUCER_EXIT__")
        ]
        producer: int | str = int(markers[-1]) if markers and markers[-1].isdigit() else "not-applicable"
        if producer == "not-applicable" and transport == 0:
            transport = 125
        if producer in {126, 127}:
            transport = producer
        return producer, transport

    def invoke_hookprobe(
        self,
        mode: str,
        nonce: str,
        *,
        privileged: bool = False,
        reconnect: bool = False,
    ) -> tuple[pathlib.Path, int | str, int]:
        capture = self.require_capture()
        arguments = [
            "/var/jb/usr/bin/hookprobe",
            "--mode", mode,
            "--nonce", nonce,
            "--run-id", self.ctx.run_id,
            "--row-id", self.ctx.row_id,
            "--probe-revision", self.ctx.task_revision,
            "--requested-mode", "injected",
        ]
        if mode == "identity":
            self.check_identity_fixtures()
            arguments.extend(("--identity-fixture-dir", self.identity_fixture_directory()))
        if reconnect:
            arguments.extend(("--reconnect", "PASS"))
        command = " ".join(shlex.quote(value) for value in arguments)
        command += "; code=$?; printf '__SHADOW_PRODUCER_EXIT__%s\\n' \"$code\" >&2; exit 0"
        transport = self.remote(
            command,
            privileged=privileged,
            stdout=capture.stdout,
            stderr=capture.stderr,
        ).code
        raw = capture.directory / f"hookprobe-{nonce}.json"
        atomic_bytes(raw, capture.stdout.read_bytes())
        producer, transport = self.producer_marker(capture.stderr, transport)
        return raw, producer, transport

    def require_clean_journal(self) -> None:
        _, latest = self.latest_events()
        pending = [event for event, row in latest.items() if row.get("state") != "restored"]
        if pending:
            fail("cleanup journal has unresolved events: " + ",".join(pending))

    def disruptive_authorization(self, mode: str) -> pathlib.Path | None:
        path = self.ctx.evidence / "disruptive-authorization.json"
        if os.environ.get("SHADOW_ALLOW_DISRUPTIVE") != self.ctx.run_id:
            return None
        try:
            owned_regular(path)
            value = read_json(path)
        except DriverError:
            return None
        if (
            value.get("run_id") != self.ctx.run_id
            or value.get("row_id") != self.ctx.row_id
            or not value.get("timestamp")
            or mode not in value.get("actions", [])
        ):
            return None
        return path

    def backend_absent_snapshot(self, path: pathlib.Path) -> None:
        script = """
set -eu
job=$(launchctl print system/me.jjolano.shadow 2>/dev/null || true)
[ -z "$job" ] || exit 1
for path in /var/jb/usr/libexec/shadowd /usr/libexec/shadowd /var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger /var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger /var/jb/var/log/shadowd.log /var/log/shadowd.log; do
  [ ! -e "$path" ] || exit 1
  printf 'backend\\t%s\\tabsent\\n' "$path"
done
"""
        if self.remote(script, privileged=True, stdout=path, stderr=self.require_capture().stderr, append=True).code:
            fail("backend remains before disruptive restart")

    def springboard_snapshot(self, path: pathlib.Path) -> tuple[str, str]:
        script = """
job=$(launchctl print system/com.apple.SpringBoard 2>/dev/null || true)
pid=$(printf '%s\\n' "$job" | sed -n 's/^[[:space:]]*pid = //p' | head -1)
case "$pid" in ''|*[!0-9]*) exit 1 ;; esac
started=$(ps -p "$pid" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//')
[ -n "$started" ] || exit 1
printf 'pid\\t%s\\nlstart\\t%s\\n' "$pid" "$started"
"""
        if self.remote(script, stdout=path, stderr=self.require_capture().stderr, append=True).code:
            fail("SpringBoard identity unavailable")
        values = dict(
            line.split("\t", 1) for line in path.read_text(errors="replace").splitlines() if "\t" in line
        )
        if set(values) != {"pid", "lstart"} or not values["pid"].isdigit() or not values["lstart"]:
            fail("invalid SpringBoard identity")
        return values["pid"], values["lstart"]

    def run_disruptive_hookprobe(self, mode: str, nonce: str, authorization: pathlib.Path) -> pathlib.Path:
        capture = self.require_capture()
        before = capture.directory / "backend-before-restart.txt"
        after = capture.directory / "backend-after-restart.txt"
        spring_before = capture.directory / "springboard-before.txt"
        spring_after = capture.directory / "springboard-after.txt"
        restart_event = capture.directory / "restart-event.json"
        self.backend_absent_snapshot(before)
        start_identity = self.springboard_snapshot(spring_before)
        command = (
            "/var/jb/usr/bin/sbreload"
            if mode == "lifecycle-backend-absent-springboard-restart"
            else "launchctl reboot userspace"
        )
        event = self.new_event()
        self.journal_event(event, "lifecycle-restart", mode, "backend-absent", "pending")
        started = time.monotonic()
        restart_code = self.remote(command, privileged=True, stdout=capture.stdout, stderr=capture.stderr, append=True).code
        self.journal_event(event, "lifecycle-restart", mode, "backend-absent", "completed")
        elapsed: int | None = None
        while time.monotonic() - started < 180:
            try:
                if self.springboard_snapshot(spring_after) != start_identity:
                    elapsed = int(time.monotonic() - started)
                    break
            except DriverError:
                pass
            time.sleep(3)
        status = "PASS" if elapsed is not None else "FAIL"
        atomic_json(restart_event, {
            "schema_version": 1,
            "mode": mode,
            "cleanup_event_id": event,
            "expected_disconnect": True,
            "action_transport_exit": restart_code,
            "reconnect_elapsed_seconds": elapsed if elapsed is not None else "timeout",
            "result": status,
        })
        if elapsed is None:
            manifest = self.manifest(
                "run-hookprobe", nonce=nonce, requested="injected", observed="SETUP-FAIL",
                artifacts=(("restart-event", restart_event), ("backend-before", before), ("springboard-before", spring_before)),
            )
            value = read_json(manifest)
            value["authorization"]["sha256"] = sha256_file(authorization)
            atomic_json(manifest, value)
            fail("restart was not observed within 180 seconds")
        self.verify_device_identity()
        self.backend_absent_snapshot(after)
        restart_capture = self.capture
        inventory = self.inventory()
        self.capture = restart_capture
        self.journal_event(event, "lifecycle-restart", mode, "backend-absent", "restored")
        raw, producer, transport = self.invoke_hookprobe(mode, nonce, privileged=True, reconnect=True)
        observed = "injected" if isinstance(producer, int) and producer == 0 and transport == 0 else "SETUP-FAIL"
        manifest = self.manifest(
            "run-hookprobe",
            nonce=nonce,
            requested="injected",
            observed=observed,
            transport=transport,
            producer=producer,
            artifacts=(
                ("raw-report", raw), ("restart-event", restart_event), ("backend-before", before),
                ("backend-after", after), ("springboard-before", spring_before),
                ("springboard-after", spring_after), ("post-restart-inventory", inventory),
            ),
        )
        value = read_json(manifest)
        value["authorization"]["sha256"] = sha256_file(authorization)
        value["cleanup"] = {
            "event_ids": [event],
            "journal_sha256": sha256_file(self.journal),
            "result": "PASS",
            "artifacts": [],
        }
        value["reconnect"] = {
            "expected_disconnect": True,
            "elapsed_seconds": elapsed,
            "result": "PASS",
        }
        atomic_json(manifest, value)
        self.validate_producer_report(raw, nonce)
        if transport:
            fail("hookprobe transport/setup failed after restart")
        if producer != 0:
            fail("hookprobe reported behavioral failure after restart")
        return manifest

    def run_hookprobe(self, mode: str, nonce: str) -> pathlib.Path:
        modes = {
            "lifecycle-backend-absent",
            "lifecycle-backend-absent-springboard-restart",
            "lifecycle-backend-absent-userspace-reboot",
            "identity",
            "regression-matrix",
        }
        if mode not in modes:
            fail(f"unsupported hookprobe mode: {mode}")
        require_token(nonce, "nonce")
        self.prepare_existing()
        self.verify_device_identity()
        capture = self.capture_dir(nonce, "run-hookprobe")
        if mode.endswith(("-springboard-restart", "-userspace-reboot")):
            authorization = self.disruptive_authorization(mode)
            if authorization is None:
                capture.stdout.write_text("NOT-RUN: missing or mismatched disruptive authorization\n")
                return self.manifest("run-hookprobe", nonce=nonce, requested="injected", observed="NOT-RUN", producer=0)
            self.require_clean_journal()
            return self.run_disruptive_hookprobe(mode, nonce, authorization)
        privileged = mode == "lifecycle-backend-absent"
        raw, producer, transport = self.invoke_hookprobe(mode, nonce, privileged=privileged)
        try:
            self.validate_producer_report(raw, nonce)
        except DriverError:
            self.manifest(
                "run-hookprobe", nonce=nonce, requested="injected", observed="SETUP-FAIL",
                transport=transport, producer=producer, artifacts=(("raw-report", raw),),
            )
            raise
        manifest = self.manifest(
            "run-hookprobe", nonce=nonce, requested="injected", observed="injected",
            transport=transport, producer=producer, artifacts=(("raw-report", raw),),
        )
        if transport:
            fail("hookprobe transport/setup failed")
        if producer != 0:
            fail("hookprobe reported behavioral failure")
        return manifest

    def collect(self) -> pathlib.Path:
        self.prepare_existing()
        capture = self.capture_dir("", "collect", "host")
        errors: list[str] = []
        count = 0
        root = self.ctx.evidence.resolve()
        for manifest in root.rglob("manifest.json"):
            count += 1
            try:
                document = read_json(manifest)
            except DriverError as exc:
                errors.append(str(exc))
                continue
            for item in list(document.get("artifacts", [])) + [document.get("stdout", {}), document.get("stderr", {})]:
                if isinstance(item, dict):
                    path_text, digest = item.get("path"), item.get("sha256")
                else:
                    path_text, digest = None, None
                if not isinstance(path_text, str) or not isinstance(digest, str):
                    errors.append(f"invalid artifact row {manifest}")
                    continue
                path = pathlib.Path(path_text)
                try:
                    path.resolve().relative_to(root)
                except ValueError:
                    errors.append(f"path escape {manifest}: {path_text}")
                    continue
                if not path.is_file() or path.is_symlink() or sha256_file(path) != digest:
                    errors.append(f"artifact mismatch {manifest}: {path_text}")
        report = capture.directory / "collection.json"
        atomic_json(report, {
            "schema_version": 1,
            "manifest_count": count,
            "status": "PASS" if not errors else "FAIL",
            "errors": errors,
        })
        result = self.manifest("collect", transport=0 if not errors else 2, producer=0, artifacts=(("collection", report),))
        if errors:
            fail("evidence collection validation failed")
        return result

    def restore_preferences(self, backup: pathlib.Path, requested: str = "") -> None:
        owned_regular(backup)
        remote = requested or self.preferences_remote()
        remote_path(remote)
        if remote.startswith("/var/jb/var/mobile/Library/Preferences/"):
            owner, mode = "mobile:mobile", "0600"
        else:
            owner, mode = "root:wheel", "0644"
        temporary = f"/var/mobile/Media/.shadow-restore-prefs-{self.ctx.run_id}-{os.getpid()}-{secrets.token_hex(3)}.plist"
        capture = self.require_capture()
        if self.scp_to(backup, temporary, stderr=capture.stderr).code:
            fail("cannot upload restored preferences")
        user, group = owner.split(":", 1)
        install = (
            f"install -o {shlex.quote(user)} -g {shlex.quote(group)} -m {mode} "
            f"{shlex.quote(temporary)} {shlex.quote(remote)} && rm -f {shlex.quote(temporary)}"
        )
        if self.remote(install, privileged=True, stdout=capture.stdout, stderr=capture.stderr, append=True).code:
            fail("cannot restore preferences")
        self.remote(
            "launchctl kill SIGTERM gui/501/com.apple.cfprefsd.xpc.daemon 2>/dev/null || launchctl kill SIGTERM user/501/com.apple.cfprefsd.xpc.daemon 2>/dev/null || true"
        )
        observed = self.remote(f"sha256sum {shlex.quote(remote)} | cut -d' ' -f1")
        if observed.code or observed.stdout.strip() != sha256_file(backup):
            fail("restored preferences hash mismatch")

    def safe_bootout_for_restore(self) -> None:
        capture = self.require_capture()
        state = self.remote("launchctl print system/me.jjolano.shadow 2>/dev/null || true")
        if state.code:
            fail("restore daemon precheck failed")
        if state.stdout.strip() and self.remote(
            "launchctl bootout system/me.jjolano.shadow",
            privileged=True,
            stdout=capture.stdout,
            stderr=capture.stderr,
            append=True,
        ).code:
            fail("restore daemon bootout failed")

    def restore_package(self, prior: str) -> None:
        fields = prior.split("|")
        if len(fields) == 4:
            recovery_text, preferences_text, preference_remote, package = fields
        elif len(fields) == 3:
            recovery_text, preferences_text, package = fields
            preference_remote = ""
        else:
            fail("invalid package recovery record")
        recovery = pathlib.Path(recovery_text)
        self._evidence_regular(recovery, "package recovery artifact")
        if package == "me.jjolano.shadow":
            self.safe_bootout_for_restore()
        temporary = f"/var/mobile/Media/.shadow-rollback-{self.ctx.run_id}-{os.getpid()}.deb"
        capture = self.require_capture()
        if self.scp_to(recovery, temporary, stderr=capture.stderr).code:
            fail("cannot upload recovery package")
        remote_hash = self.remote(f"sha256sum {shlex.quote(temporary)} | cut -d' ' -f1")
        if remote_hash.code or remote_hash.stdout.strip() != sha256_file(recovery):
            fail("rollback upload hash mismatch")
        if self.remote(
            f"dpkg -i {shlex.quote(temporary)} && rm -f {shlex.quote(temporary)}",
            privileged=True,
            stdout=capture.stdout,
            stderr=capture.stderr,
            append=True,
        ).code:
            fail("rollback dpkg failed")
        try:
            host_package = subprocess.check_output(["dpkg-deb", "-f", str(recovery), "Package"], text=True).strip()
            version = subprocess.check_output(["dpkg-deb", "-f", str(recovery), "Version"], text=True).strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            fail(f"cannot inspect recovery package: {exc}")
        if host_package != package:
            fail("rollback package ID mismatch")
        query_format = "$" + "{Package} " + "$" + "{Version}"
        installed = self.remote(f"dpkg-query -W -f={shlex.quote(query_format)} {shlex.quote(package)}")
        if installed.code or installed.stdout.strip() != f"{package} {version}":
            fail("rollback package verification failed")
        preferences = pathlib.Path(preferences_text)
        if preferences_text and preferences_text != "ABSENT":
            self._evidence_regular(preferences, "package preferences backup")
            self.restore_preferences(preferences, preference_remote)

    def _evidence_regular(self, path: pathlib.Path, description: str) -> None:
        try:
            path.resolve().relative_to(self.ctx.evidence.resolve())
        except ValueError:
            fail(f"{description} escaped evidence")
        owned_regular(path)

    def restore_component(self, prior: str) -> None:
        fields = prior.split("|")
        if len(fields) != 3:
            fail("invalid component recovery record")
        backup, remote, mode = pathlib.Path(fields[0]), fields[1], fields[2]
        allowed = {
            "/var/jb/usr/lib/ShadowCore.dylib",
            "/var/jb/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib",
            "/var/jb/Applications/dyldprobe.app/dyldprobe",
        }
        if remote not in allowed or not re.fullmatch(r"0[0-7]{3}", mode):
            fail("unsafe component recovery target")
        self._evidence_regular(backup, "component backup")
        temporary = f"/var/mobile/Media/.shadow-component-restore-{self.ctx.run_id}-{os.getpid()}"
        staged = f"{remote}.new.{self.ctx.run_id}.{os.getpid()}"
        capture = self.require_capture()
        if self.scp_to(backup, temporary, stderr=capture.stderr).code:
            fail("cannot upload component backup")
        command = (
            f"install -o root -g wheel -m {mode} {shlex.quote(temporary)} {shlex.quote(staged)} && "
            f"mv -f {shlex.quote(staged)} {shlex.quote(remote)} && rm -f {shlex.quote(temporary)}"
        )
        if self.remote(command, privileged=True, stdout=capture.stdout, stderr=capture.stderr, append=True).code:
            fail("component restore failed")
        value = self.remote(f"sha256sum {shlex.quote(remote)} | cut -d' ' -f1", privileged=True)
        if value.code or value.stdout.strip() != sha256_file(backup):
            fail("restored component hash mismatch")

    def remove_identity_fixtures(self, directory: str) -> None:
        if directory != self.identity_fixture_directory():
            fail("unsafe identity fixture cleanup target")
        script = f"""
set -eu
dir={shlex.quote(directory)}
[ ! -e "$dir" ] && [ ! -L "$dir" ] && exit 0
[ -d "$dir" ] && [ ! -L "$dir" ] || exit 1
for node in $(find "$dir" -mindepth 1 -print); do
  case "$node" in
    "$dir/Frameworks"|"$dir/Frameworks/Shadow.framework"|"$dir/copied.dylib"|"$dir/symlink-target.dylib"|"$dir/symlinked.dylib"|"$dir/Shadow.dylib"|"$dir/Frameworks/Shadow.framework/Shadow"|"$dir/shadowcore.dylib"|"$dir/ShadowCoreCompat.dylib"|"$dir/late.dylib") ;;
    *) exit 1 ;;
  esac
done
[ ! -L "$dir/symlinked.dylib" ] || [ "$(readlink "$dir/symlinked.dylib")" = symlink-target.dylib ] || exit 1
rm -f "$dir/copied.dylib" "$dir/symlink-target.dylib" "$dir/symlinked.dylib" "$dir/Shadow.dylib" "$dir/Frameworks/Shadow.framework/Shadow" "$dir/shadowcore.dylib" "$dir/ShadowCoreCompat.dylib" "$dir/late.dylib"
rmdir "$dir/Frameworks/Shadow.framework" 2>/dev/null || true
rmdir "$dir/Frameworks" 2>/dev/null || true
rmdir "$dir"
"""
        capture = self.require_capture()
        if self.remote(script, privileged=True, stdout=capture.stdout, stderr=capture.stderr, append=True).code:
            fail("identity fixture cleanup failed")

    def restore_launch_process(self, target: str, prior: str) -> None:
        if target.isdigit() and int(target) > 0:
            fields = prior.split("|", 1)
            if len(fields) != 2:
                fail("invalid launched process identity")
            pid, lstart, command = int(target), fields[0], fields[1]
            for _ in range(10):
                state = self.process_state(pid, lstart, command)
                if state in {"absent", "reused"}:
                    return
                if state != "live":
                    fail("launched process identity changed during restore")
                if self.remote(f"kill -TERM {pid}", privileged=True).code:
                    fail("launched process termination failed during restore")
                time.sleep(1)
            fail("launched process did not terminate during restore")
        current = self.find_process(target)
        if current is not None:
            self.terminate_process(current)

    def apply_mode_repair(self, manifest: pathlib.Path) -> None:
        self._evidence_regular(manifest, "mode repair manifest")
        rows: list[tuple[str, str, str, str]] = []
        for line in manifest.read_text(encoding="utf-8").splitlines():
            fields = line.split("\t")
            if len(fields) != 5 or fields[0] != "F":
                fail("invalid mode repair manifest row")
            _, digest, source, target, path = fields
            if not SHA256.fullmatch(digest) or not re.fullmatch(r"0[0-7]{3}", source) or not re.fullmatch(r"0[0-7]{3}", target) or not path.startswith("/var/jb/"):
                fail("invalid mode repair manifest row")
            rows.append((digest, source, target, path))
        if not rows or len({row[3] for row in rows}) != len(rows):
            fail("invalid mode repair manifest")
        command = " ".join(
            f"test -f {shlex.quote(path)} && test ! -L {shlex.quote(path)} && "
            f"test \"$(sha256sum {shlex.quote(path)} | cut -d' ' -f1)\" = {shlex.quote(digest)} && "
            f"chmod {target} {shlex.quote(path)} || exit 1;"
            for digest, _, target, path in rows
        )
        capture = self.require_capture()
        if self.remote(command, privileged=True, stdout=capture.stdout, stderr=capture.stderr, append=True).code:
            fail("mode repair apply failed")
        for digest, _, target, path in rows:
            state = self.remote(
                f"sha256sum {shlex.quote(path)} | cut -d' ' -f1; stat -c %a {shlex.quote(path)}",
                privileged=True,
            )
            values = state.stdout.splitlines()
            if state.code or len(values) != 2 or values[0] != digest or values[1] != target[1:]:
                fail("mode repair verification failed")

    def maybe_repair_mode_loss(self) -> pathlib.Path | None:
        if os.environ.get("SHADOW_ALLOW_MODE_REPAIR") != self.ctx.run_id:
            return None
        order, latest = self.latest_events()
        lineage: tuple[pathlib.Path, pathlib.Path] | None = None
        for event in reversed(order):
            row = latest[event]
            if row.get("action") != "install-deb":
                continue
            fields = str(row.get("prior_state", "")).split("|")
            if len(fields) == 4 and fields[3] == "me.jjolano.shadow":
                lineage = pathlib.Path(fields[0]), pathlib.Path(str(row.get("target", "")))
                break
        if lineage is None:
            fail("mode repair lineage is unavailable")
        recovery, candidate = lineage
        self._evidence_regular(recovery, "mode repair recovery archive")
        self._evidence_regular(candidate, "mode repair candidate archive")
        with tempfile.TemporaryDirectory(prefix="shadow-mode-repair-") as temporary:
            base = pathlib.Path(temporary)
            before, template = base / "recovery", base / "candidate"
            for archive, target in ((recovery, before), (candidate, template)):
                if subprocess.run(["dpkg-deb", "-x", str(archive), str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
                    fail("cannot unpack mode repair archive")
            def files(root: pathlib.Path) -> dict[str, tuple[int, str]]:
                return {
                    "/" + path.relative_to(root).as_posix(): (path.stat().st_mode & 0o777, sha256_file(path))
                    for path in root.rglob("*") if path.is_file() and not path.is_symlink()
                }
            old, new = files(before), files(template)
            legacy = {"/var/jb/usr/libexec/shadowd", "/var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist"}
            if set(new) - set(old) or (set(old) - set(new) and set(old) - set(new) != legacy):
                fail("mode repair archive paths do not match recovery contract")
            rows: list[str] = []
            for path, (source_mode, digest) in sorted(old.items()):
                if source_mode not in {0o600, 0o700}:
                    fail("recovery mode is not an umask-loss signature")
                target_mode = 0o755 if source_mode & 0o100 else 0o644
                if path in new and new[path][0] != target_mode:
                    fail("candidate mode template disagrees")
                rows.append(f"F\t{digest}\t{source_mode:04o}\t{target_mode:04o}\t{path}\n")
        manifest = self.require_capture().directory / "mode-repair.tsv"
        atomic_bytes(manifest, "".join(rows).encode())
        event = self.new_event()
        self.journal_event(event, "mode-repair", "me.jjolano.shadow", str(manifest), "pending")
        self.apply_mode_repair(manifest)
        self.journal_event(event, "mode-repair", "me.jjolano.shadow", str(manifest), "completed")
        self.journal_event(event, "mode-repair", "me.jjolano.shadow", str(manifest), "restored")
        return manifest

    def restore_event(self, row: dict[str, Any]) -> None:
        event = str(row.get("event_id", ""))
        action = str(row.get("action", ""))
        target = str(row.get("target", ""))
        prior = str(row.get("prior_state", ""))
        capture = self.require_capture()
        if not event:
            fail("invalid cleanup journal event")
        if action in {"set-mode", "launch-context"}:
            fields = prior.split("|", 1)
            if len(fields) != 2:
                fail("invalid preferences recovery record")
            self.restore_preferences(pathlib.Path(fields[0]), fields[1])
        elif action == "launch-context-file":
            fields = prior.split("|", 1)
            if len(fields) != 2 or not fields[1].endswith("/.ShadowStealthContext.json"):
                fail("unsafe launch context recovery target")
            backup, remote = fields
            if backup == "absent":
                if self.remote(f"rm -f {shlex.quote(remote)}", stdout=capture.stdout, stderr=capture.stderr, append=True).code:
                    fail("launch context cleanup failed")
            else:
                source = pathlib.Path(backup)
                self._evidence_regular(source, "launch context backup")
                if self.scp_to(source, remote, stderr=capture.stderr).code or self.remote(f"chmod 600 {shlex.quote(remote)}").code:
                    fail("launch context restore failed")
        elif action == "launch-report-file":
            fields = prior.split("|", 1)
            if len(fields) != 2 or fields[0] != "absent":
                fail("invalid launch report recovery record")
            remote = fields[1]
            if not remote.startswith(("/var/mobile/Documents/", "/var/mobile/Containers/Data/Application/")):
                fail("unsafe launch report recovery target")
            if self.remote(f"test -e {shlex.quote(remote)}").code == 0:
                if self.remote(f"test -f {shlex.quote(remote)} && test ! -L {shlex.quote(remote)}").code:
                    fail("unsafe launch report during restore")
                if self.remote(f"rm -f {shlex.quote(remote)}", stdout=capture.stdout, stderr=capture.stderr, append=True).code:
                    fail("launch report cleanup failed")
        elif action == "install-hookprobe":
            fields = prior.split("|", 1)
            if len(fields) != 2 or fields[1] != "/var/jb/usr/bin/hookprobe":
                fail("unsafe hookprobe recovery target")
            backup, remote = fields
            if backup == "absent":
                if self.remote(f"rm -f {shlex.quote(remote)}", privileged=True, stdout=capture.stdout, stderr=capture.stderr, append=True).code:
                    fail("hookprobe removal failed")
            else:
                source = pathlib.Path(backup)
                self._evidence_regular(source, "hookprobe backup")
                temporary = f"/var/mobile/Media/.hookprobe-restore-{self.ctx.run_id}-{os.getpid()}"
                if self.scp_to(source, temporary, stderr=capture.stderr).code or self.remote(
                    f"install -o root -g wheel -m 0755 {shlex.quote(temporary)} {shlex.quote(remote)} && rm -f {shlex.quote(temporary)}",
                    privileged=True,
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    append=True,
                ).code:
                    fail("hookprobe restore failed")
        elif action == "install-hookprobe-fixtures":
            if prior != "absent":
                fail("invalid identity fixture recovery record")
            self.remove_identity_fixtures(target)
        elif action == "install-component":
            self.restore_component(prior)
        elif action == "mode-repair":
            self.apply_mode_repair(pathlib.Path(prior))
        elif action == "install-deb":
            self.restore_package(prior)
        elif action in {"package-upload", "recovery-export"}:
            if not target.startswith("/var/mobile/Media/.shadow-"):
                fail("unsafe package temporary cleanup target")
            if self.remote(f"rm -f {shlex.quote(target)}", privileged=True, stdout=capture.stdout, stderr=capture.stderr, append=True).code:
                fail("package temporary cleanup failed")
        elif action == "daemon-bootout":
            launcher = "/var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist"
            if self.remote(f"test -f {shlex.quote(launcher)}", privileged=True).code == 0 and self.remote(
                f"launchctl bootstrap system {shlex.quote(launcher)} 2>/dev/null || launchctl kickstart system/me.jjolano.shadow",
                privileged=True,
                stdout=capture.stdout,
                stderr=capture.stderr,
                append=True,
            ).code:
                fail("daemon rebootstrap failed")
        elif action in {"daemon-idle", "lifecycle-restart", "launch-terminate"}:
            pass
        elif action == "launch-process":
            self.restore_launch_process(target, prior)
        elif action == "client-sigkill":
            fields = prior.split("|", 1)
            if not target.isdigit() or len(fields) != 2:
                fail("invalid client SIGKILL recovery record")
            state = self.process_state(int(target), fields[0], fields[1])
            if state not in {"absent", "reused"}:
                fail("client SIGKILL target remains live or changed during restore")
        else:
            fail(f"unknown cleanup action: {action}")
        self.journal_event(event, action, target, prior, "restored")

    def verify_restore_baseline(self, inventory: pathlib.Path) -> None:
        run = read_json(self.run_anchor)
        document = read_json(inventory)
        rows = document.get("inventory", {}).get("components", {})
        for key, baseline in run.get("baseline_components", {}).items():
            row = rows.get(key)
            if not isinstance(row, dict):
                fail(f"restore inventory missing component: {key}")
            present = row.get("discovery_status") == "one-match"
            if present != (baseline.get("presence") == "present"):
                fail(f"restore presence mismatch: {key}")
            if present and row.get("artifact_sha256") != baseline.get("sha256"):
                fail(f"restore hash mismatch: {key}")
        if document.get("inventory", {}).get("package_database", {}).get("packages") != run.get("baseline_packages"):
            fail("restore package-state mismatch")

    def restore(self) -> pathlib.Path:
        run = self.prepare_restore()
        self.verify_device_identity()
        capture = self.capture_dir("", "restore")
        order, latest = self.latest_events()
        for event in reversed(order):
            row = latest[event]
            if row.get("state") != "restored":
                self.restore_event(row)
        repair = self.maybe_repair_mode_loss()
        if run.get("baseline_service", {}).get("shadowd_job") == "present":
            job = self.remote("launchctl print system/me.jjolano.shadow 2>/dev/null || true")
            if not job.stdout.strip():
                launcher = "/var/jb/Library/LaunchDaemons/me.jjolano.shadow.plist"
                if self.remote(f"test -f {shlex.quote(launcher)}", privileged=True).code:
                    fail("baseline shadowd launchd plist missing")
                if self.remote(
                    f"launchctl bootstrap system {shlex.quote(launcher)} 2>/dev/null || launchctl kickstart system/me.jjolano.shadow",
                    privileged=True,
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    append=True,
                ).code:
                    fail("restore daemon rebootstrap failed")
        elif run.get("baseline_service", {}).get("shadowd_job") == "absent":
            job = self.remote("launchctl print system/me.jjolano.shadow 2>/dev/null || true")
            if job.stdout.strip():
                fail("restore daemon job differs from baseline")
        else:
            fail("invalid baseline shadowd service state")
        inventory_capture = self.capture
        inventory = self.inventory("restore")
        self.capture = inventory_capture
        self.verify_restore_baseline(inventory)
        artifacts: list[tuple[str, pathlib.Path]] = [("final-inventory", inventory)]
        if repair is not None:
            artifacts.append(("mode-repair", repair))
        manifest = self.manifest("restore", artifacts=artifacts)
        value = read_json(manifest)
        value["restore"]["result"] = "PASS"
        atomic_json(manifest, value)
        return manifest


def selftest() -> None:
    expected = {
        "selftest", "preflight", "inventory", "import-stock", "launch",
        "pull-report", "run-hookprobe", "collect", "restore",
    }
    assert CORE_COMMANDS == expected
    assert TASK_LABEL.fullmatch("NOVA-12A")
    assert TASK_LABEL.fullmatch("ORA-02")
    assert not TASK_LABEL.fullmatch("nova-12A")
    assert not TASK_LABEL.fullmatch("NOVA-2")
    with tempfile.TemporaryDirectory(prefix="shadow-device-selftest-") as temporary:
        evidence = pathlib.Path(temporary) / "evidence"
        evidence.mkdir()
        journal = evidence / "cleanup.jsonl"
        journal.touch()
        revision = "a" * 64
        atomic_json(evidence / "run.json", {
            "run_id": "run",
            "primary_row_id": "row",
            "primary_endpoint": "mobile@host",
            "evidence_root": "artifacts/stealth/run",
            "primary_row_type": "jailbroken",
            "driver_revision": "old-driver",
            "jailbreak": {"name": "Dopamine", "root": "/var/jb"},
            "os_version": "1",
            "os_build": "a",
            "architecture": "arm64",
            "baseline_components": {},
            "baseline_packages": {},
            "baseline_service": {"shadowd_job": "absent"},
        })
        task = evidence / "host" / "NOVA-12A"
        task.mkdir(parents=True)
        atomic_json(task / "task.json", {
            "schema_version": 1, "run_id": "run", "task_id": "NOVA-12A", "probe_revision": revision,
        })
        driver = Driver(Context(
            "run", "artifacts/stealth/run", "row", "mobile@host", "x",
            "NOVA-12A", evidence, "new-driver",
        ))
        driver.prepare_restore()
        assert driver.ctx.task_revision == revision
        try:
            driver.prepare_existing()
        except DriverError:
            pass
        else:
            raise AssertionError("new evidence accepted stale driver")
        prior_mode = os.environ.get("SHADOW_LAUNCH_MODE")
        try:
            os.environ["SHADOW_LAUNCH_MODE"] = "uninjected"
            assert driver.launch_mode("unused") == "uninjected"
            os.environ["SHADOW_LAUNCH_MODE"] = "invalid"
            try:
                driver.launch_mode("unused")
            except DriverError:
                pass
            else:
                raise AssertionError("invalid launch-mode override accepted")
        finally:
            if prior_mode is None:
                os.environ.pop("SHADOW_LAUNCH_MODE", None)
            else:
                os.environ["SHADOW_LAUNCH_MODE"] = prior_mode
        revision_manifest = pathlib.Path(temporary) / "revision.manifest"
        driver.build_revision_manifest(revision_manifest)
        rows = revision_manifest.read_text(encoding="utf-8")
        assert "\ttests/stealth_device.py\n" in rows
        assert "\ttests/stealth-device.sh\n" in rows
        marker = pathlib.Path(temporary) / "marker.txt"
        marker.write_text("__SHADOW_PRODUCER_EXIT__0\n", encoding="utf-8")
        assert driver.producer_marker(marker, 0) == (0, 0)
        marker.write_text("no producer marker\n", encoding="utf-8")
        assert driver.producer_marker(marker, 0) == ("not-applicable", 125)
        assert driver._run(["/bin/sh", "-c", "read value; test \"$value\" = x"], input_text="x\n").code == 0
    print("PASS stealth-device selftest (dynamic task labels, full-worktree provenance, restore compatibility)")


def usage() -> None:
    print(
        "usage: tests/stealth-device.sh {selftest|preflight|inventory|import-stock|launch|pull-report|run-hookprobe|collect|restore}",
        file=sys.stderr,
    )


def dispatch(argv: list[str]) -> int:
    if not argv or argv[0] not in CORE_COMMANDS:
        raise UsageError("invalid command")
    command, arguments = argv[0], argv[1:]
    if command == "selftest":
        if arguments:
            raise UsageError("selftest takes no arguments")
        selftest()
        return 0
    driver = Driver.from_environ()
    if command == "preflight" and not arguments:
        result = driver.preflight()
    elif command == "inventory" and not arguments:
        result = driver.inventory()
    elif command == "import-stock" and len(arguments) == 2:
        result = driver.import_stock(*arguments)
    elif command == "launch" and len(arguments) == 3:
        result = driver.launch(*arguments)
    elif command == "pull-report" and len(arguments) == 3:
        result = driver.pull_report(*arguments)
    elif command == "run-hookprobe" and len(arguments) == 2:
        result = driver.run_hookprobe(*arguments)
    elif command == "collect" and not arguments:
        result = driver.collect()
    elif command == "restore" and not arguments:
        result = driver.restore()
    else:
        raise UsageError("invalid command arguments")
    print(result)
    return 0


def main(argv: list[str]) -> int:
    try:
        return dispatch(argv)
    except UsageError:
        usage()
        return 64
    except (DriverError, AssertionError) as exc:
        print(f"stealth-device: {exc}", file=sys.stderr)
        return 1


def worktree_revision() -> str:
    rows = []
    for path in (SCRIPT, SCRIPT.with_name("stealth-device.sh")):
        if path.is_file():
            rows.append(f"{path.name}\t{sha256_file(path)}\n")
    return hashlib.sha256("".join(sorted(rows)).encode()).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
