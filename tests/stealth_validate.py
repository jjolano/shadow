#!/usr/bin/env python3
"""Validate Shadow stealth evidence without third-party dependencies."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any


RAW_KEYS = {
    "schema_version", "producer", "run_id", "row_id", "row_type",
    "requested_mode", "nonce", "probe_revision", "canary", "observations",
    "producer_exit",
}
SCOPE_KEYS = {
    "schema_version", "scope_id", "run_id", "task_revisions",
    "required_task_ids", "case_ids", "regression_ids", "row_ids",
}
MANIFEST_KEYS = {
    "schema_version", "run_id", "row_id", "row_type", "source", "command",
    "nonce", "endpoint", "task_id", "jailbreak", "os_version", "os_build",
    "architecture", "requested_mode", "observed_mode", "probe_revision",
    "inventory", "artifacts", "stdout", "stderr", "exit", "pid",
    "process_start_identity", "launch", "cleanup", "restore", "authorization",
    "reconnect",
}
COMPONENT_KEYS = {"shadowd", "ShadowCore", "harness", "dyldprobe", "hookprobe"}


class Invalid(Exception):
    pass


class Legacy(Exception):
    pass


def read_json(path: os.PathLike[str] | str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Invalid(f"invalid JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise Invalid(f"JSON object required: {path}")
    return value


def digest(path: os.PathLike[str] | str) -> str:
    try:
        return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    except OSError as exc:
        raise Invalid(f"unreadable artifact {path}: {exc}") from exc


def require(condition: Any, message: str) -> None:
    if not condition:
        raise Invalid(message)


def exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    require(set(value) == expected, f"{name} field drift")


def passing(value: Any) -> bool:
    if value is True or value == 0:
        return True
    if isinstance(value, str):
        return value.upper() in {"PASS", "PASSED", "OK", "TRUE"}
    if isinstance(value, dict):
        return passing(value.get("status")) or value.get("passed") is True
    return False


def validate_inventory(manifest: dict[str, Any]) -> None:
    inventory = manifest.get("inventory")
    require(isinstance(inventory, dict), "manifest inventory must be an object")
    components = inventory.get("components")
    require(isinstance(components, dict), "inventory.components must be an object")
    if not components:
        return
    require(set(components) == COMPONENT_KEYS, "component-key drift")
    package_database = inventory.get("package_database")
    require(isinstance(package_database, dict), "missing package database inventory")
    packages = package_database.get("packages")
    require(isinstance(packages, dict) and set(packages) == {"me.jjolano.shadow", "me.jjolano.shadow.harness", "me.jjolano.dyldprobe"}, "package-key drift")
    require(package_database.get("dpkg_audit") == "recorded", "dpkg audit was not recorded")
    require(package_database.get("transitional_packages") == [], "dpkg has transitional packages")
    require(all(isinstance(row, dict) and row.get("status") in {"installed", "absent"} for row in packages.values()), "package database is not ready")
    for key, row in components.items():
        require(isinstance(row, dict) and row.get("key") == key, f"bad component row: {key}")
        require(row.get("discovery_status") != "error" and row.get("pid_status") != "error", f"inventory command error: {key}")
        if row.get("expected_presence"):
            require(row.get("discovery_status") == "one-match", f"unexpected component absence: {key}")
        if row.get("pid_expected"):
            require(row.get("pid_status") == "one-match" and len(row.get("pids") or []) == 1, f"unexpected zero/ambiguous PID: {key}")


def validate_manifest(manifest: dict[str, Any]) -> None:
    require(MANIFEST_KEYS <= set(manifest), "driver manifest missing fields")
    require(manifest.get("schema_version") == 1, "unsupported manifest schema")
    require(manifest.get("row_type") in {"stock", "jailbroken"}, "invalid row type")
    require(isinstance(manifest.get("jailbreak"), dict), "missing jailbreak provenance")
    validate_inventory(manifest)
    exit_row = manifest.get("exit")
    require(isinstance(exit_row, dict), "missing exit facts")
    transport = exit_row.get("transport")
    if manifest.get("source") == "manual-stock":
        require(transport == "not-applicable", "manual stock fabricated transport")
    else:
        require(transport == 0, "failed transport")
    for name in ("cleanup", "restore"):
        row = manifest.get(name)
        require(isinstance(row, dict), f"missing {name} facts")
        require(row.get("result") not in {"FAIL", "SETUP-FAIL", "pending", "failed"}, f"failed {name}")
    require(isinstance(manifest.get("artifacts"), list), "manifest artifacts must be a list")
    for item in manifest["artifacts"]:
        require(isinstance(item, dict) and {"role", "path", "sha256"} <= set(item), "bad artifact row")
        require(digest(item["path"]) == item["sha256"], f"bad artifact hash: {item.get('role')}")


def canary_ok(raw: dict[str, Any]) -> bool:
    mode = raw["requested_mode"]
    canary = raw["canary"]
    if mode == "injected":
        return passing(canary)
    if mode == "uninjected":
        return canary == "CONTROL-INACTIVE" or (isinstance(canary, dict) and canary.get("status") == "CONTROL-INACTIVE")
    return mode == "stock" and passing(canary)


def validate_stock_metadata(raw: dict[str, Any], manifest: dict[str, Any]) -> None:
    items = [item for item in manifest["artifacts"] if item.get("role") == "stock-metadata"]
    require(len(items) == 1, "manual stock metadata artifact missing")
    metadata = read_json(items[0]["path"])
    required = {"row_id", "row_type", "os_version", "os_build", "architecture", "jailbreak", "nonce", "probe_revision", "producer", "artifact_sha256", "collection_source"}
    require(required <= set(metadata), "manual stock metadata missing fields")
    require(metadata["row_type"] == "stock" and metadata["jailbreak"] == "none", "manual stock metadata mismatch")
    for key in ("row_id", "nonce", "probe_revision", "producer"):
        require(metadata[key] == raw[key], f"manual stock metadata mismatch: {key}")
    raw_items = [item for item in manifest["artifacts"] if item.get("role") == "raw-report"]
    require(len(raw_items) == 1 and metadata["artifact_sha256"] == raw_items[0]["sha256"], "manual stock artifact mismatch")


def validate_report(raw_path: os.PathLike[str] | str, manifest_path: os.PathLike[str] | str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        raw = read_json(raw_path)
    except Invalid as exc:
        raise Legacy(str(exc)) from exc
    if raw.get("schema_version") != 1:
        raise Legacy("legacy report schema")
    exact_keys(raw, RAW_KEYS, "raw report")
    manifest = read_json(manifest_path)
    validate_manifest(manifest)
    for key in ("run_id", "row_id", "row_type", "requested_mode", "nonce", "probe_revision"):
        require(raw[key] == manifest.get(key), f"raw/manifest provenance mismatch: {key}")
    require(raw["row_type"] in {"stock", "jailbroken"}, "invalid raw row type")
    require(raw["requested_mode"] in {"stock", "uninjected", "injected"}, "invalid requested mode")
    require(not (raw["row_type"] == "jailbroken" and raw["requested_mode"] == "stock"), "stock self-claim on jailbroken row")
    require(isinstance(raw["producer_exit"], int), "invalid producer exit")
    require(raw["producer_exit"] == manifest["exit"].get("producer"), "producer exit mismatch")
    require(raw["producer_exit"] in {0, 1}, "producer setup failure")
    require(isinstance(raw["observations"], (dict, list)) and bool(raw["observations"]), "missing observations")
    require(canary_ok(raw), "canary requirement failed")
    raw_items = [item for item in manifest["artifacts"] if item.get("role") == "raw-report"]
    require(len(raw_items) == 1, "raw-report artifact must be unique")
    require(pathlib.Path(raw_items[0]["path"]).resolve() == pathlib.Path(raw_path).resolve(), "manifest owns another raw report")
    require(raw_items[0]["sha256"] == digest(raw_path), "raw report hash mismatch")
    if raw["row_type"] == "stock":
        require(manifest.get("source") == "manual-stock" and manifest["jailbreak"].get("name") == "none", "invalid stock provenance")
        validate_stock_metadata(raw, manifest)
    return raw, manifest


def load_scope(path: os.PathLike[str] | str) -> dict[str, Any]:
    scope = read_json(path)
    exact_keys(scope, SCOPE_KEYS, "scope")
    require(scope["schema_version"] == 1 and isinstance(scope["scope_id"], str), "invalid scope identity")
    require(isinstance(scope["task_revisions"], dict) and scope["task_revisions"], "empty task revision map")
    for key in ("required_task_ids", "case_ids", "regression_ids", "row_ids"):
        require(isinstance(scope[key], list) and len(scope[key]) == len(set(scope[key])), f"invalid scope {key}")
    require(set(scope["required_task_ids"]) == set(scope["task_revisions"]), "scope task/revision drift")
    return scope


def pairs(root: os.PathLike[str] | str) -> list[tuple[pathlib.Path, pathlib.Path]]:
    result = []
    for manifest_path in pathlib.Path(root).rglob("manifest.json"):
        manifest = read_json(manifest_path)
        for item in manifest.get("artifacts", []):
            if item.get("role") == "raw-report":
                result.append((pathlib.Path(item["path"]), manifest_path))
    return result


def scoped_reports(scope: dict[str, Any], root: os.PathLike[str] | str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    found = [validate_report(raw, manifest) for raw, manifest in pairs(root)]
    found = [(raw, man) for raw, man in found if raw["run_id"] == scope["run_id"] and raw["row_id"] in scope["row_ids"] and man["task_id"] in scope["required_task_ids"]]
    require(found, "scope selected no reports")
    for raw, manifest in found:
        require(scope["task_revisions"].get(manifest["task_id"]) == raw["probe_revision"], "scope revision mismatch")
    return found


def observations_dict(raw: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(raw["observations"], dict), "object observations required")
    return raw["observations"]


def validate_activation(scope_path: str, root: str) -> dict[str, Any]:
    scope = load_scope(scope_path)
    reports = [(raw, man) for raw, man in scoped_reports(scope, root)
               if raw["requested_mode"] == "injected" and isinstance(observations_dict(raw).get("activation"), dict)]
    require(len(reports) == 10, "activation requires exactly ten injected reports")
    fingerprints = []
    cases = set()
    for raw, _ in reports:
        obs = observations_dict(raw); activation = obs.get("activation")
        require(isinstance(activation, dict), "activation observation missing")
        required = {"ctor_inventory", "post_load_inventory", "post_detector_inventory", "sdk_fallback_inventory", "sdk_fallback_observed", "verdicts", "case_id"}
        require(required <= set(activation), "activation observation incomplete")
        require(activation["ctor_inventory"], "empty ctor inventory")
        require(activation["sdk_fallback_observed"] is True, "SDK fallback was not observed")
        require({"Adapter_DeviceCheck", "Adapter_DeviceSecurityKit", "Adapter_IOSSecuritySuite"} <= set(activation["sdk_fallback_inventory"]), "SDK fallback inventory incomplete")
        require(isinstance(activation["verdicts"], dict) and all(passing(value) for value in activation["verdicts"].values()), "activation verdict failure")
        cases.add(activation["case_id"])
        fingerprints.append(json.dumps({key: activation[key] for key in required - {"case_id"}}, sort_keys=True))
    require(len(set(fingerprints)) == 1, "activation divergence")
    require(set(scope["case_ids"]) == cases, "activation case scope mismatch")
    return {"status": "PASS", "samples": 10}


def validate_dyld(scope_path: str, directories: list[str]) -> dict[str, Any]:
    scope = load_scope(scope_path); expected_modes = ["stock", "uninjected", "injected"]; seen = set(); cases = set()
    for directory, expected_mode in zip(directories, expected_modes, strict=True):
        reports = scoped_reports(scope, directory)
        require(reports, f"missing {expected_mode} dyld report")
        for raw, _ in reports:
            require(raw["requested_mode"] == expected_mode, "dyld lane mode mismatch")
            dyld = observations_dict(raw).get("dyld")
            require(isinstance(dyld, dict), "dyld observation missing")
            require({"case_id", "views", "task_dyld_info", "callbacks", "concurrency", "address_uuid", "stress"} <= set(dyld), "dyld observation incomplete")
            require(len(dyld["callbacks"]) >= 9 and passing(dyld["concurrency"]) and passing(dyld["address_uuid"]) and passing(dyld["stress"]), "dyld callback/coherence failure")
            info = dyld["task_dyld_info"]
            require(isinstance(info, dict) and info.get("address") and info.get("size", 0) > 0 and info.get("format") is not None and passing(info.get("retry")), "TASK_DYLD_INFO failure")
            views = dyld["views"]
            require(isinstance(views, dict) and len(views) >= 2, "dyld public views missing")
            normalized = {json.dumps(value, sort_keys=True) for value in views.values()}
            require(len(normalized) == 1, "dyld public/direct-memory disagreement")
            cases.add(dyld["case_id"]); seen.add(expected_mode)
    require(seen == set(expected_modes) and cases == set(scope["case_ids"]), "dyld scope mismatch")
    return {"status": "PASS", "modes": expected_modes}


def validate_lifecycle(scope_path: str, root: str) -> dict[str, Any]:
    scope = load_scope(scope_path); cases = {}
    for raw, manifest in scoped_reports(scope, root):
        for row in observations_dict(raw).get("lifecycle", []):
            require(isinstance(row, dict) and isinstance(row.get("id"), str), "bad lifecycle row")
            require(passing(row.get("status")) and passing(row.get("restore")), f"lifecycle failure: {row.get('id')}")
            if "sigkill" in row["id"]:
                require(isinstance(row.get("pid"), int) and row.get("lstart"), "SIGKILL identity missing")
            if "reboot" in row["id"] or "restart" in row["id"]:
                require(passing(row.get("reconnect")), "restart reconnect not proven")
            require(row["id"] not in cases, f"duplicate lifecycle case: {row['id']}")
            cases[row["id"]] = manifest["task_id"]
    require(set(cases) == set(scope["case_ids"]), "lifecycle case scope mismatch")
    return {"status": "PASS", "cases": sorted(cases)}


def validate_matrix(scope_path: str, root: str) -> dict[str, Any]:
    scope = load_scope(scope_path); measured = {}; controls = set(); rows = set()
    for raw, _ in scoped_reports(scope, root):
        rows.add(raw["row_id"]); obs = observations_dict(raw)
        for row in obs.get("regression", []):
            require(isinstance(row, dict) and isinstance(row.get("id"), str), "bad regression row")
            status = row.get("status")
            require(passing(status) or (status == "N/A" and row.get("reason") == "symbol-absent"), f"regression failure: {row.get('id')}")
            require(row["id"] not in measured, f"duplicate regression row: {row['id']}")
            measured[row["id"]] = status
        for name, value in obs.get("controls", {}).items():
            require(passing(value), f"control failure: {name}"); controls.add(name)
    require(set(measured) == set(scope["regression_ids"]), "regression scope mismatch")
    require(rows == set(scope["row_ids"]), "matrix row scope mismatch")
    require({"positive", "unrelated"} <= controls, "matrix controls missing")
    return {"status": "PASS", "rows": sorted(rows), "regressions": len(measured)}


def union_scopes(evidence_root: pathlib.Path, release_path: pathlib.Path) -> dict[str, Any]:
    scopes = [load_scope(path) for path in (evidence_root / "scopes").glob("*.json") if path.resolve() != release_path.resolve()]
    require(scopes, "release has no partial scopes")
    union: dict[str, Any] = {key: set() for key in ("required_task_ids", "case_ids", "regression_ids", "row_ids")}
    revisions: dict[str, str] = {}
    run_ids = set()
    for scope in scopes:
        run_ids.add(scope["run_id"])
        for key in union: union[key].update(scope[key])
        for task, revision in scope["task_revisions"].items():
            require(task not in revisions or revisions[task] == revision, f"conflicting task revision: {task}")
            revisions[task] = revision
    require(len(run_ids) == 1, "partial scopes cross runs")
    union["task_revisions"] = revisions; union["run_id"] = run_ids.pop()
    return union


def validate_release(scope_path: str, root: str) -> dict[str, Any]:
    scope = load_scope(scope_path); evidence = pathlib.Path(root); expected = union_scopes(evidence, pathlib.Path(scope_path))
    require(scope["run_id"] == expected["run_id"] and scope["task_revisions"] == expected["task_revisions"], "release revision union mismatch")
    for key in ("required_task_ids", "case_ids", "regression_ids", "row_ids"):
        require(set(scope[key]) == set(expected[key]), f"release {key} union mismatch")
    reports = scoped_reports(scope, evidence)
    represented = {raw["row_id"] for raw, _ in reports}
    require(represented == set(scope["row_ids"]), "release row has no complete evidence")
    kinds = set()
    row_status = {}
    for raw, manifest in reports:
        if raw["row_type"] == "stock": kind = "stock"
        elif manifest["jailbreak"].get("root") == "/": kind = "rootful"
        else: kind = "rootless"
        kinds.add(kind); row_status[raw["row_id"]] = f"RELEASE VALIDATED — {kind.upper()} ROW {raw['row_id']}"
    project = "IMPLEMENTATION COMPLETE — RELEASE VALIDATED" if kinds == {"stock", "rootless", "rootful"} else "IMPLEMENTATION COMPLETE — RELEASE BLOCKED"
    return {"status": "PASS", "project_status": project, "row_status": row_status}


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def selftest() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="shadow-validator-") as temp:
        root = pathlib.Path(temp); raw_path = root / "raw.json"; meta_path = root / "meta.json"; manifest_path = root / "manifest.json"
        raw = {"schema_version": 1, "producer": "fixture", "run_id": "run", "row_id": "row", "row_type": "jailbroken", "requested_mode": "injected", "nonce": "n", "probe_revision": "rev", "canary": {"status": "PASS"}, "observations": {"fixture": "PASS"}, "producer_exit": 0}
        write_json(raw_path, raw)
        components = {key: {"key": key, "expected_presence": True, "pid_expected": key == "shadowd", "resolved_exact_path": f"/{key}", "discovery_status": "one-match", "artifact_sha256": "a", "pid_status": "not-applicable" if key == "ShadowCore" else ("one-match" if key == "shadowd" else "expected-absent"), "pids": None if key == "ShadowCore" else ([1] if key == "shadowd" else []), "process_start_identity": None if key == "ShadowCore" else (["t"] if key == "shadowd" else [])} for key in COMPONENT_KEYS}
        packages = {name: {"version": "1", "status": "installed"} for name in ("me.jjolano.shadow", "me.jjolano.shadow.harness", "me.jjolano.dyldprobe")}
        manifest = {"schema_version": 1, "run_id": "run", "row_id": "row", "row_type": "jailbroken", "source": "device-driver", "command": "pull-report", "nonce": "n", "endpoint": "mobile@device", "task_id": "T", "jailbreak": {"name": "Dopamine", "version": "x", "root": "/var/jb"}, "os_version": "15", "os_build": "x", "architecture": "arm64", "requested_mode": "injected", "observed_mode": "injected", "probe_revision": "rev", "inventory": {"components": components, "package_database": {"packages": packages, "transitional_packages": [], "dpkg_audit": "recorded"}}, "artifacts": [], "stdout": {"path": str(root / "out"), "sha256": ""}, "stderr": {"path": str(root / "err"), "sha256": ""}, "exit": {"command": 0, "transport": 0, "producer": 0}, "pid": 1, "process_start_identity": "t", "launch": {}, "cleanup": {"result": "not-applicable"}, "restore": {"result": "not-applicable"}, "authorization": {"sha256": None}, "reconnect": {}}
        manifest["artifacts"] = [{"role": "raw-report", "path": str(raw_path), "sha256": digest(raw_path)}]
        write_json(manifest_path, manifest); validate_report(raw_path, manifest_path)

        def rejected(change, name: str, rehash: bool = True) -> None:
            bad_raw = copy.deepcopy(raw); bad_manifest = copy.deepcopy(manifest)
            change(bad_raw, bad_manifest); write_json(raw_path, bad_raw)
            if rehash:
                for item in bad_manifest.get("artifacts", []):
                    if item.get("role") == "raw-report": item["sha256"] = digest(raw_path)
            write_json(manifest_path, bad_manifest)
            try: validate_report(raw_path, manifest_path)
            except (Invalid, Legacy): pass
            else: raise AssertionError(f"mutation accepted: {name}")

        rejected(lambda r, m: r.pop("nonce"), "missing field")
        rejected(lambda r, m: r.update(nonce="stale"), "stale nonce")
        rejected(lambda r, m: r.update(probe_revision="old"), "revision mismatch")
        rejected(lambda r, m: m["artifacts"][0].update(sha256="0" * 64), "bad hash", False)
        rejected(lambda r, m: m["exit"].update(transport=23), "transport failure")
        rejected(lambda r, m: m["cleanup"].update(result="FAIL"), "cleanup failure")
        rejected(lambda r, m: m["restore"].update(result="FAIL"), "restore failure")
        rejected(lambda r, m: m["inventory"]["components"].pop("hookprobe"), "component drift")
        rejected(lambda r, m: m["inventory"]["components"]["shadowd"].update(pids=[], pid_status="zero-match"), "unexpected zero PID")
        rejected(lambda r, m: m["inventory"]["components"]["shadowd"].update(discovery_status="error"), "inventory command error")
        rejected(lambda r, m: m["inventory"]["package_database"]["packages"]["me.jjolano.shadow"].update(status="half-configured"), "dirty package database")
        rejected(lambda r, m: r.update(requested_mode="stock"), "stock self-claim")
        rejected(lambda r, m: r.update(row_id="other"), "cross-row")
        rejected(lambda r, m: r.update(run_id="other"), "cross-run")
        pathlib.Path(raw_path).write_text("legacy text\n", encoding="utf-8")
        try: validate_report(raw_path, manifest_path)
        except Legacy: pass
        else: raise AssertionError("legacy report accepted")

        legacy = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve()), "report", str(raw_path), str(manifest_path)],
            check=False, capture_output=True, text=True,
        )
        require(legacy.returncode == 3 and json.loads(legacy.stdout)["status"] == "LEGACY_SCHEMA", "legacy exit/status drift")

        def make_pair(directory: pathlib.Path, observation: dict[str, Any], *, mode: str = "injected", row_id: str = "row", stock: bool = False) -> tuple[pathlib.Path, pathlib.Path]:
            directory.mkdir(parents=True, exist_ok=True)
            rp = directory / "raw.json"; mp = directory / "manifest.json"
            r = copy.deepcopy(raw); r.update(row_id=row_id, row_type="stock" if stock else "jailbroken", requested_mode="stock" if stock else mode, observations=observation)
            r["canary"] = {"status": "PASS"} if mode != "uninjected" else "CONTROL-INACTIVE"
            write_json(rp, r)
            m = copy.deepcopy(manifest); m.update(row_id=row_id, row_type=r["row_type"], requested_mode=r["requested_mode"], observed_mode=r["requested_mode"], source="manual-stock" if stock else "device-driver")
            m["jailbreak"] = {"name": "none", "version": "none"} if stock else {"name": "Dopamine", "version": "x", "root": "/var/jb"}
            m["exit"]["transport"] = "not-applicable" if stock else 0
            m["artifacts"] = [{"role": "raw-report", "path": str(rp), "sha256": digest(rp)}]
            if stock:
                metadata = {"row_id": row_id, "row_type": "stock", "os_version": "15", "os_build": "x", "architecture": "arm64", "jailbreak": "none", "nonce": "n", "probe_revision": "rev", "producer": "fixture", "artifact_sha256": digest(rp), "collection_source": "manual"}
                metadata_path = directory / "metadata.json"; write_json(metadata_path, metadata)
                m["artifacts"].append({"role": "stock-metadata", "path": str(metadata_path), "sha256": digest(metadata_path)})
            write_json(mp, m)
            return rp, mp

        def make_scope(path: pathlib.Path, case_ids: list[str], regression_ids: list[str], row_ids: list[str]) -> pathlib.Path:
            value = {"schema_version": 1, "scope_id": path.stem, "run_id": "run", "task_revisions": {"T": "rev"}, "required_task_ids": ["T"], "case_ids": case_ids, "regression_ids": regression_ids, "row_ids": row_ids}
            write_json(path, value); return path

        # activation
        activation_root = root / "activation"; activation_scope = make_scope(root / "activation-scope.json", ["activation"], [], ["row"])
        activation = {"case_id": "activation", "ctor_inventory": ["core"], "post_load_inventory": ["core"], "post_detector_inventory": ["core"], "sdk_fallback_inventory": ["Adapter_DeviceCheck", "Adapter_DeviceSecurityKit", "Adapter_IOSSecuritySuite"], "sdk_fallback_observed": True, "verdicts": {"v": "PASS"}}
        for index in range(10): make_pair(activation_root / str(index), {"activation": activation})
        validate_activation(str(activation_scope), str(activation_root))
        changed = read_json(activation_root / "9" / "raw.json"); changed["observations"]["activation"]["sdk_fallback_observed"] = False; write_json(activation_root / "9" / "raw.json", changed)
        changed_manifest = read_json(activation_root / "9" / "manifest.json"); changed_manifest["artifacts"][0]["sha256"] = digest(activation_root / "9" / "raw.json"); write_json(activation_root / "9" / "manifest.json", changed_manifest)
        try: validate_activation(str(activation_scope), str(activation_root))
        except Invalid: pass
        else: raise AssertionError("missing SDK fallback accepted")

        # dyld
        dyld_scope = make_scope(root / "dyld-scope.json", ["dyld"], [], ["stock-row", "row"])
        dyld_observation = {"case_id": "dyld", "views": {"public": ["A"], "memory": ["A"]}, "task_dyld_info": {"address": 1, "size": 8, "format": 64, "retry": "PASS"}, "callbacks": list(range(9)), "concurrency": "PASS", "address_uuid": "PASS", "stress": "PASS"}
        stock_pair = make_pair(root / "dyld" / "stock", {"dyld": dyld_observation}, mode="stock", row_id="stock-row", stock=True)
        make_pair(root / "dyld" / "uninjected", {"dyld": dyld_observation}, mode="uninjected")
        make_pair(root / "dyld" / "injected", {"dyld": dyld_observation})
        validate_dyld(str(dyld_scope), [str(root / "dyld" / lane) for lane in ("stock", "uninjected", "injected")])
        stock_metadata = read_json(root / "dyld" / "stock" / "metadata.json"); stock_metadata["nonce"] = "wrong"; write_json(root / "dyld" / "stock" / "metadata.json", stock_metadata)
        stock_manifest = read_json(stock_pair[1]); stock_manifest["artifacts"][1]["sha256"] = digest(root / "dyld" / "stock" / "metadata.json"); write_json(stock_pair[1], stock_manifest)
        try: validate_report(*stock_pair)
        except Invalid: pass
        else: raise AssertionError("manual stock metadata mismatch accepted")
        stock_metadata["nonce"] = "n"; write_json(root / "dyld" / "stock" / "metadata.json", stock_metadata)
        stock_manifest["artifacts"][1]["sha256"] = digest(root / "dyld" / "stock" / "metadata.json"); write_json(stock_pair[1], stock_manifest)
        dyld_raw = read_json(root / "dyld" / "injected" / "raw.json"); dyld_raw["observations"]["dyld"]["callbacks"] = [] ; write_json(root / "dyld" / "injected" / "raw.json", dyld_raw)
        dyld_manifest = read_json(root / "dyld" / "injected" / "manifest.json"); dyld_manifest["artifacts"][0]["sha256"] = digest(root / "dyld" / "injected" / "raw.json"); write_json(root / "dyld" / "injected" / "manifest.json", dyld_manifest)
        try: validate_dyld(str(dyld_scope), [str(root / "dyld" / lane) for lane in ("stock", "uninjected", "injected")])
        except Invalid: pass
        else: raise AssertionError("dyld callback omission accepted")
        dyld_raw["observations"]["dyld"].update(callbacks=list(range(9)), stress="FAIL"); write_json(root / "dyld" / "injected" / "raw.json", dyld_raw)
        dyld_manifest["artifacts"][0]["sha256"] = digest(root / "dyld" / "injected" / "raw.json"); write_json(root / "dyld" / "injected" / "manifest.json", dyld_manifest)
        try: validate_dyld(str(dyld_scope), [str(root / "dyld" / lane) for lane in ("stock", "uninjected", "injected")])
        except Invalid: pass
        else: raise AssertionError("dyld stress failure accepted")

        # lifecycle
        lifecycle_scope = make_scope(root / "lifecycle-scope.json", ["normal", "restart"], [], ["row"])
        make_pair(root / "lifecycle", {"lifecycle": [{"id": "normal", "status": "PASS", "restore": "PASS"}, {"id": "restart", "status": "PASS", "restore": "PASS", "reconnect": "PASS"}]})
        validate_lifecycle(str(lifecycle_scope), str(root / "lifecycle"))
        lifecycle_raw = read_json(root / "lifecycle" / "raw.json"); lifecycle_raw["observations"]["lifecycle"].pop(); write_json(root / "lifecycle" / "raw.json", lifecycle_raw)
        lifecycle_manifest = read_json(root / "lifecycle" / "manifest.json"); lifecycle_manifest["artifacts"][0]["sha256"] = digest(root / "lifecycle" / "raw.json"); write_json(root / "lifecycle" / "manifest.json", lifecycle_manifest)
        try: validate_lifecycle(str(lifecycle_scope), str(root / "lifecycle"))
        except Invalid: pass
        else: raise AssertionError("missing lifecycle case accepted")

        # matrix
        matrix_scope = make_scope(root / "matrix-scope.json", [], ["R1", "R2"], ["row"])
        make_pair(root / "matrix", {"regression": [{"id": "R1", "status": "PASS"}, {"id": "R2", "status": "N/A", "reason": "symbol-absent"}], "controls": {"positive": "PASS", "unrelated": "PASS"}})
        validate_matrix(str(matrix_scope), str(root / "matrix"))
        matrix_raw = read_json(root / "matrix" / "raw.json"); matrix_raw["observations"]["regression"].pop(); write_json(root / "matrix" / "raw.json", matrix_raw)
        matrix_manifest = read_json(root / "matrix" / "manifest.json"); matrix_manifest["artifacts"][0]["sha256"] = digest(root / "matrix" / "raw.json"); write_json(root / "matrix" / "manifest.json", matrix_manifest)
        try: validate_matrix(str(matrix_scope), str(root / "matrix"))
        except Invalid: pass
        else: raise AssertionError("missing regression row accepted")

        # scope union and terminal release semantics
        release_root = root / "release"; make_pair(release_root / "device" / "row", {"fixture": "PASS"})
        scope_dir = release_root / "scopes"; partial = {"schema_version": 1, "scope_id": "p", "run_id": "run", "task_revisions": {"T": "rev"}, "required_task_ids": ["T"], "case_ids": [], "regression_ids": [], "row_ids": ["row"]}
        write_json(scope_dir / "partial.json", partial)
        release = copy.deepcopy(partial); release["scope_id"] = "release-v1"; write_json(scope_dir / "release-v1.json", release)
        result = validate_release(str(scope_dir / "release-v1.json"), str(release_root))
        require(result["project_status"] == "IMPLEMENTATION COMPLETE — RELEASE BLOCKED", "rootless-only release status drift")
        bad = copy.deepcopy(release); bad["row_ids"].append("missing"); write_json(scope_dir / "bad-release.json", bad)
        try: validate_release(str(scope_dir / "bad-release.json"), str(release_root))
        except Invalid: pass
        else: raise AssertionError("release union drift accepted")
        omitted = copy.deepcopy(partial); omitted.pop("case_ids"); write_json(scope_dir / "omitted.json", omitted)
        try: load_scope(scope_dir / "omitted.json")
        except Invalid: pass
        else: raise AssertionError("scope omission accepted")
        return {"status": "PASS", "mutations": 22, "commands": 8}


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="stealth_validate.py")
    sub = value.add_subparsers(dest="command", required=True)
    sub.add_parser("selftest")
    report = sub.add_parser("report"); report.add_argument("raw_report"); report.add_argument("driver_manifest")
    for name in ("activation", "lifecycle", "matrix", "release"):
        item = sub.add_parser(name); item.add_argument("--scope", required=True); item.add_argument("root")
    dyld = sub.add_parser("dyld"); dyld.add_argument("--scope", required=True); dyld.add_argument("stock_dir"); dyld.add_argument("uninjected_dir"); dyld.add_argument("injected_dir")
    return value


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "selftest": return selftest()
    if args.command == "report":
        raw, _ = validate_report(args.raw_report, args.driver_manifest); return {"status": "PASS", "producer": raw["producer"]}
    if args.command == "activation": return validate_activation(args.scope, args.root)
    if args.command == "dyld": return validate_dyld(args.scope, [args.stock_dir, args.uninjected_dir, args.injected_dir])
    if args.command == "lifecycle": return validate_lifecycle(args.scope, args.root)
    if args.command == "matrix": return validate_matrix(args.scope, args.root)
    if args.command == "release": return validate_release(args.scope, args.root)
    raise Invalid("unknown command")


def main() -> int:
    try:
        result = run(parser().parse_args())
    except Legacy as exc:
        print(json.dumps({"status": "LEGACY_SCHEMA", "error": str(exc)}, sort_keys=True, separators=(",", ":")))
        return 3
    except (Invalid, AssertionError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
