from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any


class CodexAnalysisError(RuntimeError):
    pass


@dataclass
class CodexConfig:
    enabled: bool = True
    command: str = "codex"
    model: str = ""
    timeout_seconds: float = 900.0
    auto_analyze_after_explore: bool = True
    batch_size: int = 20

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CodexConfig":
        return cls(
            enabled=bool(value.get("enabled", True)),
            command=str(value.get("command", "codex")),
            model=str(os.environ.get("CODEX_ANALYSIS_MODEL") or value.get("model", "")),
            timeout_seconds=float(value.get("timeout_seconds", 900.0)),
            auto_analyze_after_explore=bool(value.get("auto_analyze_after_explore", True)),
            batch_size=max(1, int(value.get("batch_size", 20))),
        )


class CodexInventoryAnalyzer:
    def __init__(
        self,
        *,
        config: CodexConfig,
        workspace_dir: Path,
        inventory_path: Path,
        schema_path: Path,
    ):
        self.config = config
        self.workspace_dir = workspace_dir.resolve()
        self.inventory_path = inventory_path.resolve()
        self.schema_path = schema_path.resolve()

    def doctor(self) -> dict[str, Any]:
        executable = shutil.which(self.config.command)
        result: dict[str, Any] = {
            "enabled": self.config.enabled,
            "command": self.config.command,
            "executable": executable,
            "schema_path": str(self.schema_path),
            "schema_exists": self.schema_path.is_file(),
            "model": self.config.model or "<codex-cli-default>",
        }
        if not self.config.enabled:
            result["ok"] = True
            result["reason"] = "Codex analysis is disabled in config."
            return result
        if executable is None:
            result["ok"] = False
            result["reason"] = f"Codex CLI command was not found: {self.config.command}"
            return result
        try:
            completed = subprocess.run(
                [executable, "login", "status"],
                cwd=self.workspace_dir,
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["ok"] = False
            result["reason"] = f"Codex login check failed: {exc}"
            return result
        login_text = (completed.stdout + completed.stderr).strip()
        result["login_status"] = login_text
        result["ok"] = bool(
            completed.returncode == 0
            and "logged in" in login_text.casefold()
            and self.schema_path.is_file()
        )
        if not result["ok"]:
            result["reason"] = login_text or "Codex CLI is not authenticated."
        return result

    def analyze_run(self, run_dir: Path, *, force: bool = False) -> dict[str, Any]:
        run_dir = run_dir.resolve()
        if not run_dir.is_dir():
            raise CodexAnalysisError(f"Run directory does not exist: {run_dir}")
        if not self.config.enabled:
            raise CodexAnalysisError("Codex analysis is disabled in config.")
        doctor = self.doctor()
        if not doctor.get("ok"):
            raise CodexAnalysisError(str(doctor.get("reason") or doctor))

        step_dirs = sorted(
            path
            for path in run_dir.glob("step-*")
            if path.is_dir() and (path / "common.json").is_file()
        )
        if not step_dirs:
            raise CodexAnalysisError(f"No completed step observations found in {run_dir}")
        pending = [
            path
            for path in step_dirs
            if force or not self._is_codex_analysis(path / "analysis.json")
        ]
        inventory = self._load_inventory()
        run_id = run_dir.name
        if not pending:
            return {
                "status": "already_analyzed",
                "run_directory": str(run_dir),
                "analyzed_steps": 0,
                "inventory_path": str(self.inventory_path),
            }

        all_analyses: list[dict[str, Any]] = []
        started_at = datetime.now().astimezone().isoformat()
        try:
            for chunk_index, start in enumerate(range(0, len(pending), self.config.batch_size), 1):
                chunk = pending[start : start + self.config.batch_size]
                bundle = build_analysis_bundle(run_dir, chunk, inventory)
                input_path = run_dir / f"codex-input-{chunk_index:03d}.json"
                _write_json(input_path, bundle)
                print(
                    f"[AUTO] Codex analyzing {len(chunk)} step(s), batch {chunk_index}...",
                    flush=True,
                )
                response = self._run_codex(run_dir, chunk_index, bundle)
                response_path = run_dir / f"codex-result-{chunk_index:03d}.json"
                _write_json(response_path, response)
                analyses = self._write_step_analyses(run_dir, chunk, response)
                all_analyses.extend(analyses)
                inventory = normalize_inventory(
                    response.get("inventory", {}),
                    previous=inventory,
                    run_id=run_id,
                    analyses=analyses,
                    allowed_refs=bundle["allowed_evidence_refs"],
                )
                _write_json(self.inventory_path, inventory)
                _write_json(run_dir / "feature-inventory.json", inventory)
                print(f"[AUTO] Codex batch {chunk_index} analysis received", flush=True)
        except Exception as exc:
            self._update_run_summary(
                run_dir,
                {
                    "status": "failed",
                    "started_at": started_at,
                    "finished_at": datetime.now().astimezone().isoformat(),
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )
            raise

        result = {
            "status": "completed",
            "run_directory": str(run_dir),
            "analyzed_steps": len(all_analyses),
            "inventory_feature_count": len(inventory.get("features", [])),
            "inventory_path": str(self.inventory_path),
            "started_at": started_at,
            "finished_at": datetime.now().astimezone().isoformat(),
        }
        self._update_run_summary(run_dir, result)
        return result

    def _run_codex(
        self, run_dir: Path, chunk_index: int, bundle: dict[str, Any]
    ) -> dict[str, Any]:
        executable = shutil.which(self.config.command)
        if executable is None:
            raise CodexAnalysisError(f"Codex CLI command was not found: {self.config.command}")
        output_path = run_dir / f".codex-last-message-{chunk_index:03d}.json"
        command = [
            executable,
            "exec",
            "--ephemeral",
            "--sandbox",
            "read-only",
            "--skip-git-repo-check",
            "--output-schema",
            str(self.schema_path),
            "--output-last-message",
            str(output_path),
            "--color",
            "never",
            "--cd",
            str(self.workspace_dir),
        ]
        if self.config.model:
            command.extend(["--model", self.config.model])
        command.append("-")
        prompt = build_codex_prompt(bundle)
        try:
            completed = subprocess.run(
                command,
                input=prompt,
                cwd=self.workspace_dir,
                text=True,
                capture_output=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise CodexAnalysisError(
                f"Codex analysis timed out after {self.config.timeout_seconds:.0f}s"
            ) from exc
        log_path = run_dir / f"codex-exec-{chunk_index:03d}.log"
        log_path.write_text(
            completed.stdout + ("\n[stderr]\n" + completed.stderr if completed.stderr else ""),
            encoding="utf-8",
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise CodexAnalysisError(
                f"Codex CLI exited with {completed.returncode}: {detail[-1500:]}"
            )
        if not output_path.is_file():
            raise CodexAnalysisError("Codex CLI did not write its final JSON response.")
        try:
            response = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CodexAnalysisError(f"Codex returned invalid JSON: {exc}") from exc
        finally:
            output_path.unlink(missing_ok=True)
        if not isinstance(response, dict):
            raise CodexAnalysisError("Codex response must be a JSON object.")
        return response

    def _write_step_analyses(
        self, run_dir: Path, step_dirs: list[Path], response: dict[str, Any]
    ) -> list[dict[str, Any]]:
        by_id = {
            str(item.get("step_id")): item
            for item in response.get("step_analyses", [])
            if isinstance(item, dict)
        }
        written: list[dict[str, Any]] = []
        for step_dir in step_dirs:
            step_id = step_dir.name
            analysis = by_id.get(step_id)
            if analysis is None:
                raise CodexAnalysisError(f"Codex omitted analysis for {step_id}")
            analysis["feature_id"] = normalize_feature_id(
                str(analysis.get("feature_id") or analysis.get("feature_label") or step_id)
            )
            allowed_refs = set(step_evidence_refs(run_dir, step_dir))
            analysis["evidence_refs"] = [
                ref for ref in analysis.get("evidence_refs", []) if ref in allowed_refs
            ] or sorted(allowed_refs)
            analysis["source"] = "codex"
            analysis["schema_version"] = "codex-step-analysis/v1"
            analysis["analyzed_at"] = datetime.now().astimezone().isoformat()
            _write_json(step_dir / "analysis.json", analysis)
            written.append(analysis)
        return written

    def _load_inventory(self) -> dict[str, Any]:
        if not self.inventory_path.is_file():
            return empty_inventory()
        try:
            value = json.loads(self.inventory_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CodexAnalysisError(f"Existing inventory is invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise CodexAnalysisError("Existing inventory must be a JSON object.")
        return value

    @staticmethod
    def _is_codex_analysis(path: Path) -> bool:
        if not path.is_file():
            return False
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False
        return value.get("source") == "codex"

    @staticmethod
    def _update_run_summary(run_dir: Path, codex_result: dict[str, Any]) -> None:
        summary_path = run_dir / "run-summary.json"
        summary: dict[str, Any] = {}
        if summary_path.is_file():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                summary = {}
        summary["normal_behavior_analyzer"] = "codex"
        summary["codex_analysis"] = codex_result
        _write_json(summary_path, summary)


def build_codex_prompt(bundle: dict[str, Any]) -> str:
    serialized = json.dumps(bundle, ensure_ascii=False, separators=(",", ":"))
    return (
        "You are Codex acting as an evidence-constrained Android runtime security analyst. "
        "Analyze the supplied authorized-test observations and merge them into the existing feature inventory. "
        "Return only JSON matching the provided output schema. Do not use shell, web, or other tools. "
        "Treat runtime facts as observations and everything else as inference. A successful request does not prove "
        "server-side authorization. Reuse an existing feature_id when a new step represents the same capability; "
        "create a stable F_UPPER_SNAKE_CASE id only for a genuinely new capability. Do not create one feature per "
        "navigation click when several clicks are entry points or subflows of one feature. Preserve existing evidence "
        "while adding new evidence. Use only strings listed in allowed_evidence_refs for evidence_refs. Never claim a "
        "vulnerability without direct evidence. Unknown storage, authorization, actors, controllability, and failure "
        "behavior must remain explicit unknowns rather than guesses.\n\nINPUT_JSON:\n"
        + serialized
    )


def build_analysis_bundle(
    run_dir: Path, step_dirs: list[Path], inventory: dict[str, Any]
) -> dict[str, Any]:
    run_summary = _read_json(run_dir / "run-summary.json", {})
    blocked = _read_json(run_dir / "blocked-actions.json", {"actions": []})
    steps = [build_step_bundle(run_dir, step_dir) for step_dir in step_dirs]
    evidence_refs = sorted(
        {ref for step in steps for ref in step["evidence_refs"]}
        | set(inventory_evidence_refs(inventory))
    )
    blocked_items = []
    for item in blocked.get("actions", [])[:80]:
        node = item.get("node", {})
        policy = item.get("policy", {})
        blocked_items.append(
            {
                "activity": item.get("activity"),
                "label": node.get("label"),
                "resource_id": node.get("resource_id"),
                "risk_level": policy.get("level"),
                "matched_rules": policy.get("matched_rules", []),
            }
        )
    return {
        "schema_version": "codex-analysis-input/v1",
        "run_id": run_dir.name,
        "run_summary": {
            "status": run_summary.get("status"),
            "executed_steps": run_summary.get("executed_steps"),
            "max_auto_risk": run_summary.get("max_auto_risk"),
            "blocked_action_count": run_summary.get("blocked_action_count", len(blocked_items)),
        },
        "steps": steps,
        "blocked_candidates": blocked_items,
        "existing_inventory": inventory,
        "allowed_evidence_refs": evidence_refs,
    }


def build_step_bundle(run_dir: Path, step_dir: Path) -> dict[str, Any]:
    before = _read_json(step_dir / "before.json", {})
    after = _read_json(step_dir / "after.json", {})
    common = _read_json(step_dir / "common.json", {})
    return {
        "step_id": step_dir.name,
        "decision": _read_json(step_dir / "decision.json", {}),
        "policy": _read_json(step_dir / "policy.json", {}),
        "observation": _read_json(step_dir / "observation.json", {}),
        "metadata": _read_json(step_dir / "metadata.json", {}),
        "before": compact_ui_snapshot(before),
        "after": compact_ui_snapshot(after),
        "runtime_summary": compact_common_summary(common),
        "evidence_refs": step_evidence_refs(run_dir, step_dir),
    }


def compact_ui_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    controls = []
    for item in value.get("actionable_nodes", [])[:60]:
        controls.append(
            {
                "label": item.get("label"),
                "resource_id": item.get("resource_id"),
                "class": item.get("class"),
                "selected": item.get("selected"),
                "checked": item.get("checked"),
            }
        )
    return {
        "activity": value.get("activity"),
        "foreground_package": value.get("foreground_package"),
        "signature": value.get("signature"),
        "actionable_controls": controls,
        "actionable_control_count": len(value.get("actionable_nodes", [])),
    }


def compact_common_summary(value: dict[str, Any]) -> dict[str, Any]:
    info = value.get("commonInformation", {})
    protocols: dict[str, Any] = {}
    protocol_fields = (
        "method", "host", "route", "eventTypes", "queryFields",
        "authenticationIndicatorHeaders", "responseCodes", "status",
    )
    for family, entries in info.get("protocols", {}).items():
        if not isinstance(entries, list):
            continue
        compact_entries = [
            {key: item.get(key) for key in protocol_fields if key in item}
            for item in entries[:30]
        ]
        protocols[family] = {
            "total": len(entries),
            "items": compact_entries,
            "truncated": len(entries) > len(compact_entries),
        }

    input_groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for item in info.get("observed_input_fields", []):
        key = (str(item.get("source", "")), str(item.get("operation", "")))
        input_groups[key].add(str(item.get("field", "")))
    observed_inputs = [
        {"source": key[0], "operation": key[1], "fields": sorted(fields)}
        for key, fields in list(input_groups.items())[:30]
    ]

    state_counter: Counter[tuple[str, str, str, str]] = Counter()
    for item in info.get("state_changes", []):
        state_counter[
            (
                str(item.get("mutation", "")),
                str(item.get("valueType", "")),
                str(item.get("producer", "")),
                str(item.get("status", "")),
            )
        ] += 1
    states = [
        {
            "mutation": key[0],
            "value_type": key[1],
            "producer": key[2],
            "status": key[3],
            "count": count,
        }
        for key, count in state_counter.most_common(30)
    ]

    def select(entries: Any, fields: tuple[str, ...], limit: int) -> list[dict[str, Any]]:
        if not isinstance(entries, list):
            return []
        return [
            {key: item.get(key) for key in fields if key in item}
            for item in entries[:limit]
        ]

    return {
        "schema_version": value.get("schemaVersion"),
        "segment_id": value.get("segmentId"),
        "scenario_label": value.get("scenarioLabel"),
        "event_count": value.get("eventCount", 0),
        "privacy": value.get("privacy", {}),
        "field_coverage": value.get("fieldCoverage", {}),
        "collection_gaps": value.get("collection", {}).get("gaps", []),
        "entry_points": select(
            info.get("entry_points"), ("kind", "target", "activity", "fragment", "status"), 12
        ),
        "screens": select(info.get("screens"), ("event", "component", "status"), 20),
        "observed_input_groups": observed_inputs,
        "protocols": protocols,
        "state_changes": {"total": len(info.get("state_changes", [])), "items": states},
        "external_destinations": select(
            info.get("external_destinations"), ("transport", "host", "status"), 30
        ),
        "failure_behavior": select(
            info.get("failure_behavior"), ("kind", "operation", "status", "error"), 20
        ),
        "limitations": value.get("limitations", []),
    }


def normalize_inventory(
    value: dict[str, Any], *, previous: dict[str, Any], run_id: str,
    analyses: list[dict[str, Any]], allowed_refs: list[str]
) -> dict[str, Any]:
    inventory = value if isinstance(value, dict) else {}
    previous_runs = previous.get("source_runs", []) if isinstance(previous, dict) else []
    inventory["schema_version"] = "feature-inventory/v1"
    inventory["source_runs"] = sorted(
        {str(item) for item in inventory.get("source_runs", [])}
        | {str(item) for item in previous_runs}
        | {run_id}
    )
    allowed = set(allowed_refs)
    refs_by_feature: dict[str, set[str]] = defaultdict(set)
    for analysis in analyses:
        refs_by_feature[str(analysis.get("feature_id"))].update(analysis.get("evidence_refs", []))
    output_features = [
        item for item in inventory.get("features", []) if isinstance(item, dict)
    ]
    output_ids = {
        normalize_feature_id(str(item.get("feature_id") or item.get("feature_name") or "UNKNOWN"))
        for item in output_features
    }
    previous_features = [
        item
        for item in previous.get("features", [])
        if isinstance(item, dict)
        and normalize_feature_id(
            str(item.get("feature_id") or item.get("feature_name") or "UNKNOWN")
        ) not in output_ids
    ]
    features = []
    used_ids: set[str] = set()
    for feature in output_features + previous_features:
        feature = dict(feature)
        feature_id = normalize_feature_id(str(feature.get("feature_id") or feature.get("feature_name") or "UNKNOWN"))
        if feature_id in used_ids:
            continue
        used_ids.add(feature_id)
        feature["feature_id"] = feature_id
        refs = [ref for ref in feature.get("evidence_refs", []) if ref in allowed]
        feature["evidence_refs"] = sorted(set(refs) | refs_by_feature.get(feature_id, set()))
        observed_runs = {str(item) for item in feature.get("observed_run_ids", [])}
        if refs_by_feature.get(feature_id) or any(ref.startswith(run_id + "/") for ref in refs):
            observed_runs.add(run_id)
        feature["observed_run_ids"] = sorted(observed_runs)
        features.append(feature)
    inventory["features"] = sorted(features, key=lambda item: item["feature_id"])
    coverage = inventory.get("coverage", {})
    coverage["observed_feature_count"] = sum(
        1 for item in features if item.get("status") in {"observed", "partial"}
    )
    coverage["observed_categories"] = sorted(
        {str(item.get("category")) for item in features if item.get("category")}
    )
    coverage.setdefault("blocked_candidate_count", 0)
    coverage.setdefault("notes", [])
    inventory["coverage"] = coverage
    inventory.setdefault("unresolved_questions", [])
    return inventory


def normalize_feature_id(value: str) -> str:
    normalized = re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")
    if not normalized.startswith("F_"):
        normalized = "F_" + normalized
    return normalized[:96] or "F_UNKNOWN"


def step_evidence_refs(run_dir: Path, step_dir: Path) -> list[str]:
    names = (
        "decision.json", "policy.json", "observation.json", "metadata.json",
        "common.json", "trace.log", "before.json", "after.json",
    )
    return [
        f"{run_dir.name}/{step_dir.name}/{name}"
        for name in names
        if (step_dir / name).is_file()
    ]


def inventory_evidence_refs(inventory: dict[str, Any]) -> list[str]:
    return [
        str(ref)
        for feature in inventory.get("features", [])
        if isinstance(feature, dict)
        for ref in feature.get("evidence_refs", [])
    ]


def empty_inventory() -> dict[str, Any]:
    return {
        "schema_version": "feature-inventory/v1",
        "source_runs": [],
        "features": [],
        "coverage": {
            "observed_feature_count": 0,
            "observed_categories": [],
            "blocked_candidate_count": 0,
            "notes": [],
        },
        "unresolved_questions": [],
    }


def _read_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
