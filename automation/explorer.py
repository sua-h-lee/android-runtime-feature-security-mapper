from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import time
from typing import Any

from .adb import ADBClient, ADBError
from .codex_analyzer import CodexConfig
from .frida_manager import FridaManager, FridaManagerError
from .glm import GLMClient, GLMConfig, GLMError
from .models import Decision, RiskAssessment, UINode, UISnapshot
from .policy import PolicyEngine, RISK_ORDER


@dataclass(frozen=True)
class InputFixture:
    key: str
    resource_id_contains: str = ""
    label_contains: str = ""
    value_env: str = ""
    literal_value: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "InputFixture":
        return cls(
            key=str(value["key"]),
            resource_id_contains=str(value.get("resource_id_contains", "")),
            label_contains=str(value.get("label_contains", "")),
            value_env=str(value.get("value_env", "")),
            literal_value=str(value.get("value", "")),
        )

    def matches(self, node: UINode) -> bool:
        resource_match = not self.resource_id_contains or (
            self.resource_id_contains.casefold() in node.resource_id.casefold()
        )
        label_match = not self.label_contains or (
            self.label_contains.casefold() in node.label.casefold()
        )
        return node.is_editable and resource_match and label_match

    def value(self) -> str | None:
        if self.value_env:
            return os.environ.get(self.value_env)
        return self.literal_value or None

    def public_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "resource_id_contains": self.resource_id_contains,
            "label_contains": self.label_contains,
            "value_env": self.value_env,
            "value_available": self.value() is not None,
        }


@dataclass
class ExplorerConfig:
    config_path: Path
    device_serial: str
    adb_path: str
    package: str
    frida_script: Path
    output_dir: Path
    policy_path: Path
    max_auto_risk: str
    max_steps: int
    max_backtracks: int
    startup_settle_seconds: float
    startup_ready_timeout_seconds: float
    ui_stable_timeout_seconds: float
    trace_quiet_seconds: float
    trace_quiet_timeout_seconds: float
    stop_app_when_done: bool
    goal: str
    fixtures: list[InputFixture]
    glm: GLMConfig
    codex: CodexConfig
    codex_schema: Path
    inventory_path: Path

    @classmethod
    def from_file(
        cls,
        path: Path,
        *,
        max_steps: int | None = None,
        max_auto_risk: str | None = None,
        glm_enabled: bool | None = None,
        vision: bool | None = None,
        goal: str | None = None,
    ) -> "ExplorerConfig":
        path = path.resolve()
        raw = json.loads(path.read_text(encoding="utf-8"))
        base = path.parent

        def resolve(value: str) -> Path:
            candidate = Path(value).expanduser()
            return candidate.resolve() if candidate.is_absolute() else (base / candidate).resolve()

        glm_raw = dict(raw.get("glm", {}))
        if glm_enabled is not None:
            glm_raw["enabled"] = glm_enabled
        if vision is not None:
            glm_raw["vision"] = vision
        return cls(
            config_path=path,
            device_serial=str(raw.get("device_serial", "emulator-5554")),
            adb_path=str(raw.get("adb_path", "adb")),
            package=str(raw.get("package", "com.kakao.talk")),
            frida_script=resolve(str(raw.get("frida_script", "../frida_feature_trace.js"))),
            output_dir=resolve(str(raw.get("output_dir", "../runs"))),
            policy_path=resolve(str(raw.get("policy_path", "risk_policy.json"))),
            max_auto_risk=max_auto_risk or str(raw.get("max_auto_risk", "safe")),
            max_steps=max_steps if max_steps is not None else int(raw.get("max_steps", 20)),
            max_backtracks=int(raw.get("max_backtracks", 10)),
            startup_settle_seconds=float(raw.get("startup_settle_seconds", 3.0)),
            startup_ready_timeout_seconds=float(raw.get("startup_ready_timeout_seconds", 20.0)),
            ui_stable_timeout_seconds=float(raw.get("ui_stable_timeout_seconds", 7.0)),
            trace_quiet_seconds=float(raw.get("trace_quiet_seconds", 1.0)),
            trace_quiet_timeout_seconds=float(raw.get("trace_quiet_timeout_seconds", 5.0)),
            stop_app_when_done=bool(raw.get("stop_app_when_done", True)),
            goal=goal or str(raw.get("goal", "Inventory low-risk KakaoTalk features and normal transitions.")),
            fixtures=[InputFixture.from_dict(item) for item in raw.get("input_fixtures", [])],
            glm=GLMConfig.from_dict(glm_raw),
            codex=CodexConfig.from_dict(dict(raw.get("codex", {}))),
            codex_schema=resolve(
                str(raw.get("codex_schema", "schemas/codex_inventory.schema.json"))
            ),
            inventory_path=resolve(
                str(raw.get("inventory_path", "../inventory/feature-inventory.json"))
            ),
        )

    def public_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["config_path"] = str(self.config_path)
        value["frida_script"] = str(self.frida_script)
        value["output_dir"] = str(self.output_dir)
        value["policy_path"] = str(self.policy_path)
        value["codex_schema"] = str(self.codex_schema)
        value["inventory_path"] = str(self.inventory_path)
        value["fixtures"] = [item.public_dict() for item in self.fixtures]
        value["glm"]["api_key_present"] = bool(os.environ.get(self.glm.api_key_env))
        return value


class AutoExplorer:
    def __init__(self, config: ExplorerConfig):
        self.config = config
        self.adb = ADBClient(config.device_serial, adb_path=config.adb_path)
        self.policy = PolicyEngine.from_file(config.policy_path, max_auto_risk=config.max_auto_risk)
        self.glm = GLMClient(config.glm)
        self.visited_actions: set[tuple[str, str, str]] = set()
        self.blocked_keys: set[tuple[str, str]] = set()
        self.blocked_actions: list[dict[str, Any]] = []
        self.graph_edges: list[dict[str, Any]] = []
        self.errors: list[dict[str, Any]] = []
        self.executed_steps = 0
        self.backtracks = 0
        self.started_at = datetime.now().astimezone()
        self.run_dir = self._create_run_dir()

    def _create_run_dir(self) -> Path:
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        stem = self.started_at.strftime("%Y%m%d-%H%M%S") + "-auto-explore"
        candidate = self.config.output_dir / stem
        suffix = 1
        while candidate.exists():
            candidate = self.config.output_dir / f"{stem}-{suffix}"
            suffix += 1
        return candidate

    def doctor(self) -> dict[str, Any]:
        checks: dict[str, Any] = {
            "device_serial": self.config.device_serial,
            "package": self.config.package,
            "frida_script": {
                "path": str(self.config.frida_script),
                "exists": self.config.frida_script.is_file(),
            },
            "policy": {
                "path": str(self.config.policy_path),
                "exists": self.config.policy_path.is_file(),
                "max_auto_risk": self.policy.max_auto_risk,
            },
            "glm": {
                "available": self.glm.available,
                "reason": self.glm.unavailable_reason(),
                "vision": self.config.glm.vision,
                "model": self.config.glm.model,
            },
            "fixtures": [item.public_dict() for item in self.config.fixtures],
        }
        try:
            self.adb.ensure_device()
            checks["adb"] = {"ok": True}
        except Exception as exc:
            checks["adb"] = {"ok": False, "error": str(exc)}
        try:
            FridaManager._import_frida()
            checks["frida_python"] = {"ok": True}
        except Exception as exc:
            checks["frida_python"] = {"ok": False, "error": str(exc)}
        if self.config.glm.enabled:
            if not self.glm.available:
                checks["glm"]["live_request"] = {
                    "ok": False,
                    "error": self.glm.unavailable_reason(),
                }
            else:
                try:
                    self.glm.probe()
                    checks["glm"]["live_request"] = {"ok": True}
                except GLMError as exc:
                    checks["glm"]["live_request"] = {"ok": False, "error": str(exc)}
        checks["ok"] = bool(
            checks["frida_script"]["exists"]
            and checks["policy"]["exists"]
            and checks["adb"]["ok"]
            and checks["frida_python"]["ok"]
            and (not self.config.glm.enabled or self.glm.available)
            and (
                not self.config.glm.enabled
                or checks["glm"].get("live_request", {}).get("ok") is True
            )
        )
        return checks

    def run(self) -> dict[str, Any]:
        if self.config.glm.enabled and not self.glm.available:
            raise GLMError(self.glm.unavailable_reason() or "GLM is unavailable")
        write_json(self.run_dir / "config.json", self.config.public_dict())
        self.adb.ensure_device()
        self.adb.force_stop(self.config.package)

        manager = FridaManager(
            serial=self.config.device_serial,
            package=self.config.package,
            script_path=self.config.frida_script,
            log_path=self.run_dir / "frida-session.log",
        )
        try:
            manager.start()
            time.sleep(self.config.startup_settle_seconds)
            current = self._wait_for_startup_screen()
            manager.wait_for_quiet(
                quiet_seconds=self.config.trace_quiet_seconds,
                timeout=self.config.trace_quiet_timeout_seconds,
            )
            current = self.adb.wait_for_stable_ui(timeout=self.config.ui_stable_timeout_seconds)
            self._save_snapshot(self.run_dir / "initial", current)
            current = self._explore(manager, current)
            self._save_snapshot(self.run_dir / "final", current)
            status = "completed"
        except KeyboardInterrupt:
            status = "interrupted"
        except Exception as exc:
            status = "failed"
            self.errors.append({"stage": "run", "error": f"{type(exc).__name__}: {exc}"})
            raise
        finally:
            manager.stop()
            if self.config.stop_app_when_done:
                try:
                    self.adb.force_stop(self.config.package)
                except Exception as exc:
                    self.errors.append({"stage": "force_stop", "error": str(exc)})
            summary = self._run_summary(status)
            write_json(self.run_dir / "run-summary.json", summary)
            write_json(self.run_dir / "graph.json", {"edges": self.graph_edges})
            write_json(self.run_dir / "blocked-actions.json", {"actions": self.blocked_actions})
        return summary

    def _explore(self, manager: FridaManager, current: UISnapshot) -> UISnapshot:
        max_iterations = max(30, self.config.max_steps * 5)
        iterations = 0
        while self.executed_steps < self.config.max_steps and iterations < max_iterations:
            iterations += 1
            if current.foreground_package != self.config.package:
                self.errors.append(
                    {
                        "stage": "foreground_check",
                        "error": "Target package left foreground",
                        "foreground_package": current.foreground_package,
                        "activity": current.activity,
                    }
                )
                break

            candidates = self._unvisited_candidates(current)
            fixture_keys = {node.index: self._fixture_keys(node) for node in candidates}
            assessments = {
                node.index: self._assessment_for_candidate(node, current, fixture_keys[node.index])
                for node in candidates
            }
            self._remember_blocked(current, candidates, assessments)
            allowed = [node for node in candidates if assessments[node.index].allowed]

            if not allowed:
                if not self._backtrack(current):
                    break
                current = self.adb.wait_for_stable_ui(timeout=self.config.ui_stable_timeout_seconds)
                continue

            screenshot_for_glm = self.run_dir / "planner-screen.png"
            if self.glm.available and self.config.glm.vision:
                self.adb.screenshot(screenshot_for_glm)
            try:
                if self.glm.available:
                    print("[AUTO] GLM deciding next action...", flush=True)
                decision = self._choose_decision(
                    current, candidates, assessments, fixture_keys, screenshot_for_glm
                )
                if self.glm.available:
                    print("[AUTO] GLM decision received", flush=True)
            except GLMError as exc:
                self.errors.append({"stage": "glm_decision", "error": str(exc)})
                if self.config.glm.enabled:
                    raise
                decision = heuristic_decision(allowed, fixture_keys)

            if decision.action == "stop":
                break
            if decision.action == "back":
                if not self._backtrack(current):
                    break
                current = self.adb.wait_for_stable_ui(timeout=self.config.ui_stable_timeout_seconds)
                continue

            node = node_by_index(candidates, decision.node_index)
            if node is None:
                self.errors.append({"stage": "decision", "error": "Selected node is unavailable"})
                break
            if decision.action == "type" and decision.fixture_key not in fixture_keys[node.index]:
                self.errors.append(
                    {
                        "stage": "decision",
                        "error": "GLM selected an unavailable fixture",
                        "fixture_key": decision.fixture_key,
                    }
                )
                self.visited_actions.add((current.signature, node.action_key, decision.action))
                continue

            risk = self.policy.assess(decision, node, current)
            if not risk.allowed:
                self._remember_one_blocked(current, node, risk, decision)
                self.visited_actions.add((current.signature, node.action_key, decision.action))
                continue

            current = self._execute_transition(manager, current, node, decision, risk)
        return current

    def _unvisited_candidates(self, snapshot: UISnapshot) -> list[UINode]:
        result: list[UINode] = []
        for node in snapshot.nodes:
            action = self._default_action(node)
            if (snapshot.signature, node.action_key, action) not in self.visited_actions:
                result.append(node)
        return result

    @staticmethod
    def _default_action(node: UINode) -> str:
        if node.is_editable:
            return "type"
        if node.scrollable and not node.clickable:
            return "scroll_down"
        return "tap"

    def _fixture_keys(self, node: UINode) -> list[str]:
        return [fixture.key for fixture in self.config.fixtures if fixture.matches(node) and fixture.value() is not None]

    def _assessment_for_candidate(
        self, node: UINode, snapshot: UISnapshot, fixture_keys: list[str]
    ) -> RiskAssessment:
        action = self._default_action(node)
        fixture_key = fixture_keys[0] if action == "type" and fixture_keys else None
        return self.policy.assess(
            Decision(action=action, node_index=node.index, fixture_key=fixture_key), node, snapshot
        )

    def _choose_decision(
        self,
        snapshot: UISnapshot,
        candidates: list[UINode],
        assessments: dict[int, RiskAssessment],
        fixture_keys: dict[int, list[str]],
        screenshot: Path,
    ) -> Decision:
        if self.glm.available:
            return self.glm.decide(
                snapshot=snapshot,
                candidates=candidates,
                assessments=assessments,
                goal=self.config.goal,
                screenshot=screenshot if screenshot.is_file() else None,
                fixture_keys=fixture_keys,
            )
        allowed = [node for node in candidates if assessments[node.index].allowed]
        return heuristic_decision(allowed, fixture_keys)

    def _execute_transition(
        self,
        manager: FridaManager,
        before: UISnapshot,
        node: UINode,
        decision: Decision,
        risk: RiskAssessment,
    ) -> UISnapshot:
        self.executed_steps += 1
        label = decision.feature_hint or node.label or decision.action
        print(
            f"[AUTO] step {self.executed_steps:03d}: {decision.action} {label!r} "
            f"(risk={risk.level})",
            flush=True,
        )
        step_dir = self.run_dir / f"step-{self.executed_steps:03d}-{safe_slug(label)}"
        step_dir.mkdir(parents=True)
        self._save_snapshot(step_dir / "before", before)
        write_json(step_dir / "decision.json", decision.to_dict())
        write_json(step_dir / "policy.json", risk.to_dict())

        segment_label = f"step-{self.executed_steps:03d}:{label}"
        manager.reset_summary(segment_label)
        mark = manager.message_mark()
        manager.mark_user_action("automation_" + decision.action, node.resource_id or node.label)
        started = datetime.now().astimezone()
        self._perform_action(node, decision)
        after = self.adb.wait_for_stable_ui(timeout=self.config.ui_stable_timeout_seconds)
        manager.wait_for_quiet(
            quiet_seconds=self.config.trace_quiet_seconds,
            timeout=self.config.trace_quiet_timeout_seconds,
        )
        common = manager.get_summary()
        finished = datetime.now().astimezone()
        self._save_snapshot(step_dir / "after", after)
        write_json(step_dir / "common.json", common)
        (step_dir / "trace.log").write_text(
            "\n".join(manager.messages_since(mark)) + "\n", encoding="utf-8"
        )

        observation = build_transition_observation(before, after, decision, common, risk, node)
        write_json(step_dir / "observation.json", observation)

        metadata = {
            "step": self.executed_steps,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "action": decision.to_dict(),
            "node": node.prompt_dict(),
            "risk": risk.to_dict(),
            "before_signature": before.signature,
            "after_signature": after.signature,
            "ui_changed": before.signature != after.signature,
            "target_left_foreground": after.foreground_package != self.config.package,
            "common_event_count": common.get("eventCount"),
            "segment_id": common.get("segmentId"),
        }
        write_json(step_dir / "metadata.json", metadata)
        self.graph_edges.append(
            {
                "from": before.signature,
                "to": after.signature,
                "kind": decision.action,
                "label": label,
                "step": self.executed_steps,
                "risk": risk.level,
            }
        )
        self.visited_actions.add((before.signature, node.action_key, decision.action))
        self.backtracks = 0
        return after

    def _perform_action(self, node: UINode, decision: Decision) -> None:
        if decision.action == "scroll_down":
            bounds = node.bounds
            self.adb.scroll_down((bounds.x1, bounds.y1, bounds.x2, bounds.y2))
            return
        x, y = node.bounds.center
        self.adb.tap(x, y)
        if decision.action == "type":
            fixture = self._fixture(decision.fixture_key)
            if fixture is None or fixture.value() is None:
                raise RuntimeError(f"Input fixture is unavailable: {decision.fixture_key}")
            time.sleep(0.3)
            self.adb.input_text(fixture.value() or "")

    def _fixture(self, key: str | None) -> InputFixture | None:
        for fixture in self.config.fixtures:
            if fixture.key == key:
                return fixture
        return None

    def _backtrack(self, before: UISnapshot) -> bool:
        if self.backtracks >= self.config.max_backtracks:
            return False
        self.backtracks += 1
        self.adb.back()
        self.graph_edges.append(
            {"from": before.signature, "to": None, "kind": "back", "label": "navigation_back"}
        )
        time.sleep(0.5)
        return True

    def _wait_for_startup_screen(self) -> UISnapshot:
        deadline = time.monotonic() + self.config.startup_ready_timeout_seconds
        current = self.adb.wait_for_stable_ui(timeout=self.config.ui_stable_timeout_seconds)
        while time.monotonic() < deadline:
            activity = current.activity or ""
            transient = not activity or "SplashActivity" in activity or "TaskRootActivity" in activity
            if current.foreground_package == self.config.package and not transient:
                return current
            time.sleep(0.7)
            current = self.adb.wait_for_stable_ui(timeout=2.5, stable_samples=1)
        self.errors.append(
            {
                "stage": "startup_wait",
                "error": "Startup activity did not leave its transient screen before timeout.",
                "activity": current.activity,
            }
        )
        return current

    def _remember_blocked(
        self,
        snapshot: UISnapshot,
        candidates: list[UINode],
        assessments: dict[int, RiskAssessment],
    ) -> None:
        for node in candidates:
            risk = assessments[node.index]
            if not risk.allowed:
                action = self._default_action(node)
                decision = Decision(
                    action=action,
                    node_index=node.index,
                    fixture_key=(self._fixture_keys(node) or [None])[0],
                    reason="Blocked by unattended exploration policy.",
                    feature_hint=node.label,
                    source="policy",
                )
                self._remember_one_blocked(snapshot, node, risk, decision)

    def _remember_one_blocked(
        self,
        snapshot: UISnapshot,
        node: UINode,
        risk: RiskAssessment,
        decision: Decision,
    ) -> None:
        key = (snapshot.signature, node.action_key)
        if key in self.blocked_keys:
            return
        self.blocked_keys.add(key)
        self.blocked_actions.append(
            {
                "screen_signature": snapshot.signature,
                "activity": snapshot.activity,
                "node": node.prompt_dict(),
                "decision": decision.to_dict(),
                "policy": risk.to_dict(),
                "status": "NOT_EXECUTED_REQUIRES_APPROVAL",
            }
        )

    def _save_snapshot(self, prefix: Path, snapshot: UISnapshot) -> None:
        prefix.parent.mkdir(parents=True, exist_ok=True)
        prefix.with_suffix(".xml").write_text(snapshot.xml, encoding="utf-8")
        self.adb.screenshot(prefix.with_suffix(".png"))
        write_json(
            prefix.with_suffix(".json"),
            {
                "activity": snapshot.activity,
                "foreground_package": snapshot.foreground_package,
                "signature": snapshot.signature,
                "actionable_nodes": [node.prompt_dict() for node in snapshot.nodes],
            },
        )

    def _run_summary(self, status: str) -> dict[str, Any]:
        return {
            "status": status,
            "run_directory": str(self.run_dir),
            "started_at": self.started_at.isoformat(),
            "finished_at": datetime.now().astimezone().isoformat(),
            "executed_steps": self.executed_steps,
            "blocked_action_count": len(self.blocked_actions),
            "visited_screen_count": len(
                {edge["from"] for edge in self.graph_edges if edge.get("from")}
                | {edge["to"] for edge in self.graph_edges if edge.get("to")}
            ),
            "glm_used": self.glm.available,
            "glm_planner_used": self.glm.available,
            "normal_behavior_analyzer": "codex_pending",
            "glm_unavailable_reason": self.glm.unavailable_reason(),
            "max_auto_risk": self.policy.max_auto_risk,
            "errors": self.errors,
        }


def heuristic_decision(
    candidates: list[UINode], fixture_keys: dict[int, list[str]]
) -> Decision:
    if not candidates:
        return Decision(action="back", reason="No allowed unvisited controls remain.")

    def score(node: UINode) -> tuple[int, int]:
        value = 0
        if node.text or node.content_desc:
            value += 5
        if node.resource_id:
            value += 3
        if "tab" in node.content_desc.casefold() or "chip_" in node.resource_id.casefold():
            value -= 4
        if node.selected or node.checked:
            value -= 3
        if node.scrollable and not node.clickable:
            value -= 2
        if any(word in node.label.casefold() for word in ("취소", "닫기", "back", "close", "cancel")):
            value -= 4
        return value, -node.index

    node = max(candidates, key=score)
    if node.is_editable:
        keys = fixture_keys.get(node.index, [])
        if not keys:
            return Decision(action="back", reason="Editable control has no configured fixture.")
        action = "type"
        fixture_key = keys[0]
    elif node.scrollable and not node.clickable:
        action = "scroll_down"
        fixture_key = None
    else:
        action = "tap"
        fixture_key = None
    return Decision(
        action=action,
        node_index=node.index,
        fixture_key=fixture_key,
        reason="Highest-scoring unvisited action allowed by policy.",
        feature_hint=node.label or action,
        expected_transition="Observe the resulting UI and runtime evidence.",
        source="heuristic",
    )


def build_transition_observation(
    before: UISnapshot,
    after: UISnapshot,
    decision: Decision,
    common: dict[str, Any],
    risk: RiskAssessment,
    node: UINode,
) -> dict[str, Any]:
    info = common.get("commonInformation", {})
    protocols = info.get("protocols", {})
    protocol_count = sum(len(value) for value in protocols.values() if isinstance(value, list))
    state_count = len(info.get("state_changes", []))
    destinations = len(info.get("external_destinations", []))
    priority = "low"
    if protocol_count or destinations or RISK_ORDER[risk.level] >= RISK_ORDER["state_change"]:
        priority = "medium"
    if risk.level in {"external_effect", "critical"} and (protocol_count or destinations):
        priority = "high"
    return {
        "schema_version": "runtime-observation/v1",
        "analysis_status": "pending_codex",
        "source": "deterministic_observation_builder",
        "feature_hint": decision.feature_hint or node.label or decision.action,
        "transition": {
            "ui_changed": before.signature != after.signature,
            "before_activity": before.activity,
            "after_activity": after.activity,
        },
        "observed_evidence": {
            "event_count": common.get("eventCount", 0),
            "protocol_count": protocol_count,
            "state_change_count": state_count,
            "external_destination_count": destinations,
        },
        "preliminary_security_priority": priority,
        "preliminary_reasons": [
            "Runtime network/state evidence was observed." if protocol_count or state_count else "UI-only transition observed."
        ],
        "known_analysis_limits": [
            "Authorization and input controllability require targeted tests.",
            "Observed success is not proof of server-side authorization enforcement.",
        ],
        "codex_analysis_required": True,
    }


def node_by_index(nodes: list[UINode], index: int | None) -> UINode | None:
    for node in nodes:
        if node.index == index:
            return node
    return None


def safe_slug(value: str, limit: int = 48) -> str:
    normalized = "-".join(
        "".join(character.casefold() if character.isalnum() else " " for character in value).split()
    )
    return (normalized[:limit] or "action").strip("-")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
