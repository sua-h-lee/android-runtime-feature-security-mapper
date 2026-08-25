import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation.codex_analyzer import (
    CodexConfig,
    CodexInventoryAnalyzer,
    compact_common_summary,
    empty_inventory,
    normalize_inventory,
)


def feature(feature_id: str = "F_TEST") -> dict:
    return {
        "feature_id": feature_id,
        "feature_name": "Test feature",
        "category": "navigation",
        "status": "observed",
        "description": "Observed test transition",
        "actors": [],
        "entry_points": ["test button"],
        "preconditions": [],
        "screens": ["MainActivity"],
        "normal_flow": ["Tap test button"],
        "security_assets": [],
        "controllable_inputs": [],
        "trust_boundaries": [],
        "protocols": [],
        "expected_authorization": [],
        "state_changes": [],
        "data_storage": [],
        "external_destinations": [],
        "failure_behavior": [],
        "security_priority": "low",
        "security_unknowns": [],
        "recommended_follow_up": [],
        "evidence_refs": [],
        "observed_run_ids": []
    }


class CodexAnalyzerTest(unittest.TestCase):
    def test_compact_common_summary_removes_evidence_ref_fanout(self) -> None:
        raw = {
            "schemaVersion": "security-observation/v1",
            "segmentId": "segment-1",
            "eventCount": 12,
            "commonInformation": {
                "entry_points": [{
                    "kind": "click", "target": "button", "evidence_refs": ["e1"] * 100
                }],
                "protocols": {"http": [{
                    "method": "GET", "host": "example.test", "route": "/x",
                    "responseCodes": [200], "evidence_refs": ["e2"] * 100
                }]},
                "observed_input_fields": [],
                "state_changes": [],
                "external_destinations": [],
                "failure_behavior": [],
                "screens": []
            }
        }
        compact = compact_common_summary(raw)
        serialized = json.dumps(compact)
        self.assertNotIn("evidence_refs", serialized)
        self.assertEqual(compact["protocols"]["http"]["total"], 1)

    def test_normalize_inventory_preserves_unmentioned_previous_feature(self) -> None:
        old = feature("F_OLD")
        old["evidence_refs"] = ["old-run/step-001/common.json"]
        old["observed_run_ids"] = ["old-run"]
        previous = empty_inventory()
        previous["features"] = [old]
        current = empty_inventory()
        current["features"] = [feature("F_NEW")]
        analysis = {
            "feature_id": "F_NEW",
            "evidence_refs": ["new-run/step-001/common.json"]
        }
        normalized = normalize_inventory(
            current,
            previous=previous,
            run_id="new-run",
            analyses=[analysis],
            allowed_refs=["old-run/step-001/common.json", "new-run/step-001/common.json"],
        )
        by_id = {item["feature_id"]: item for item in normalized["features"]}
        self.assertEqual(set(by_id), {"F_NEW", "F_OLD"})
        self.assertEqual(by_id["F_OLD"]["observed_run_ids"], ["old-run"])
        self.assertEqual(by_id["F_NEW"]["observed_run_ids"], ["new-run"])

    def test_analyze_run_writes_step_analysis_and_global_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "20260825-test-auto-explore"
            step_dir = run_dir / "step-001-test"
            step_dir.mkdir(parents=True)
            for name, value in {
                "decision.json": {"action": "tap", "feature_hint": "test"},
                "policy.json": {"level": "safe", "allowed": True},
                "observation.json": {"analysis_status": "pending_codex"},
                "metadata.json": {"step": 1, "segment_id": "segment-1"},
                "common.json": {"eventCount": 1, "commonInformation": {"protocols": {}}},
                "before.json": {"activity": "MainActivity", "actionable_nodes": []},
                "after.json": {"activity": "MainActivity", "actionable_nodes": []},
            }.items():
                (step_dir / name).write_text(json.dumps(value), encoding="utf-8")
            (step_dir / "trace.log").write_text("", encoding="utf-8")
            (run_dir / "run-summary.json").write_text(
                json.dumps({"status": "completed", "executed_steps": 1}), encoding="utf-8"
            )
            (run_dir / "blocked-actions.json").write_text(
                json.dumps({"actions": []}), encoding="utf-8"
            )
            response_feature = feature()
            response_feature["evidence_refs"] = [
                f"{run_dir.name}/{step_dir.name}/common.json"
            ]
            response = {
                "schema_version": "codex-runtime-analysis/v1",
                "run_id": run_dir.name,
                "step_analyses": [{
                    "step_id": step_dir.name,
                    "feature_id": "F_TEST",
                    "feature_label": "Test feature",
                    "category": "navigation",
                    "normal_behavior": ["Tap keeps MainActivity visible"],
                    "observed_evidence": ["One runtime event"],
                    "security_priority": "low",
                    "priority_reasons": [],
                    "security_unknowns": [],
                    "recommended_follow_up": [],
                    "confidence": "medium",
                    "inference_notes": [],
                    "evidence_refs": [f"{run_dir.name}/{step_dir.name}/common.json"]
                }],
                "inventory": {
                    "schema_version": "feature-inventory/v1",
                    "source_runs": [run_dir.name],
                    "features": [response_feature],
                    "coverage": {
                        "observed_feature_count": 1,
                        "observed_categories": ["navigation"],
                        "blocked_candidate_count": 0,
                        "notes": []
                    },
                    "unresolved_questions": []
                }
            }
            analyzer = CodexInventoryAnalyzer(
                config=CodexConfig(enabled=True),
                workspace_dir=root,
                inventory_path=root / "inventory" / "feature-inventory.json",
                schema_path=root / "schema.json",
            )
            with patch.object(analyzer, "doctor", return_value={"ok": True}), patch.object(
                analyzer, "_run_codex", return_value=response
            ):
                result = analyzer.analyze_run(run_dir)
            self.assertEqual(result["status"], "completed")
            analysis = json.loads((step_dir / "analysis.json").read_text(encoding="utf-8"))
            self.assertEqual(analysis["source"], "codex")
            self.assertTrue((root / "inventory" / "feature-inventory.json").is_file())


if __name__ == "__main__":
    unittest.main()
