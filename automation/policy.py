from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from .models import Decision, RiskAssessment, UINode, UISnapshot


RISK_ORDER = {
    "safe": 0,
    "unknown": 1,
    "state_change": 2,
    "external_effect": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    level: str
    keywords: tuple[str, ...]
    resource_id_keywords: tuple[str, ...]
    action_types: tuple[str, ...]
    reason: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "PolicyRule":
        level = str(value.get("level", "unknown"))
        if level not in RISK_ORDER:
            raise ValueError(f"Unknown policy risk level: {level}")
        return cls(
            rule_id=str(value["id"]),
            level=level,
            keywords=tuple(str(item).casefold() for item in value.get("keywords", [])),
            resource_id_keywords=tuple(
                str(item).casefold() for item in value.get("resource_id_keywords", [])
            ),
            action_types=tuple(str(item) for item in value.get("action_types", [])),
            reason=str(value.get("reason", value["id"])),
        )


class PolicyEngine:
    def __init__(self, config: dict[str, Any], max_auto_risk: str | None = None):
        configured_level = max_auto_risk or str(config.get("max_auto_risk", "safe"))
        if configured_level not in RISK_ORDER:
            raise ValueError(f"Unknown max_auto_risk: {configured_level}")
        self.max_auto_risk = configured_level
        self.default_unlabeled_risk = str(config.get("default_unlabeled_risk", "unknown"))
        self.generic_confirmation_labels = {
            str(item).casefold() for item in config.get("generic_confirmation_labels", [])
        }
        self.rules = [PolicyRule.from_dict(item) for item in config.get("rules", [])]

    @classmethod
    def from_file(cls, path: Path, max_auto_risk: str | None = None) -> "PolicyEngine":
        return cls(json.loads(path.read_text(encoding="utf-8")), max_auto_risk=max_auto_risk)

    def assess(
        self,
        decision: Decision,
        node: UINode | None,
        snapshot: UISnapshot,
    ) -> RiskAssessment:
        label = "" if node is None else " ".join(
            [node.text, node.content_desc, node.resource_id, node.class_name]
        ).casefold()
        context = " ".join(snapshot.prompt_dict()["visible_text"]).casefold()
        matched: list[PolicyRule] = []

        if node is not None and node.password:
            return RiskAssessment(
                level="critical",
                allowed=False,
                reasons=["Password fields are never explored automatically."],
                matched_rules=["password-field"],
            )

        for rule in self.rules:
            keyword_hit = any(keyword in label for keyword in rule.keywords)
            resource_hit = bool(node) and any(
                keyword in node.resource_id.casefold() for keyword in rule.resource_id_keywords
            )
            action_hit = decision.action in rule.action_types
            if rule.rule_id == "fixture-input" and decision.fixture_key:
                action_hit = False
            if keyword_hit or resource_hit or action_hit:
                matched.append(rule)

        node_label = "" if node is None else node.label.casefold().strip()
        if node_label in self.generic_confirmation_labels:
            for rule in self.rules:
                if any(keyword in context for keyword in rule.keywords):
                    matched.append(rule)

        if matched:
            highest = max(matched, key=lambda rule: RISK_ORDER[rule.level])
            level = highest.level
            reasons = list(dict.fromkeys(rule.reason for rule in matched))
            matched_ids = list(dict.fromkeys(rule.rule_id for rule in matched))
        elif decision.action == "scroll_down":
            level = "safe"
            reasons = ["Scrolling only changes the visible viewport."]
            matched_ids = []
        elif (
            node is not None
            and not (node.text or node.content_desc)
            and not (decision.action == "type" and decision.fixture_key)
        ):
            level = self.default_unlabeled_risk
            reasons = ["The control has no user-visible text or accessibility label."]
            matched_ids = ["unlabeled-control"]
        elif decision.action == "type" and not decision.fixture_key:
            level = "unknown"
            reasons = ["Typing is allowed only through a named test fixture."]
            matched_ids = ["missing-input-fixture"]
        else:
            level = "safe"
            reasons = ["No state-changing or external-effect policy rule matched."]
            matched_ids = []

        allowed = RISK_ORDER[level] <= RISK_ORDER[self.max_auto_risk]
        return RiskAssessment(level=level, allowed=allowed, reasons=reasons, matched_rules=matched_ids)

    def candidate_assessments(self, snapshot: UISnapshot) -> dict[int, RiskAssessment]:
        result: dict[int, RiskAssessment] = {}
        for node in snapshot.nodes:
            action = "type" if node.is_editable else ("scroll_down" if node.scrollable and not node.clickable else "tap")
            result[node.index] = self.assess(Decision(action=action, node_index=node.index), node, snapshot)
        return result
