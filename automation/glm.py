from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Any
from urllib import error, request

from .models import Decision, RiskAssessment, UINode, UISnapshot


class GLMError(RuntimeError):
    pass


@dataclass
class GLMConfig:
    enabled: bool = False
    base_url: str = ""
    model: str = ""
    api_key_env: str = "GLM_API_KEY"
    timeout_seconds: float = 45.0
    vision: bool = False
    include_ui_text: bool = True

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "GLMConfig":
        return cls(
            enabled=bool(value.get("enabled", False)),
            base_url=str(os.environ.get("GLM_BASE_URL") or value.get("base_url", "")),
            model=str(os.environ.get("GLM_MODEL") or value.get("model", "")),
            api_key_env=str(value.get("api_key_env", "GLM_API_KEY")),
            timeout_seconds=float(value.get("timeout_seconds", 45.0)),
            vision=bool(value.get("vision", False)),
            include_ui_text=bool(value.get("include_ui_text", True)),
        )


class GLMClient:
    def __init__(self, config: GLMConfig):
        self.config = config

    @property
    def available(self) -> bool:
        return bool(
            self.config.enabled
            and self.config.base_url
            and self.config.model
            and not self.config.vision
            and os.environ.get(self.config.api_key_env)
        )

    def unavailable_reason(self) -> str | None:
        if not self.config.enabled:
            return "GLM integration is disabled in config."
        if not self.config.base_url:
            return "GLM base_url is missing (config or GLM_BASE_URL)."
        if not self.config.model:
            return "GLM model is missing (config or GLM_MODEL)."
        if self.config.vision:
            return (
                f"Configured model {self.config.model} is text-only in this program. "
                "Remove --vision to use GLM-5.1."
            )
        if not os.environ.get(self.config.api_key_env):
            return f"Environment variable {self.config.api_key_env} is missing."
        return None

    def _endpoint(self) -> str:
        base = self.config.base_url.rstrip("/")
        return base if base.endswith("/chat/completions") else base + "/chat/completions"

    def _chat(self, system: str, payload: dict[str, Any], screenshot: Path | None = None) -> dict[str, Any]:
        if not self.available:
            raise GLMError(self.unavailable_reason() or "GLM is unavailable")

        user_text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

        body = {
            "model": self.config.model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_text},
            ],
        }
        api_key = os.environ[self.config.api_key_env]
        http_request = request.Request(
            self._endpoint(),
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(http_request, timeout=self.config.timeout_seconds) as response:
                envelope = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise GLMError(f"GLM HTTP {exc.code}: {detail[:800]}") from exc
        except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise GLMError(f"GLM request failed: {exc}") from exc

        try:
            content = envelope["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise GLMError(f"Unexpected GLM response envelope: {envelope}") from exc
        if isinstance(content, list):
            content = "".join(str(item.get("text", "")) for item in content if isinstance(item, dict))
        return extract_json_object(str(content))

    def probe(self) -> dict[str, Any]:
        result = self._chat(
            "Return exactly one JSON object and no prose: {\"ok\":true}",
            {"task": "connection_check"},
        )
        if result.get("ok") is not True:
            raise GLMError(f"Unexpected GLM connection-check response: {result}")
        return result

    def decide(
        self,
        *,
        snapshot: UISnapshot,
        candidates: list[UINode],
        assessments: dict[int, RiskAssessment],
        goal: str,
        screenshot: Path | None,
        fixture_keys: dict[int, list[str]],
    ) -> Decision:
        candidate_payload: list[dict[str, Any]] = []
        for node in candidates[:80]:
            item = node.prompt_dict()
            if not self.config.include_ui_text:
                item["label"] = ""
                item["text"] = ""
                item["content_desc"] = ""
            item["policy"] = assessments[node.index].to_dict()
            item["available_fixture_keys"] = fixture_keys.get(node.index, [])
            candidate_payload.append(item)

        screen = snapshot.prompt_dict()
        if not self.config.include_ui_text:
            screen["visible_text"] = []
        payload = {
            "goal": goal,
            "screen": screen,
            "candidates": candidate_payload,
            "rules": {
                "choose_one_action": True,
                "never_bypass_policy": True,
                "typing_requires_fixture_key": True,
            },
        }
        system = (
            "You are a conservative Android UI exploration planner for an authorized test account. "
            "Choose exactly one candidate that improves feature coverage. Never invent coordinates, "
            "never request raw credentials, and never bypass a policy decision. Prefer policy.allowed=true. "
            "Return JSON only with keys: action (tap|type|scroll_down|back|stop), node_index, fixture_key, reason, "
            "feature_hint, expected_transition. For type, fixture_key must be one of the candidate's "
            "available_fixture_keys. Use stop when no useful allowed action exists."
        )
        result = self._chat(system, payload, screenshot=screenshot)
        action = str(result.get("action", "stop"))
        if action not in {"tap", "type", "scroll_down", "back", "stop"}:
            raise GLMError(f"GLM returned unsupported action: {action}")
        node_index = result.get("node_index")
        if action in {"tap", "type", "scroll_down"}:
            if not isinstance(node_index, int) or node_index not in {node.index for node in candidates}:
                raise GLMError(f"GLM returned invalid node_index: {node_index}")
        else:
            node_index = None
        return Decision(
            action=action,
            node_index=node_index,
            fixture_key=result.get("fixture_key") or None,
            reason=str(result.get("reason", "")),
            feature_hint=str(result.get("feature_hint", "")),
            expected_transition=str(result.get("expected_transition", "")),
            source="glm",
        )

def extract_json_object(text: str) -> dict[str, Any]:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.IGNORECASE)
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end <= start:
            raise GLMError(f"GLM did not return a JSON object: {text[:500]}")
        try:
            value = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError as exc:
            raise GLMError(f"GLM returned invalid JSON: {text[:500]}") from exc
    if not isinstance(value, dict):
        raise GLMError("GLM response JSON must be an object")
    return value
