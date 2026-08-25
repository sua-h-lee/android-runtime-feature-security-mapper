from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import re
from typing import Any
from xml.etree import ElementTree


_BOUNDS_RE = re.compile(r"\[(?P<x1>\d+),(?P<y1>\d+)\]\[(?P<x2>\d+),(?P<y2>\d+)\]")


@dataclass(frozen=True)
class Bounds:
    x1: int
    y1: int
    x2: int
    y2: int

    @classmethod
    def parse(cls, value: str) -> "Bounds | None":
        match = _BOUNDS_RE.fullmatch(value or "")
        if not match:
            return None
        return cls(*(int(match.group(name)) for name in ("x1", "y1", "x2", "y2")))

    @property
    def center(self) -> tuple[int, int]:
        return ((self.x1 + self.x2) // 2, (self.y1 + self.y2) // 2)

    @property
    def usable(self) -> bool:
        return self.x2 > self.x1 and self.y2 > self.y1

    def compact(self) -> str:
        return f"[{self.x1},{self.y1}][{self.x2},{self.y2}]"


@dataclass(frozen=True)
class UINode:
    index: int
    text: str
    content_desc: str
    resource_id: str
    class_name: str
    package: str
    clickable: bool
    long_clickable: bool
    checkable: bool
    checked: bool
    enabled: bool
    selected: bool
    scrollable: bool
    password: bool
    bounds: Bounds

    @property
    def label(self) -> str:
        return self.text or self.content_desc or self.resource_id.rsplit("/", 1)[-1]

    @property
    def action_key(self) -> str:
        stable = "|".join(
            [self.resource_id, self.text, self.content_desc, self.class_name, self.bounds.compact()]
        )
        return hashlib.sha256(stable.encode("utf-8", errors="replace")).hexdigest()[:20]

    @property
    def is_editable(self) -> bool:
        return self.class_name.endswith("EditText")

    def prompt_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "label": self.label[:120],
            "text": self.text[:120],
            "content_desc": self.content_desc[:120],
            "resource_id": self.resource_id,
            "class": self.class_name,
            "checkable": self.checkable,
            "checked": self.checked,
            "selected": self.selected,
            "editable": self.is_editable,
            "scrollable": self.scrollable,
            "password": self.password,
            "bounds": self.bounds.compact(),
        }


@dataclass
class UISnapshot:
    activity: str | None
    foreground_package: str | None
    xml: str
    nodes: list[UINode]
    signature: str

    def prompt_dict(self) -> dict[str, Any]:
        return {
            "activity": self.activity,
            "foreground_package": self.foreground_package,
            "screen_signature": self.signature,
            "visible_text": visible_text(self.nodes),
        }


@dataclass
class Decision:
    action: str
    node_index: int | None = None
    reason: str = ""
    feature_hint: str = ""
    expected_transition: str = ""
    fixture_key: str | None = None
    source: str = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessment:
    level: str
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_ui_xml(xml: str) -> list[UINode]:
    root = ElementTree.fromstring(xml)
    candidates: list[UINode] = []
    seen: set[tuple[str, str, str, str]] = set()

    for element in root.iter("node"):
        attrs = element.attrib
        bounds = Bounds.parse(attrs.get("bounds", ""))
        if bounds is None or not bounds.usable:
            continue
        enabled = attrs.get("enabled", "true") == "true"
        clickable = attrs.get("clickable", "false") == "true"
        long_clickable = attrs.get("long-clickable", "false") == "true"
        checkable = attrs.get("checkable", "false") == "true"
        class_name = attrs.get("class", "")
        action_class = class_name.endswith(("Button", "ImageButton", "EditText", "CheckBox", "Switch"))
        if not enabled or not (clickable or long_clickable or checkable or action_class or attrs.get("scrollable") == "true"):
            continue

        text = attrs.get("text", "").strip()
        content_desc = attrs.get("content-desc", "").strip()
        resource_id = attrs.get("resource-id", "").strip()
        dedupe_key = (resource_id, text or content_desc, class_name, bounds.compact())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        candidates.append(
            UINode(
                index=len(candidates),
                text=text,
                content_desc=content_desc,
                resource_id=resource_id,
                class_name=class_name,
                package=attrs.get("package", ""),
                clickable=clickable,
                long_clickable=long_clickable,
                checkable=checkable,
                checked=attrs.get("checked", "false") == "true",
                enabled=enabled,
                selected=attrs.get("selected", "false") == "true",
                scrollable=attrs.get("scrollable", "false") == "true",
                password=attrs.get("password", "false") == "true",
                bounds=bounds,
            )
        )
    return candidates


def visible_text(nodes: list[UINode], limit: int = 40) -> list[str]:
    values: list[str] = []
    for node in nodes:
        for value in (node.text, node.content_desc):
            value = value.strip()
            if value and value not in values:
                values.append(value[:160])
                if len(values) >= limit:
                    return values
    return values


def screen_signature(activity: str | None, nodes: list[UINode]) -> str:
    # Ignore volatile bounds and most text when a stable resource id exists.
    parts = [activity or "unknown"]
    for node in nodes:
        identity = node.resource_id or node.content_desc or node.text or node.class_name
        parts.append(f"{node.class_name}|{identity[:120]}")
    material = "\n".join(sorted(parts))
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:20]
