import json
from pathlib import Path
import unittest

from automation.models import Bounds, Decision, UINode, UISnapshot
from automation.policy import PolicyEngine


POLICY_PATH = Path(__file__).parents[1] / "risk_policy.json"


def node(index: int, text: str, resource_id: str = "", class_name: str = "android.widget.Button") -> UINode:
    return UINode(
        index=index,
        text=text,
        content_desc="",
        resource_id=resource_id,
        class_name=class_name,
        package="com.kakao.talk",
        clickable=True,
        long_clickable=False,
        checkable=False,
        checked=False,
        enabled=True,
        selected=False,
        scrollable=False,
        password=False,
        bounds=Bounds(0, index * 100, 200, index * 100 + 80),
    )


class PolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PolicyEngine(json.loads(POLICY_PATH.read_text(encoding="utf-8")))

    def snapshot(self, nodes: list[UINode]) -> UISnapshot:
        return UISnapshot("MainActivity", "com.kakao.talk", "<hierarchy/>", nodes, "screen")

    def test_safe_navigation_allowed(self) -> None:
        item = node(0, "친구")
        result = self.policy.assess(Decision("tap", 0), item, self.snapshot([item]))
        self.assertEqual(result.level, "safe")
        self.assertTrue(result.allowed)

    def test_delete_and_send_blocked(self) -> None:
        delete = node(0, "삭제")
        send = node(1, "", "com.kakao.talk:id/send_button_layout")
        snapshot = self.snapshot([delete, send])
        delete_result = self.policy.assess(Decision("tap", 0), delete, snapshot)
        send_result = self.policy.assess(Decision("tap", 1), send, snapshot)
        self.assertEqual(delete_result.level, "state_change")
        self.assertEqual(send_result.level, "external_effect")
        self.assertFalse(delete_result.allowed)
        self.assertFalse(send_result.allowed)

    def test_advertisement_navigation_is_not_in_default_safe_crawl(self) -> None:
        advertisement = node(
            0,
            "Go to Kakao News",
            "com.kakao.talk:id/talk_media_ad_view",
        )
        result = self.policy.assess(
            Decision("tap", 0), advertisement, self.snapshot([advertisement])
        )
        self.assertEqual(result.level, "unknown")
        self.assertFalse(result.allowed)

    def test_generic_confirmation_inherits_context_risk(self) -> None:
        confirm = node(0, "확인")
        delete = node(1, "친구 삭제")
        result = self.policy.assess(Decision("tap", 0), confirm, self.snapshot([confirm, delete]))
        self.assertEqual(result.level, "state_change")

    def test_typing_requires_fixture_but_fixture_can_be_allowed(self) -> None:
        editable = node(
            0,
            "",
            "com.kakao.talk:id/message_edit_text",
            class_name="android.widget.EditText",
        )
        snapshot = self.snapshot([editable])
        blocked = self.policy.assess(Decision("type", 0), editable, snapshot)
        allowed = self.policy.assess(
            Decision("type", 0, fixture_key="test-message"), editable, snapshot
        )
        self.assertEqual(blocked.level, "unknown")
        self.assertFalse(blocked.allowed)
        self.assertEqual(allowed.level, "safe")
        self.assertTrue(allowed.allowed)


if __name__ == "__main__":
    unittest.main()
