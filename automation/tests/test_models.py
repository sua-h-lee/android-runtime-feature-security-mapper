import unittest

from automation.models import Bounds, parse_ui_xml, screen_signature


UI_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.kakao.talk" clickable="false" enabled="true" bounds="[0,0][1080,2400]">
    <node index="1" text="친구" content-desc="" resource-id="com.kakao.talk:id/friends_tab" class="android.widget.Button" package="com.kakao.talk" clickable="true" enabled="true" bounds="[0,2200][270,2400]" />
    <node index="2" text="" content-desc="목록" resource-id="com.kakao.talk:id/list" class="androidx.recyclerview.widget.RecyclerView" package="com.kakao.talk" clickable="false" scrollable="true" enabled="true" bounds="[0,100][1080,2200]" />
  </node>
</hierarchy>
"""


class ModelsTest(unittest.TestCase):
    def test_bounds(self) -> None:
        bounds = Bounds.parse("[10,20][110,220]")
        self.assertIsNotNone(bounds)
        self.assertEqual(bounds.center, (60, 120))

    def test_parse_actionable_nodes_and_signature(self) -> None:
        nodes = parse_ui_xml(UI_XML)
        self.assertEqual(len(nodes), 2)
        self.assertEqual(nodes[0].label, "친구")
        self.assertTrue(nodes[1].scrollable)
        signature = screen_signature("com.kakao.talk/.MainActivity", nodes)
        self.assertEqual(len(signature), 20)


if __name__ == "__main__":
    unittest.main()
