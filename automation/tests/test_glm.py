import os
import unittest
from unittest.mock import patch

from automation.glm import GLMClient, GLMConfig, GLMError, extract_json_object


class GLMTest(unittest.TestCase):
    def test_extract_plain_json(self) -> None:
        self.assertEqual(extract_json_object('{"action":"stop"}')["action"], "stop")

    def test_extract_fenced_json(self) -> None:
        value = extract_json_object('```json\n{"action":"tap","node_index":2}\n```')
        self.assertEqual(value["node_index"], 2)

    def test_reject_non_json(self) -> None:
        with self.assertRaises(GLMError):
            extract_json_object("click the first button")

    def test_environment_can_override_provider_defaults(self) -> None:
        with patch.dict(
            os.environ,
            {"GLM_BASE_URL": "https://example.test/v1", "GLM_MODEL": "test-model"},
        ):
            config = GLMConfig.from_dict(
                {"base_url": "https://api.z.ai/api/paas/v4", "model": "glm-5.1"}
            )
        self.assertEqual(config.base_url, "https://example.test/v1")
        self.assertEqual(config.model, "test-model")

    def test_vision_is_rejected_before_calling_text_only_model(self) -> None:
        client = GLMClient(
            GLMConfig(
                enabled=True,
                base_url="https://api.z.ai/api/paas/v4",
                model="glm-5.1",
                vision=True,
            )
        )
        self.assertFalse(client.available)
        self.assertIn("Remove --vision", client.unavailable_reason() or "")

    def test_probe_requires_positive_json_acknowledgement(self) -> None:
        client = GLMClient(GLMConfig(enabled=True))
        with patch.object(client, "_chat", return_value={"ok": True}):
            self.assertTrue(client.probe()["ok"])
        with patch.object(client, "_chat", return_value={"ok": False}):
            with self.assertRaises(GLMError):
                client.probe()


if __name__ == "__main__":
    unittest.main()
