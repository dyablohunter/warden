import unittest

from tests.helpers import make_settings
from warden.config import TUNABLE, apply_overrides, parse_env_file, severity_rank


class ConfigTests(unittest.TestCase):
    def test_parse_env(self):
        env = parse_env_file('# c\nA=1\nexport B="two words"\nC=\'x#y\'\nD=val # comment\nE=\nbad line\n')
        self.assertEqual(env, {"A": "1", "B": "two words", "C": "x#y", "D": "val", "E": ""})

    def test_defaults_deepseek(self):
        s = make_settings()
        self.assertEqual(s.llm.provider, "deepseek")
        self.assertEqual(s.llm.model, "deepseek-chat")
        self.assertEqual(s.llm.base_url, "https://api.deepseek.com")
        self.assertEqual(s.llm.api_key, "test-key")
        self.assertEqual(s.autonomy, "full")

    def test_swap_provider(self):
        s = make_settings(LLM_PROVIDER="anthropic", ANTHROPIC_API_KEY="ak")
        self.assertEqual(s.llm.adapter, "anthropic")
        self.assertEqual(s.llm.api_key, "ak")
        s = make_settings(LLM_PROVIDER="openai", OPENAI_API_KEY="ok")
        self.assertIsNone(s.llm)
        self.assertIn("LLM_MODEL", s.llm_error)
        s = make_settings(LLM_PROVIDER="custom", LLM_BASE_URL="http://x/v1/", LLM_MODEL="m")
        self.assertEqual(s.llm.base_url, "http://x/v1")

    def test_fallback(self):
        s = make_settings(LLM_FALLBACK_PROVIDER="ollama", LLM_FALLBACK_MODEL="llama")
        self.assertEqual(s.llm_fallback.provider, "ollama")

    def test_bad_autonomy_is_safe(self):
        self.assertEqual(make_settings(WARDEN_AUTONOMY="yolo").autonomy, "observe")

    def test_overrides_bounded(self):
        s = make_settings()
        apply_overrides(s, {"ssh_max_failures": "1", "conn_per_ip_max": "999999", "unknown": "5"})
        self.assertEqual(s.ssh_max_failures, TUNABLE["ssh_max_failures"][0])
        self.assertEqual(s.conn_per_ip_max, TUNABLE["conn_per_ip_max"][1])

    def test_severity(self):
        self.assertGreater(severity_rank("critical"), severity_rank("medium"))
        self.assertEqual(severity_rank("bogus"), 0)


if __name__ == "__main__":
    unittest.main()
