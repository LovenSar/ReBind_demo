#!/usr/bin/env python3
"""API Key 轮转与恢复逻辑测试

验证：
1. .env 多行同名 key 正确加载为逗号分隔
2. 429 限流时立即切换到下一个 key（不等待）
3. 被封禁的 key 不会被重新使用
4. 当日封禁 → 次日解封
5. 所有 key 耗尽后进入等待状态

运行: python tests/test_api_key_rotation.py
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SA_ROOT = REPO_ROOT / "tools" / "Semantics_Alignment"
KP_DIR = SA_ROOT / "kp"

for p in (str(SA_ROOT), str(KP_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

spec = importlib.util.spec_from_file_location("kp_llm", KP_DIR / "kp_llm.py")
kp_llm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kp_llm)


def _reset_key_state():
    """Reset module-level key state between tests."""
    kp_llm._API_KEYS.clear()
    kp_llm._API_KEY_INDEX = 0
    kp_llm._BLOCKED_KEYS.clear()
    kp_llm._LAST_PARSED_ENV_KEYS = ()
    kp_llm._PRUNED_ON_STARTUP = False


class TestDotenvMultiLineLoading(unittest.TestCase):
    """Test that .env files with multiple OPENAI_API_KEY lines are parsed correctly."""

    def setUp(self):
        _reset_key_state()
        self._orig_env = os.environ.get("OPENAI_API_KEY")
        if "OPENAI_API_KEY" in os.environ:
            del os.environ["OPENAI_API_KEY"]

    def tearDown(self):
        if self._orig_env is not None:
            os.environ["OPENAI_API_KEY"] = self._orig_env
        elif "OPENAI_API_KEY" in os.environ:
            del os.environ["OPENAI_API_KEY"]

    def test_multi_line_same_key(self):
        """Multiple OPENAI_API_KEY= lines should be merged with commas."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("OPENAI_API_KEY=key_AAA\n")
            f.write("OPENAI_API_KEY=key_BBB\n")
            f.write("OPENAI_API_KEY=key_CCC\n")
            f.flush()
            path = Path(f.name)

        try:
            kp_llm._load_dotenv_file(path)
            val = os.environ.get("OPENAI_API_KEY", "")
            self.assertIn("key_AAA", val)
            self.assertIn("key_BBB", val)
            self.assertIn("key_CCC", val)

            keys = kp_llm._parse_api_keys_from_env("OPENAI_API_KEY")
            self.assertEqual(len(keys), 3)
            self.assertEqual(keys, ["key_AAA", "key_BBB", "key_CCC"])
        finally:
            path.unlink()

    def test_numbered_suffix_format(self):
        """OPENAI_API_KEY_1=..., OPENAI_API_KEY_2=... should all merge into OPENAI_API_KEY."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("OPENAI_API_KEY_1=ak_first\n")
            f.write("OPENAI_API_KEY_2=ak_second\n")
            f.write("OPENAI_API_KEY_3=ak_third\n")
            f.flush()
            path = Path(f.name)

        try:
            kp_llm._load_dotenv_file(path)
            val = os.environ.get("OPENAI_API_KEY", "")
            self.assertIn("ak_first", val)
            self.assertIn("ak_second", val)
            self.assertIn("ak_third", val)

            keys = kp_llm._parse_api_keys_from_env("OPENAI_API_KEY")
            self.assertEqual(len(keys), 3)
            self.assertEqual(keys, ["ak_first", "ak_second", "ak_third"])
        finally:
            path.unlink()

    def test_single_line_comma_separated(self):
        """Traditional comma-separated format still works."""
        os.environ["OPENAI_API_KEY"] = "key_X,key_Y"
        keys = kp_llm._parse_api_keys_from_env("OPENAI_API_KEY")
        self.assertEqual(keys, ["key_X", "key_Y"])

    def test_merge_existing_env_with_dotenv_keys_idempotent(self):
        """Existing single key should merge with dotenv multi-keys without duplication."""
        os.environ["OPENAI_API_KEY"] = "env_primary"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("OPENAI_API_KEY_1=dotenv_one\n")
            f.write("OPENAI_API_KEY_2=dotenv_two\n")
            f.flush()
            path = Path(f.name)

        try:
            kp_llm._try_load_api_key_from_dotenv({"dotenv_path": str(path)}, "OPENAI_API_KEY")
            keys = kp_llm._parse_api_keys_from_env("OPENAI_API_KEY")
            self.assertEqual(keys, ["env_primary", "dotenv_one", "dotenv_two"])

            # 再次调用不应重复追加相同 key。
            kp_llm._try_load_api_key_from_dotenv({"dotenv_path": str(path)}, "OPENAI_API_KEY")
            keys_again = kp_llm._parse_api_keys_from_env("OPENAI_API_KEY")
            self.assertEqual(keys_again, ["env_primary", "dotenv_one", "dotenv_two"])
        finally:
            path.unlink()


class TestKeyBlockAndRotate(unittest.TestCase):
    """Test the block-and-rotate mechanism."""

    def setUp(self):
        _reset_key_state()

    def test_block_rotates_to_next(self):
        kp_llm._API_KEYS = ["key_A", "key_B", "key_C"]
        kp_llm._API_KEY_INDEX = 0

        result = kp_llm._block_current_key_and_rotate()
        self.assertTrue(result)
        self.assertTrue(kp_llm._is_key_blocked("key_A"))
        self.assertFalse(kp_llm._is_key_blocked("key_B"))
        self.assertEqual(kp_llm._get_current_api_key(), "key_B")

    def test_block_all_keys(self):
        kp_llm._API_KEYS = ["key_A", "key_B"]
        kp_llm._API_KEY_INDEX = 0

        result1 = kp_llm._block_current_key_and_rotate()
        self.assertTrue(result1)
        self.assertEqual(kp_llm._get_current_api_key(), "key_B")

        result2 = kp_llm._block_current_key_and_rotate()
        self.assertFalse(result2, "Should return False when all keys are blocked")
        self.assertTrue(kp_llm._is_key_blocked("key_A"))
        self.assertTrue(kp_llm._is_key_blocked("key_B"))

    def test_rotate_skips_blocked(self):
        kp_llm._API_KEYS = ["key_A", "key_B", "key_C"]
        kp_llm._API_KEY_INDEX = 0
        kp_llm._BLOCKED_KEYS["key_B"] = time.time()

        result = kp_llm._block_current_key_and_rotate()
        self.assertTrue(result)
        self.assertEqual(kp_llm._get_current_api_key(), "key_C")

    def test_unblock_expired_keys(self):
        import datetime
        yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).timestamp()
        kp_llm._BLOCKED_KEYS["key_old"] = yesterday
        kp_llm._BLOCKED_KEYS["key_new"] = time.time()

        unblocked = kp_llm._unblock_expired_keys()
        self.assertGreaterEqual(unblocked, 1)
        self.assertFalse(kp_llm._is_key_blocked("key_old"), "Yesterday's key should be unblocked")
        self.assertTrue(kp_llm._is_key_blocked("key_new"), "Today's key should stay blocked")


class TestKeyRotationIntegration(unittest.TestCase):
    """Integration test simulating the full 429 → rotate → exhaust → recover cycle."""

    def setUp(self):
        _reset_key_state()

    def test_full_rotation_cycle(self):
        kp_llm._API_KEYS = ["key_1", "key_2", "key_3"]
        kp_llm._API_KEY_INDEX = 0

        print("\n--- Simulating 429 rotation cycle ---")

        self.assertEqual(kp_llm._get_current_api_key(), "key_1")

        ok = kp_llm._block_current_key_and_rotate()
        self.assertTrue(ok)
        self.assertEqual(kp_llm._get_current_api_key(), "key_2")
        print(f"  Key 1 blocked → using key_2")

        ok = kp_llm._block_current_key_and_rotate()
        self.assertTrue(ok)
        self.assertEqual(kp_llm._get_current_api_key(), "key_3")
        print(f"  Key 2 blocked → using key_3")

        ok = kp_llm._block_current_key_and_rotate()
        self.assertFalse(ok)
        print(f"  Key 3 blocked → all exhausted")

        self.assertEqual(len(kp_llm._BLOCKED_KEYS), 3)

        kp_llm._BLOCKED_KEYS.clear()
        self.assertTrue(any(not kp_llm._is_key_blocked(k) for k in kp_llm._API_KEYS))
        print(f"  Keys unblocked → ready to resume")

    def test_keys_not_permanently_deleted(self):
        """Ensure _API_KEYS list is never shrunk (keys are blocked, not deleted)."""
        kp_llm._API_KEYS = ["key_A", "key_B", "key_C"]
        original_count = len(kp_llm._API_KEYS)
        kp_llm._API_KEY_INDEX = 0

        for _ in range(3):
            kp_llm._block_current_key_and_rotate()

        self.assertEqual(len(kp_llm._API_KEYS), original_count,
                         "Key list should not shrink; keys are blocked, not deleted")


if __name__ == "__main__":
    unittest.main(verbosity=2)
