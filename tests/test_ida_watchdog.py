#!/usr/bin/env python3
"""IDA Watchdog 集成测试

模拟 IDA HTTP 服务器的启动/崩溃/重启，验证看门狗机制：
1. IDA 正常运行 → IDAService 正常请求
2. IDA 崩溃 → 连续失败后自动降级
3. IDA 恢复 → 自动检测并恢复同步

运行方式:
    python tests/test_ida_watchdog.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import time
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SA_ROOT = REPO_ROOT / "tools" / "Semantics_Alignment"
KP_DIR = SA_ROOT / "kp"

for p in (str(SA_ROOT), str(KP_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

spec = importlib.util.spec_from_file_location("kp_ida", KP_DIR / "kp_ida.py")
kp_ida = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kp_ida)

IDAService = kp_ida.IDAService
wait_for_ida_server = kp_ida.wait_for_ida_server


class _FakeIDAHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that mimics idat_server responses."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        action = body.get("action", "")

        if action == "ping":
            resp = {"status": "ok"}
        elif action == "rename_and_sync":
            resp = {
                "status": "ok",
                "new_name": body.get("name", "unknown"),
                "updated_pseudocode": "int fake_func() { return 0; }",
            }
        else:
            resp = {"status": "ok", "action": action}

        payload = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


class FakeIDAServer:
    """Context-manager wrapper around a throwaway HTTP server."""

    def __init__(self, port: int = 0):
        self._requested_port = port
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> int:
        self._server = HTTPServer(("127.0.0.1", self._requested_port), _FakeIDAHandler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def running(self) -> bool:
        return self._server is not None


class TestIDAWatchdog(unittest.TestCase):

    def test_normal_request(self):
        """IDA 正常时，request 应该返回有效数据。"""
        srv = FakeIDAServer()
        port = srv.start()
        try:
            svc = IDAService(f"http://127.0.0.1:{port}", enabled=True, connect_timeout_s=5.0)
            result = svc.request("ping", ensure_online=False)
            self.assertIsNotNone(result)
            self.assertEqual(result["status"], "ok")
            self.assertFalse(svc.degraded)
        finally:
            srv.stop()

    def test_auto_degrade_after_consecutive_failures(self):
        """IDA 崩溃后，连续 N 次失败应触发自动降级。"""
        srv = FakeIDAServer()
        port = srv.start()
        url = f"http://127.0.0.1:{port}"

        svc = IDAService(url, enabled=True, max_consecutive_fails=3, connect_timeout_s=3.0, recover_interval_s=1.0)

        result = svc.request("ping", ensure_online=False)
        self.assertIsNotNone(result)
        self.assertFalse(svc.degraded)

        srv.stop()
        time.sleep(0.3)

        for i in range(3):
            result = svc.request("ping", ensure_online=False)
            self.assertIsNone(result)

        self.assertTrue(svc.degraded, "Should be degraded after 3 consecutive failures")

        result = svc.request("ping", ensure_online=False)
        self.assertIsNone(result, "Degraded mode should return None immediately")

    def test_auto_recover_after_restart(self):
        """IDA 崩溃 → 降级 → 重启 IDA → 自动恢复。"""
        srv = FakeIDAServer()
        port = srv.start()
        url = f"http://127.0.0.1:{port}"

        svc = IDAService(url, enabled=True, max_consecutive_fails=2, connect_timeout_s=3.0, recover_interval_s=1.0)

        result = svc.request("ping", ensure_online=False)
        self.assertIsNotNone(result)

        srv.stop()
        time.sleep(0.3)

        for _ in range(2):
            svc.request("ping", ensure_online=False)
        self.assertTrue(svc.degraded)

        srv2 = FakeIDAServer(port=port)
        srv2.start()
        try:
            time.sleep(1.5)

            result = svc.request("ping", ensure_online=False)
            self.assertIsNotNone(result, "Should recover after IDA restart + recover interval")
            self.assertFalse(svc.degraded, "Should exit degraded mode after successful recover")

            result2 = svc.request("ping", ensure_online=False)
            self.assertIsNotNone(result2, "Subsequent requests should work normally")
        finally:
            srv2.stop()

    def test_wait_for_ida_server_bounded(self):
        """wait_for_ida_server 使用 max_wait_seconds 时不应无限阻塞。"""
        t0 = time.time()
        ok = wait_for_ida_server("http://127.0.0.1:19999", max_wait_seconds=3.0, retry_interval_s=1.0)
        elapsed = time.time() - t0
        self.assertFalse(ok)
        self.assertLess(elapsed, 10.0, "Should return within a reasonable time")

    def test_multiple_degrade_recover_cycles(self):
        """模拟多次 IDA 崩溃/恢复循环（类似用户手动杀 IDA 2-3 次）。"""
        srv = FakeIDAServer()
        port = srv.start()
        url = f"http://127.0.0.1:{port}"

        svc = IDAService(url, enabled=True, max_consecutive_fails=2, connect_timeout_s=3.0, recover_interval_s=0.5)

        for cycle in range(3):
            result = svc.request("ping", ensure_online=False)
            self.assertIsNotNone(result, f"Cycle {cycle}: should work when IDA is up")
            self.assertFalse(svc.degraded)

            srv.stop()
            time.sleep(0.2)

            for _ in range(2):
                svc.request("ping", ensure_online=False)
            self.assertTrue(svc.degraded, f"Cycle {cycle}: should degrade after IDA killed")

            srv = FakeIDAServer(port=port)
            srv.start()
            time.sleep(1.0)

            result = svc.request("ping", ensure_online=False)
            self.assertIsNotNone(result, f"Cycle {cycle}: should recover after restart")
            self.assertFalse(svc.degraded, f"Cycle {cycle}: should exit degraded mode")

        self.assertEqual(svc._degraded_count, 3, "Should have degraded exactly 3 times")
        srv.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
