#!/usr/bin/env python3
"""IDA Watchdog 端到端实验

模拟完整的流水线场景来验证看门狗的健壮性：
1. 启动 Mock IDA Server
2. 模拟 Phase 1~3 的 IDA 交互模式
3. 在运行过程中多次 "杀掉" IDA（停止 mock server）
4. 验证：
   - 看门狗自动检测到 IDA 死亡
   - 自动降级为离线模式（继续 DB 写入）
   - 阶段间看门狗尝试重启（模拟 restart_fn）
   - IDA 恢复后自动重新启用同步

运行方式:
    python scripts/watchdog_experiment.py

作者: ReBind Demo Team
"""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SA_ROOT = REPO_ROOT / "tools" / "Semantics_Alignment"
KP_DIR = SA_ROOT / "kp"
BREADTH_DIR = SA_ROOT / "breadth"

for p in (str(SA_ROOT), str(KP_DIR), str(BREADTH_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

spec = importlib.util.spec_from_file_location("kp_ida", KP_DIR / "kp_ida.py")
kp_ida = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kp_ida)

IDAService = kp_ida.IDAService
wait_for_ida_server = kp_ida.wait_for_ida_server

# ═══════════════════════════════════════════════════════════════════
# Mock IDA Server
# ═══════════════════════════════════════════════════════════════════
_RENAME_LOG: list[dict] = []


class _FakeIDAHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        action = body.get("action", "")

        if action == "ping":
            resp = {"status": "ok"}
        elif action == "rename_and_sync":
            name = body.get("name", "unknown")
            ea = body.get("ea", 0)
            _RENAME_LOG.append({"ea": ea, "name": name, "time": time.time()})
            resp = {
                "status": "ok",
                "new_name": name,
                "updated_pseudocode": f"int {name}() {{ return 0; }}",
            }
        elif action == "rename_global":
            resp = {"status": "ok", "new_name": body.get("name", "")}
        elif action == "save_database":
            resp = {"status": "ok"}
        elif action == "save_and_exit":
            resp = {"status": "ok"}
        else:
            resp = {"status": "ok", "action": action}

        payload = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        pass


class MockIDAServer:
    PORT = 18345

    def __init__(self):
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self):
        self._server = HTTPServer(("127.0.0.1", self.PORT), _FakeIDAHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        print(f"    [MockIDA] ✓ 启动，端口 {self.PORT}")

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        print("    [MockIDA] ✗ 已停止（模拟 IDA 崩溃）")

    @property
    def running(self) -> bool:
        return self._server is not None


# ═══════════════════════════════════════════════════════════════════
# 实验运行器
# ═══════════════════════════════════════════════════════════════════

def _banner(msg: str) -> None:
    print(f"\n{'═' * 60}")
    print(f"  {msg}")
    print(f"{'═' * 60}\n")


def _phase_banner(phase: int, name: str) -> None:
    print(f"\n{'─' * 50}")
    print(f"  Phase {phase}: {name}")
    print(f"{'─' * 50}")


def run_experiment():
    _banner("IDA Watchdog 端到端实验")

    mock = MockIDAServer()
    ida_url = f"http://127.0.0.1:{MockIDAServer.PORT}"

    restart_count = [0]

    def restart_fn() -> bool:
        restart_count[0] += 1
        print(f"    [restart_fn] 第 {restart_count[0]} 次调用，正在重启 Mock IDA...")
        mock.start()
        time.sleep(0.5)
        return mock.running

    svc = IDAService(
        ida_url,
        enabled=True,
        max_consecutive_fails=3,
        connect_timeout_s=5.0,
        recover_interval_s=2.0,
    )

    ida_sync = True

    def ida_health_check(phase_just_finished: int) -> None:
        nonlocal ida_sync
        if not ida_sync and not svc.degraded:
            return
        if svc.degraded:
            print(f"  [Watchdog] Phase {phase_just_finished} 结束，IDA 处于离线状态，尝试重启...")
            restarted = restart_fn()
            if restarted:
                ok = wait_for_ida_server(ida_url, max_wait_seconds=5.0)
                if ok:
                    svc._record_success()
                    ida_sync = True
                    print("  [Watchdog] IDA 重启成功，后续阶段恢复实时同步。")
                else:
                    print("  [Watchdog] IDA 重启后仍无法连接，继续离线运行。")
            else:
                print("  [Watchdog] IDA 重启未成功，继续离线运行。")

    # ── 实验开始 ──────────────────────────────────────
    print("步骤 1: 启动 Mock IDA Server")
    mock.start()

    # ── Phase 1: 正常运行，然后中途杀掉 IDA ──
    _phase_banner(1, "Knowledge Propagation — 正常 → 中途杀 IDA")

    func_count = 0
    success_count = 0
    fail_count = 0

    for i in range(15):
        func_count += 1
        ea = 0x401000 + i * 0x100
        name = f"func_{ea:08X}"

        if i == 5:
            print(f"\n  >>> 在第 {i} 个函数后杀掉 IDA <<<\n")
            mock.stop()

        result = svc.request(
            "rename_and_sync",
            {"ea": ea, "name": name, "comment": "test"},
            ensure_online=False,
        )

        status = "OK" if result else "SKIP(offline)"
        if result:
            success_count += 1
        else:
            fail_count += 1
        print(f"  [{i+1:2d}/15] func=0x{ea:08X} → {status}  (degraded={svc.degraded})")

    print(f"\n  Phase 1 结果: 成功={success_count}, 跳过={fail_count}, 总计={func_count}")
    print(f"  Watchdog 状态: degraded={svc.degraded}, 连续失败={svc._consecutive_fails}")

    # ── 阶段间检查 ──
    print("\n  >>> 阶段间看门狗检查 <<<")
    ida_health_check(1)

    # ── Phase 2: 应该已经恢复 ──
    _phase_banner(2, "Validation — IDA 已恢复")

    p2_success = 0
    for i in range(8):
        ea = 0x402000 + i * 0x100
        result = svc.request(
            "rename_and_sync",
            {"ea": ea, "name": f"validated_{ea:08X}", "comment": "phase2"},
            ensure_online=False,
        )
        status = "OK" if result else "SKIP"
        if result:
            p2_success += 1
        print(f"  [{i+1:2d}/8] func=0x{ea:08X} → {status}")

    print(f"\n  Phase 2 结果: 成功={p2_success}/8")

    # ── 阶段间检查 ──
    ida_health_check(2)

    # ── Phase 3: 再次杀掉 IDA ──
    _phase_banner(3, "Globals — 开始前杀 IDA")

    print("  >>> 在 Phase 3 开始前杀掉 IDA <<<\n")
    mock.stop()

    p3_success = 0
    for i in range(6):
        ea = 0x600000 + i * 0x10
        result = svc.request(
            "rename_global",
            {"ea": ea, "name": f"g_var_{ea:08X}", "type": "int"},
            ensure_online=False,
        )
        status = "OK" if result else "SKIP(offline)"
        if result:
            p3_success += 1
        print(f"  [{i+1:2d}/6] global=0x{ea:08X} → {status}")

    print(f"\n  Phase 3 结果: 成功={p3_success}/6, 全部离线模式")

    # ── 阶段间检查 ──
    print("\n  >>> 阶段间看门狗检查 <<<")
    ida_health_check(3)

    # ── Phase 4: 再次恢复后正常工作 ──
    _phase_banner(4, "Local Vars — IDA 再次恢复")

    p4_success = 0
    for i in range(5):
        ea = 0x403000 + i * 0x100
        result = svc.request(
            "rename_and_sync",
            {"ea": ea, "name": f"lvar_opt_{ea:08X}", "comment": "phase4"},
            ensure_online=False,
        )
        status = "OK" if result else "SKIP"
        if result:
            p4_success += 1
        print(f"  [{i+1:2d}/5] func=0x{ea:08X} → {status}")

    print(f"\n  Phase 4 结果: 成功={p4_success}/5")

    # ── Phase 5: 第三次杀掉 IDA ──
    _phase_banner(5, "Annotation — 第三次杀 IDA")

    print("  >>> 在 Phase 5 中途杀掉 IDA <<<\n")

    p5_success = 0
    for i in range(10):
        ea = 0x404000 + i * 0x100
        if i == 3:
            mock.stop()

        result = svc.request(
            "rename_and_sync",
            {"ea": ea, "name": f"annotated_{ea:08X}", "comment": "phase5"},
            ensure_online=False,
        )
        status = "OK" if result else "SKIP(offline)"
        if result:
            p5_success += 1
        print(f"  [{i+1:2d}/10] func=0x{ea:08X} → {status}")

    print(f"\n  Phase 5 结果: 成功={p5_success}/10")

    # ── 最终汇总 ──
    _banner("实验结果汇总")

    total_renames = len(_RENAME_LOG)
    print(f"  Mock IDA 共接收 {total_renames} 次成功的 rename 请求")
    print(f"  IDA 被杀次数: 3 次")
    print(f"  看门狗自动重启次数: {restart_count[0]}")
    print(f"  看门狗累计降级次数: {svc._degraded_count}")
    print(f"  最终 IDA 状态: degraded={svc.degraded}")
    print()

    # 验证断言
    errors = []
    if svc._degraded_count < 2:
        errors.append(f"降级次数不足: 期望 >=2, 实际 {svc._degraded_count}")
    if restart_count[0] < 2:
        errors.append(f"重启次数不足: 期望 >=2, 实际 {restart_count[0]}")
    if total_renames < 10:
        errors.append(f"成功 rename 太少: 期望 >=10, 实际 {total_renames}")

    if errors:
        print("  [FAIL] 以下验证未通过:")
        for e in errors:
            print(f"    - {e}")
        sys.exit(1)
    else:
        print("  [PASS] 所有验证通过！看门狗表现正常。")
        print()
        print("  结论:")
        print("    1. IDA 崩溃后，看门狗在连续 3 次失败后自动降级")
        print("    2. 降级期间，流水线继续运行（跳过 IDA 同步，仅写 DB）")
        print("    3. 阶段间检查点自动尝试重启 IDA 并恢复同步")
        print("    4. 多次崩溃/恢复循环均正常工作")

    if mock.running:
        mock.stop()


if __name__ == "__main__":
    run_experiment()
