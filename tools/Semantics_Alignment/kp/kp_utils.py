"""kp_utils.py

通用工具函数，供 kp 包内部及 breadth/、depth/ 下各模块共享使用。
所有函数均不依赖其他 kp_* 模块，以避免循环导入。
"""

from __future__ import annotations

import builtins
import inspect
from pathlib import Path


def install_print_with_location() -> None:
    """将全局 print 替换为带调用位置前缀的版本（幂等，重复调用无副作用）。

    输出格式：``<绝对路径>:<行号> <原始消息>``

    该函数在 breadth/pipeline.py、breadth/alignment_loader.py 和 idat_server.py 中
    原本各自独立定义，现统一到此处。
    """
    if getattr(builtins, "_original_print", None):
        return

    builtins._original_print = builtins.print  # type: ignore[attr-defined]

    def _print_with_location(*args, **kwargs):
        frame = inspect.currentframe()
        if frame and frame.f_back:
            caller = frame.f_back
            path = Path(caller.f_code.co_filename).resolve()
            lineno = caller.f_lineno
            prefix = f"{path}:{lineno} "
        else:
            prefix = ""
        message = " ".join(str(a) for a in args)
        builtins._original_print(f"{prefix}{message}", **kwargs)

    builtins.print = _print_with_location  # type: ignore[assignment]
