"""kp/_compat.py

向后兼容别名集中存放处。

历史遗留代码可以继续从 kp.kp_config / kp.kp_types 导入带 _ 前缀的名称，
但新代码应直接使用不带 _ 的正式名称。

    - kp.kp_config: get_cfg_int / get_cfg_float / get_cfg_bool / get_cfg_section
    - kp.kp_types:  count_effective_pseudocode_lines / find_generic_lvar_names

此模块不对外导出，仅供内部向后兼容使用，不应被新代码直接 import。
"""

from .kp_config import (
    get_cfg_bool as _get_cfg_bool,
    get_cfg_float as _get_cfg_float,
    get_cfg_int as _get_cfg_int,
    get_cfg_section as _get_cfg_section,
)
from .kp_types import (
    count_effective_pseudocode_lines as _count_effective_pseudocode_lines,
    find_generic_lvar_names as _find_generic_lvar_names,
)

__all__ = [
    "_get_cfg_bool",
    "_get_cfg_float",
    "_get_cfg_int",
    "_get_cfg_section",
    "_count_effective_pseudocode_lines",
    "_find_generic_lvar_names",
]
