"""VarLedger 集成导出中复用单次函数反编译结果。"""

import os


def bounded_symbol_filename(directory, prefix, name, suffix, sanitize, max_path_length=240,
                            max_name_length=100):
    """给深层 VarLedger 导出路径预留长度，避免 Windows MAX_PATH 截断符号文件。"""
    fixed_path = os.path.join(directory, prefix + suffix)
    name_budget = min(max_name_length, max_path_length - len(fixed_path))
    if name_budget <= 0:
        return prefix + suffix
    safe_name = sanitize(name, max_len=name_budget)
    return prefix + safe_name[:name_budget] + suffix


def function_pseudocode_filename(pseudo_dir, ea, name, sanitize, max_path_length=240):
    """为 Windows 长导出目录限制函数名长度，同时保留地址作为稳定主键。"""
    prefix = "0x%X_" % ea
    return bounded_symbol_filename(pseudo_dir, prefix, name, ".c", sanitize,
                                   max_path_length=max_path_length)


def export_functions_once(functions, decompile, render, emit, map_function, on_error=None,
                          cache_lookup=None, cache_restore=None, on_cache_complete=None):
    """逐函数只反编译一次，并把同一个 cfunc 交给伪代码和映射消费者。

    ``functions`` 元素为 ``(ea, name)``。返回值不保留 cfunc，避免大型样本把
    全部 Hex-Rays 语法树长期留在内存中。
    """
    results = []
    for ea, name in functions:
        cfunc = None
        try:
            payload = cache_lookup(ea, name) if cache_lookup is not None else None
            if payload is not None and cache_restore is not None:
                restored = cache_restore(ea, name, payload)
                if restored:
                    emit(ea, name, payload["pseudo_text"])
                    if on_cache_complete is not None:
                        on_cache_complete(ea, name, payload)
                    results.append((ea, "completed", "cache_hit"))
                    continue
            cfunc = decompile(ea)
            if cfunc is None:
                raise ValueError("Hex-Rays 没有返回函数反编译结果")
            code = render(cfunc)
            emit(ea, name, code)
            map_function(ea, cfunc, code)
            results.append((ea, "completed", None))
        except Exception as error:
            if on_error is not None:
                on_error(ea, name, error)
            results.append((ea, "failed", str(error)))
    return results
