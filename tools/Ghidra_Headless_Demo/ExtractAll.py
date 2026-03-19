# coding=utf-8
# @runtime Jython
# ExtractAll.py - 合并提取：符号表/字符串/段/节/交叉引用 + 反汇编 + 伪代码
# 兼容 Ghidra 11 和 12，支持断点续跑

from ghidra.program.model.symbol import SymbolTable, SymbolType, Symbol, Namespace, ReferenceManager, Reference
from ghidra.program.model.listing import Listing, FunctionManager, Program, Function
from ghidra.program.model.mem import Memory, MemoryBlock
from ghidra.util.task import ConsoleTaskMonitor

import os
import csv
import sys
import traceback

# --- Config ---
LIMIT_REFS_TO_FUNCTIONS_ONLY = False
MIN_REFS_TO_CREATE_FILE = 1
INCLUDE_BYTES = True
DECOMPILE_TIMEOUT = 120
# --- Config End ---

def sanitize_filename(name, max_len=100):
    if name is None:
        name = "None"
    name = name.replace('.', '_').replace(':', '_').replace('<', '_').replace('>', '_')
    name = name.replace('*', '_').replace('?', '_').replace(' ', '_')
    safe = "".join(c if c.isalnum() or c in ('_', '-') else '_' for c in name).strip('_-')
    while "__" in safe:
        safe = safe.replace("__", "_")
    if len(safe) > max_len:
        safe = safe[:max_len // 3] + "..." + safe[-max_len // 3:]
        safe = "".join(c if c.isalnum() or c in ('_', '-') else '_' for c in safe).strip('_-')
    return safe if safe else "sanitized_empty_name"

def write_csv(filepath, header, data_rows):
    if not data_rows:
        return 0
    println("Writing {} rows to {}...".format(len(data_rows), os.path.basename(filepath)))
    try:
        parent = os.path.dirname(filepath)
        if not os.path.exists(parent):
            os.makedirs(parent)
        is_py3 = sys.version_info[0] >= 3
        mode, kw = ('w', {'newline': '', 'encoding': 'utf-8'}) if is_py3 else ('wb', {})
        with open(filepath, mode, **kw) as f:
            w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            w.writerow(header if is_py3 else [h.encode('utf-8') for h in header])
            for row in data_rows:
                r = [str(x) if x is not None else "" for x in row]
                w.writerow(r if is_py3 else [x.encode('utf-8') for x in r])
        return len(data_rows)
    except Exception as e:
        printerr("Error writing {}: {}".format(filepath, e))
        return -1

# --- Init ---
println("--- ExtractAll: 符号表 + 反汇编 + 伪代码 ---")
try:
    program = currentProgram
    mem = program.getMemory()
    listing = program.getListing()
    symbol_table = program.getSymbolTable()
    func_manager = program.getFunctionManager()
    ref_manager = program.getReferenceManager()
except NameError:
    printerr("Error: 请在 Ghidra 中运行此脚本")
    exit(1)

program_name = program.getName() or "UntitledProgram"
monitor = ConsoleTaskMonitor()

# --- Parse args ---
# 用法: ExtractAll.py <output_base> [导入文件名，与 program.getName() 对齐] [--force|-f]
# shell 传入第二参数为二进制 basename，可与 sanitize 后的子目录名一致（避免仅用无扩展名前缀预建空目录）
output_base = "./"
force_rerun = False
name_override = None
try:
    args = getScriptArgs()
    if args:
        non_flags = []
        for a in args:
            s = str(a) if a is not None else ""
            if s in ("-f", "--force"):
                force_rerun = True
            elif s and not s.startswith("-"):
                non_flags.append(s)
        if len(non_flags) >= 1:
            output_base = os.path.abspath(non_flags[0])
        if len(non_flags) >= 2:
            name_override = non_flags[1]
except NameError:
    pass

safe_name = sanitize_filename(name_override if name_override else program_name)
output_info_dir = os.path.join(output_base, safe_name + "_output")
output_disasm_dir = os.path.join(output_base, safe_name + "_disassembly")
output_pseudo_dir = os.path.join(output_base, safe_name + "_pseudocode")
refs_dir = os.path.join(output_info_dir, safe_name + "_cross_refs")

# ========== 1. Binary Info ==========
info_marker = os.path.join(output_info_dir, safe_name + "_symbols.csv")
if not force_rerun and os.path.exists(info_marker):
    println("--- 跳过 BinaryInfo（已存在，断点续跑）---")
else:
    if not os.path.exists(output_info_dir):
        os.makedirs(output_info_dir)
    if not os.path.exists(refs_dir):
        os.makedirs(refs_dir)

    output_base_path = os.path.join(output_info_dir, safe_name)
    symbol_file = output_base_path + "_symbols.csv"
    string_file = output_base_path + "_strings.csv"
    segment_file = output_base_path + "_segments.csv"
    section_file = output_base_path + "_sections.csv"

    # Symbols
    println("\n--- Extracting Symbol Table ---")
    symbols_data = []
    for sym in symbol_table.getSymbolIterator(True):
        monitor.checkCanceled()
        addr = sym.getAddress()
        ns = sym.getParentNamespace()
        ns_name = ns.getName(True) if ns and ns.getID() != Namespace.GLOBAL_NAMESPACE_ID else "Global"
        symbols_data.append([sym.getName(), str(addr) if addr else "N/A", str(sym.getSymbolType()),
            str(sym.getSource()), str(sym.isGlobal()), str(sym.isPrimary()), str(sym.isExternal()), ns_name])
    write_csv(symbol_file, ["Name", "Address", "Type", "Source", "Is Global", "Is Primary", "Is External", "Namespace"], symbols_data)

    # Strings (try DefinedDataIterator, fallback skip)
    println("\n--- Extracting Strings ---")
    strings_data = []
    try:
        from ghidra.program.util import DefinedDataIterator
        iter_method = getattr(DefinedDataIterator, 'definedData', None) or getattr(DefinedDataIterator, 'definedDataIn', None)
        if iter_method:
            for data in iter_method(program):
                monitor.checkCanceled()
                try:
                    v = data.getValue()
                    if (isinstance(v, str) or (hasattr(__builtins__, 'unicode') and isinstance(v, unicode))) and len(str(v)) >= 4:
                        strings_data.append([str(v), str(data.getAddress()), data.getLength()])
                except Exception:
                    pass
    except Exception as e:
        printerr("Strings extraction skipped: {}".format(e))
    write_csv(string_file, ["String", "Address", "Length"], strings_data)

    # Segments
    println("\n--- Extracting Segments ---")
    segments_data = [[b.getName(), str(b.getStart()), str(b.getEnd()), str(b.getSize()),
        str(b.isRead()), str(b.isWrite()), str(b.isExecute()), str(b.isVolatile()), str(b.isArtificial()), b.getComment() or ""]
        for b in mem.getBlocks()]
    write_csv(segment_file, ["Name", "Start Address", "End Address", "Length", "Read", "Write", "Execute", "Volatile", "Artificial", "Comment"], segments_data)

    # Sections
    sections_data = [[b.getName(), str(b.getStart()), str(b.getEnd()), str(b.getSize())] for b in mem.getBlocks()]
    write_csv(section_file, ["Name", "Start Address", "End Address", "Length"], sections_data)

    # Cross-refs
    println("\n--- Extracting Cross-References ---")
    ref_header = ["Reference From Address", "Reference Type", "Containing Function", "Primary Ref"]
    ref_count = 0
    for sym in symbol_table.getSymbolIterator(True):
        monitor.checkCanceled()
        addr = sym.getAddress()
        if addr is None or not addr.isMemoryAddress() or (LIMIT_REFS_TO_FUNCTIONS_ONLY and sym.getSymbolType() != SymbolType.FUNCTION):
            continue
        refs = []
        try:
            for ref in ref_manager.getReferencesTo(addr):
                fn = func_manager.getFunctionContaining(ref.getFromAddress())
                refs.append([str(ref.getFromAddress()), ref.getReferenceType().getName(),
                    fn.getName(True) if fn else "N/A", str(ref.isPrimary())])
        except Exception:
            continue
        if len(refs) >= MIN_REFS_TO_CREATE_FILE:
            fpath = os.path.join(refs_dir, "{}_{}_{}_refs.csv".format(safe_name, str(addr).replace(':', '_'), sanitize_filename(sym.getName(), 60)))
            if write_csv(fpath, ref_header, refs) > 0:
                ref_count += 1
    println("Generated {} cross-reference files.".format(ref_count))

# ========== 2. Disassembly ==========
skip_disasm = not force_rerun and os.path.exists(output_disasm_dir) and len([f for f in os.listdir(output_disasm_dir) if f.endswith('.asm')]) > 0
if skip_disasm:
    println("\n--- 跳过 Disassembly（已有文件，断点续跑）---")
else:
    if not os.path.exists(output_disasm_dir):
        os.makedirs(output_disasm_dir)
    functions = list(func_manager.getFunctions(True))
    total = len(functions)
    println("\n--- Extracting Disassembly ({} functions) ---".format(total))
    extracted, errors = 0, 0
    for i, func in enumerate(functions):
        if (i + 1) % 50 == 0 or i == total - 1:
            println("   Progress: {}/{}".format(i + 1, total))
        try:
            fpath = os.path.join(output_disasm_dir, "{}_{}.asm".format(func.getEntryPoint(), sanitize_filename(func.getName())))
            with open(fpath, "wb") as f:
                f.write("; Function: {}\n; Address: {}\n; Body: {}\n\n".format(
                    func.getName(), func.getEntryPoint(), func.getBody()).encode('utf-8'))
                count = 0
                for inst in listing.getInstructions(func.getBody(), True):
                    mnem = inst.getMnemonicString() or "DB"
                    ops = ", ".join(inst.getDefaultOperandRepresentation(j) or "" for j in range(inst.getNumOperands()))
                    line = "{:<10} {:<10} {}".format(str(inst.getAddress()), mnem, ops)
                    if INCLUDE_BYTES:
                        try:
                            b = inst.getBytes()
                            line = "{:<40} ; {}".format(line, " ".join("{:02X}".format(x & 0xff) for x in b) if b else "No bytes")
                        except Exception:
                            line = "{:<40} ; (bytes err)".format(line)
                    f.write((line + "\n").encode('utf-8'))
                    count += 1
                if count > 0:
                    extracted += 1
                elif not func.getBody().isEmpty():
                    errors += 1
        except Exception as e:
            printerr("   Error {} @ {}: {}".format(func.getName(), func.getEntryPoint(), e))
            errors += 1
    println("Disassembly: {} extracted, {} errors".format(extracted, errors))

# ========== 3. Pseudocode ==========
skip_pseudo = not force_rerun and os.path.exists(output_pseudo_dir) and len([f for f in os.listdir(output_pseudo_dir) if f.endswith('.c')]) > 0
if skip_pseudo:
    println("\n--- 跳过 Pseudocode（已有文件，断点续跑）---")
else:
    if not os.path.exists(output_pseudo_dir):
        os.makedirs(output_pseudo_dir)
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    if not ifc.openProgram(program):
        printerr("Error: 无法打开反编译器（Ghidra 12 可能缺少 decompile 可执行文件）")
    else:
        functions = list(func_manager.getFunctions(True))
        total = len(functions)
        println("\n--- Extracting Pseudocode ({} functions) ---".format(total))
        decompiled, failed = 0, 0
        try:
            for i, func in enumerate(functions):
                if (i + 1) % 50 == 0 or i == total - 1:
                    println("   Progress: {}/{}".format(i + 1, total))
                try:
                    res = ifc.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)
                    pseudocode = None
                    if res and res.decompileCompleted():
                        hf = res.getHighFunction()
                        if hf:
                            try:
                                df = res.getDecompiledFunction()
                                if df:
                                    pseudocode = df.getC()
                            except Exception:
                                pass
                            if not pseudocode and hasattr(hf, 'getC'):
                                try:
                                    pseudocode = hf.getC()
                                except Exception:
                                    pass
                            # 仅当 getC() 得到非空文本才算成功（df 非 None 不代表有 C 文本；此处只递增一次）
                            if pseudocode:
                                decompiled += 1
                            else:
                                failed += 1
                        else:
                            failed += 1
                    else:
                        failed += 1
                    if pseudocode:
                        fpath = os.path.join(output_pseudo_dir, "{}_{}.c".format(func.getEntryPoint(), sanitize_filename(func.getName())))
                        with open(fpath, "wb") as f:
                            f.write("// Function: {}\n// Address: {}\n\n".format(func.getName(), func.getEntryPoint()).encode('utf-8'))
                            f.write(pseudocode.encode('utf-8'))
                except Exception as e:
                    printerr("   Error {} @ {}: {}".format(func.getName(), func.getEntryPoint(), e))
                    failed += 1
        finally:
            ifc.dispose()
        println("Pseudocode: {} decompiled, {} failed".format(decompiled, failed))

println("\n--- ExtractAll 完成 ---")
println("输出: {}".format(output_base))
