#!/bin/bash

# Ghidra Headless 分析脚本 - 精简版
# 使用方法: ./input_prehandle_start.sh <二进制文件路径>
# 支持 Ghidra 11/12，单次运行完成全部分析，直接在二进制所在目录输出

# Ghidra 路径
GHIDRA_11_PATH="/Users/lovensar/Applications/ghidra_11.4.3_PUBLIC_20251203/ghidra_11.4.3_PUBLIC/support/analyzeHeadless"
GHIDRA_12_PATH="/Users/lovensar/Applications/ghidra_12.0.4_PUBLIC_20260303/ghidra_12.0.4_PUBLIC/support/analyzeHeadless"

# 自动检测 Ghidra：进入本分支时一律清空 GHIDRA_CMD，再按 11→12 选择，避免无效路径残留导致跳过检测
if [ -z "$GHIDRA_CMD" ] || [ ! -e "$GHIDRA_CMD" ]; then
  if [ -n "${GHIDRA_CMD:-}" ] && [ ! -e "$GHIDRA_CMD" ]; then
    echo "Warning: GHIDRA_CMD 路径无效，将尝试自动检测: $GHIDRA_CMD"
  fi
  GHIDRA_CMD=""
  [ -e "$GHIDRA_11_PATH" ] && GHIDRA_CMD="$GHIDRA_11_PATH" && echo "使用 Ghidra 11"
  [ -z "$GHIDRA_CMD" ] && [ -e "$GHIDRA_12_PATH" ] && GHIDRA_CMD="$GHIDRA_12_PATH" && echo "使用 Ghidra 12"
  [ -z "$GHIDRA_CMD" ] && { echo "Error: 未找到 Ghidra，请设置 GHIDRA_CMD"; exit 1; }
else
  echo "使用: $GHIDRA_CMD"
fi

# 参数解析（支持 --force / -f 强制重跑，可放在二进制前后）
FORCE_ARG=""
BINARY_ARG=""
for arg in "$@"; do
  case "$arg" in
    --force|-f) FORCE_ARG="--force" ;;
    *) [ -z "$BINARY_ARG" ] && BINARY_ARG="$arg" ;;
  esac
done
[ -z "$BINARY_ARG" ] && { echo "Usage: $0 <binary> [--force]"; exit 1; }
[ ! -f "$BINARY_ARG" ] && { echo "Error: 文件不存在: $BINARY_ARG"; exit 1; }
[ -d "$BINARY_ARG" ] && { echo "Error: 请提供文件而非目录"; exit 1; }

# 路径解析（二进制所在目录即为工作目录）
INPUT_FILE="$(cd "$(dirname "$BINARY_ARG")" && pwd)/$(basename "$BINARY_ARG")"
FILE_DIR="$(dirname "$INPUT_FILE")"
FILE_NAME="$(basename "$INPUT_FILE")"
BASE_NAME="${FILE_NAME%.*}"

# 输出目录：外层仍用无扩展名前缀（与 README 一致）；子目录由 ExtractAll 按 sanitize(文件名) 创建，勿用 BASE_NAME 预建否则会留下空目录
OUTPUT_BASE="${FILE_DIR}/${BASE_NAME}_ghidemo"
mkdir -p "$OUTPUT_BASE"

# 临时项目目录（分析结束后删除）
PROJECT_DIR="${TMPDIR:-/tmp}/ghidra_${BASE_NAME}_$$"
mkdir -p "$PROJECT_DIR"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "分析: $FILE_NAME"
echo "输出: $OUTPUT_BASE"
[ -n "$FORCE_ARG" ] && echo "模式: 强制重跑"
[ -n "${GHIDRA_EXTRA_OPTS:-}" ] && echo "Ghidra 附加参数: $GHIDRA_EXTRA_OPTS"

# 可选：export GHIDRA_EXTRA_OPTS="-max-cpu 4" 等（见 analyzeHeadlessREADME）
declare -a EXTRA_HEADLESS=()
if [ -n "${GHIDRA_EXTRA_OPTS:-}" ]; then
  # shellcheck disable=SC2206
  EXTRA_HEADLESS=($GHIDRA_EXTRA_OPTS)
fi

# 单次 Ghidra 运行：导入 + 分析 + 单一提取脚本（支持断点续跑，传 --force 则全量重跑）
"$GHIDRA_CMD" "$PROJECT_DIR" "proj" "${EXTRA_HEADLESS[@]}" \
  -import "$INPUT_FILE" \
  -scriptPath "$SCRIPT_DIR" \
  -postScript ExtractAll.py "$OUTPUT_BASE" "$FILE_NAME" $FORCE_ARG

# 清理临时项目
rm -rf "$PROJECT_DIR"

echo "完成: $OUTPUT_BASE"
