#!/bin/bash
# PE Obfuscator v1.0
# 用法: ./packer.sh <input.exe> [output.exe]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ $# -lt 1 ]; then
    echo "用法: $0 <input.exe> [output.exe]"
    echo ""
    echo "功能:"
    echo "  - .text 节区加密 (XOR LCG)"
    echo "  - 加载器 stub 注入 (新 .crypt 节区)"
    echo "  - 反调试检测 (PEB, NtGlobalFlag)"
    echo "  - 入口点重定向"
    echo ""
    echo "示例:"
    echo "  $0 myapp.exe"
    echo "  $0 myapp.exe protected.exe"
    exit 1
fi

INPUT="$1"
OUTPUT="${2:-${INPUT%.exe}_obfuscated.exe}"

if [ ! -f "$INPUT" ]; then
    echo "[!] 文件不存在: $INPUT"
    exit 1
fi

python3 "$SCRIPT_DIR/packer.py" "$INPUT" "$OUTPUT"

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "  ✓ 混淆成功!"
    echo "========================================"
    echo "在 Windows 上运行: $OUTPUT"
    echo ""
    echo "保护清单:"
    echo "  ✓ .text 节区已加密"
    echo "  ✓ 加载器 stub 已注入"
    echo "  ✓ 反调试检测已启用"
    echo "  ✓ 入口点已重定向"
else
    echo ""
    echo "[!] 混淆失败"
    exit 1
fi
