# PE Obfuscator 🛡️

.text 节区加密 + 加载器注入 + 反调试 — 单文件，即插即用。

---

## Prerequisites

```bash
pip install pefile
sudo apt install mingw-w64
```

## One‑Shot

```bash
cd ~/.openclaw/workspace/projects/pe-obfuscator
./packer.sh input.exe output.exe
```

把 `output.exe` 拖到 Windows 上，运行即自动解密执行。

## What It Does

| Layer | Mechanism |
|-------|-----------|
| 🔐 .text 加密 | LCG XOR，每文件随机密钥 |
| 🧩 Stub 注入 | 新建 `.crypt` 节区，含解密 loader |
| 🕵️ 反调试 | PEB.BeingDebugged + NtGlobalFlag 检测 |
| 🎯 OEP 劫持 | 入口指向 stub，隐藏原始入口点 |

## File Layout

```
packer.sh      — 一键封装
packer.py      — 核心混淆引擎
stub.c         — 运行时解密加载器 (编译进 PE)
test_app.c     — 用于验证的测试程序
```
