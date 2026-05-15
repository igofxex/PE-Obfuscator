# PE Obfuscator 🛡️

由 OpenClaw 驱动的 PE 代码混淆工具。通过对 .text 节区加密、加载器注入与反调试检测，提高逆向分析门槛，维护开发者的权益。

## 效果

| 保护层 | 说明 |
|--------|------|
| 🔐 .text 加密 | LCG XOR 流加密，每文件随机密钥，IDA/Debugger 中 .text 完全乱码 |
| 🧩 Stub 注入 | 新建 `.crypt` 可执行节区，注入解密加载器，运行时代理解密并跳回 OEP |
| 🕵️ 反调试 | PEB.BeingDebugged + NtGlobalFlag 双重检测，发现调试器则死循环阻塞分析 |
| 🎯 OEP 劫持 | 原始入口点被加密隐藏，程序从 Stub 开始执行 |

## 环境要求

```bash
pip install pefile
sudo apt install mingw-w64
```

## 使用方法

```bash
./packer.sh input.exe output.exe
```

将生成的 `output.exe` 在 Windows 上运行即可。

## 工作原理

```
input.exe
    │
    ├─ ① 解析 PE 结构，定位 .text 节区
    ├─ ② 生成随机密钥，LCG XOR 加密 .text
    ├─ ③ 编译 stub.c，注入为 .crypt 新节区
    ├─ ④ 入口点重定向到 stub
    └─ output.exe

运行时:
    .crypt(stub) → 反调试检测 → 解密 .text → 跳转 OEP
```

## 文件结构

```
packer.sh      — 一键封装脚本
packer.py      — 核心混淆引擎 (PE 解析 + 加密 + 注入)
stub.c         — 运行时解密加载器 (MinGW 编译注入到 PE)
test_app.c     — 验证用测试程序
USAGE.md       — 简洁使用参考
```

## 注意事项

- 仅支持 **64 位 Windows PE** (x86-64)
- 被混淆的程序不能已有其他加密壳
- 某些杀软可能对注入行为敏感，建议签名后再分发
