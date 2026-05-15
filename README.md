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
