#!/usr/bin/env python3
"""
PE Obfuscator v1.0 — 对 EXE 进行节区加密 + 加载器注入 + 反调试
用法: python3 packer.py <input.exe> [output.exe]

依赖: pip3 install pefile
      sudo apt install mingw-w64
"""

import pefile, random, struct, os, sys, subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STUB_C = os.path.join(SCRIPT_DIR, "stub.c")


# ---------- 加密工具 ----------
def lcg_xor(data, k1, k2):
    """与 stub.c 一致的 LCG XOR 加解密"""
    seed = k1 ^ k2
    out = bytearray(data)
    for i in range(len(out)):
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        out[i] ^= (seed >> 16) & 0xFF
    return bytes(out)


def u16(d, o): return struct.unpack("<H", bytes(d[o:o+2]))[0]
def u32(d, o): return struct.unpack("<I", bytes(d[o:o+4]))[0]


# ---------- 编译加载器 ----------
def compile_stub(oep, text_rva, text_sz, k1, k2):
    """编译带参数的加载器 stub"""
    with open(STUB_C) as f:
        code = f.read()
    code = code.replace("0x00000000   /* Original Entry Point RVA */", f"0x{oep:08X}   /* OEP RVA */")
    code = code.replace("0x00000000   /* .text section RVA */", f"0x{text_rva:08X}   /* .text RVA */")
    code = code.replace("0x00000000   /* .text section size */", f"0x{text_sz:08X}   /* .text size */")
    code = code.replace("0xDEADBEEF   /* XOR key part 1 */", f"0x{k1:08X}   /* key1 */")
    code = code.replace("0xCAFEBABE   /* XOR key part 2 */", f"0x{k2:08X}   /* key2 */")

    src = "/tmp/_obf_stub.c"
    out = "/tmp/_obf_stub.exe"
    with open(src, "w") as f:
        f.write(code)

    cmd = ["x86_64-w64-mingw32-gcc", "-m64", "-Os", "-nostartfiles",
           "-e", "EntryPoint", "-lkernel32", "-lntdll",
           "-Wl,-s", "-o", out, src]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[!] Stub compile error:\n{r.stderr}")
        return None

    # 提取 .text 节区作为 stub 二进制
    sp = pefile.PE(out)
    for s in sp.sections:
        name = s.Name.decode().rstrip('\x00').strip()
        if name in ('.text', 'CODE'):
            return s.get_data()
    with open(out, "rb") as f:
        return f.read()


# ---------- 主流程 ----------
def pack(inpath, outpath):
    print(f"[*] 读取: {inpath}")

    with open(inpath, "rb") as f:
        raw = bytearray(f.read())

    # 解析 PE 结构
    pe_off = u32(raw, 0x3C)
    num_sects = u16(raw, pe_off + 6)
    opt_hdr_sz = u16(raw, pe_off + 20)
    opt_hdr = pe_off + 4 + 20
    sect_start = opt_hdr + opt_hdr_sz

    # 找 .text
    text_rva = text_sz = text_raw = 0
    for i in range(num_sects):
        sh = sect_start + i * 40
        name = raw[sh:sh+8].rstrip(b'\x00').decode('latin-1').strip()
        if name == '.text':
            text_rva = u32(raw, sh + 12)
            text_sz = u32(raw, sh + 16)
            text_raw = u32(raw, sh + 20)
            break
    if not text_sz:
        print("[!] .text 节区未找到")
        return False

    oep = u32(raw, opt_hdr + 0x10)
    fa = u32(raw, opt_hdr + 0x3C) or 0x200
    sa = u32(raw, opt_hdr + 0x38) or 0x1000

    print(f"    OEP: 0x{oep:08X}")
    print(f"    .text: VA=0x{text_rva:X} size=0x{text_sz:X}")

    # 生成密钥
    k1 = random.randint(0, 0xFFFFFFFF)
    k2 = random.randint(0, 0xFFFFFFFF)
    print(f"    密钥: 0x{k1:08X} 0x{k2:08X}")

    # 编译加载器
    print("[*] 编译加载器 stub...")
    stub = compile_stub(oep, text_rva, text_sz, k1, k2)
    if stub is None:
        return False
    print(f"    Stub: {len(stub)} 字节")

    # 加密 .text
    raw_text = bytes(raw[text_raw:text_raw + text_sz])
    raw[text_raw:text_raw + text_sz] = lcg_xor(raw_text, k1, k2)
    print(f"[+] .text 已加密 (0x{text_sz:X} bytes)")

    # 计算新节区 (.crypt)
    last_sh = sect_start + (num_sects - 1) * 40
    lva = u32(raw, last_sh + 12); lvs = u32(raw, last_sh + 8)
    lro = u32(raw, last_sh + 20); lrs = u32(raw, last_sh + 16)

    nva = ((lva + lvs + sa - 1) // sa) * sa
    nro = ((lro + lrs + fa - 1) // fa) * fa
    nrs = ((len(stub) + fa - 1) // fa) * fa
    nvs = ((len(stub) + sa - 1) // sa) * sa

    # 写入 stub 数据
    while len(raw) < nro:
        raw.append(0)
    raw.extend(stub)
    while len(raw) < nro + nrs:
        raw.append(0)

    # 添加节区表
    new_sh_off = sect_start + num_sects * 40
    while len(raw) < new_sh_off + 40:
        raw.append(0)
    sec_hdr = struct.pack('<8sIIIIIIHHI',
        b'.crypt\x00\x00', nvs, nva, nrs, nro,
        0, 0, 0, 0, 0xE0000020)
    struct.pack_into("<40s", raw, new_sh_off, sec_hdr)

    # 更新 PE 头
    struct.pack_into("<H", raw, pe_off + 6, num_sects + 1)  # Sections count
    struct.pack_into("<I", raw, opt_hdr + 0x10, nva)         # EntryPoint
    struct.pack_into("<I", raw, opt_hdr + 0x38, nva + nvs)   # SizeOfImage

    # 写出
    with open(outpath, "wb") as f:
        f.write(raw)

    # 验证
    try:
        vp = pefile.PE(outpath)
        print(f"[+] 输出: {outpath}")
        print(f"    节区: {vp.FILE_HEADER.NumberOfSections}")
        print(f"    入口: 0x{vp.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
        print(f"    大小: {os.path.getsize(outpath) // 1024} KB")
        return True
    except Exception as e:
        print(f"[!] PE 验证失败: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 packer.py <input.exe> [output.exe]")
        sys.exit(1)
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.splitext(inp)[0] + "_obfuscated.exe"
    if not os.path.exists(inp):
        print(f"[!] 文件不存在: {inp}")
        sys.exit(1)
    pack(inp, out)
