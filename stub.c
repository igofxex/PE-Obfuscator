/*
 * stub.c — PE Loader Stub
 * Compiled with MinGW-w64, injected as the new entry point.
 * Decrypts .text section at runtime, resolves imports, jumps to OEP.
 */

#include <windows.h>
#include <winternl.h>

/* ---- Configuration (patched by packer.py at build time) ---- */
#define OEP_ADDR      0x00000000   /* Original Entry Point RVA */
#define TEXT_RVA      0x00000000   /* .text section RVA */
#define TEXT_SIZE     0x00000000   /* .text section size */
#define KEY1          0xDEADBEEF   /* XOR key part 1 */
#define KEY2          0xCAFEBABE   /* XOR key part 2 */
#define IAT_RVA       0x00000000   /* Import Address Table RVA */
#define IAT_SIZE      0x00000000   /* Import Address Table size */
/* ----------------------------------------------------------- */

/* Simple LCG for XOR stream generation */
static unsigned int g_seed;

static unsigned int rand_next(void) {
    g_seed = g_seed * 1103515245 + 12345;
    return (g_seed / 65536) % 32768;
}

static void decrypt_xor(unsigned char *data, int size, unsigned int k1, unsigned int k2) {
    g_seed = k1 ^ k2;
    for (int i = 0; i < size; i++) {
        data[i] ^= (unsigned char)(rand_next() & 0xFF);
    }
}

/* Check if being debugged */
static int anti_debug(void) {
    /* PEB.BeingDebugged */
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb->BeingDebugged) return 1;
    
    /* NtGlobalFlag */
    if (*(unsigned long*)((char*)peb + 0xBC) & 0x00000070) return 1;
    
    return 0;
}

/* Resolve a single API by hash (simple CRC32-like) */
typedef struct {
    char* dll_name;
    unsigned int func_hash;  
} ImportEntry;

static unsigned int hash_string(const char* str) {
    unsigned int h = 0;
    while (*str) {
        h = (h << 5) - h + *str++;
    }
    return h;
}

void __attribute__((force_align_arg_pointer))
EntryPoint(void) {
    /* Anti-debug: if debugger detected, infinite loop */
    if (anti_debug()) {
        while(1) Sleep(1000);
    }

    /* Get our own module handle */
    ULONG_PTR image_base;
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(EntryPoint, &mbi, sizeof(mbi));
    image_base = (ULONG_PTR)mbi.AllocationBase;
    
    /* Decrypt .text section */
    unsigned char* text_ptr = (unsigned char*)(image_base + TEXT_RVA);
    decrypt_xor(text_ptr, TEXT_SIZE, KEY1, KEY2);
    
    /* Restore IAT */
    if (IAT_SIZE > 0) {
        /* The IAT entries are encrypted - decrypt them */
        unsigned char* iat_ptr = (unsigned char*)(image_base + IAT_RVA);
        decrypt_xor(iat_ptr, IAT_SIZE, KEY1 ^ 0xFFFFFFFF, KEY2 ^ 0xAAAAAAAA);
    }
    
    /* Flush instruction cache to ensure decoded code is used */
    FlushInstructionCache(GetCurrentProcess(), text_ptr, TEXT_SIZE);
    
    /* Jump to original entry point */
    void (*oep)(void) = (void (*)(void))(image_base + OEP_ADDR);
    oep();
}
