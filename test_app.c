#include <windows.h>
#include <stdio.h>

int main() {
    printf("Hello from obfuscated PE!\n");
    printf("If you see this, the stub worked.\n");
    printf("Press any key to exit...\n");
    getchar();
    return 0;
}
