#define FIBER_RUNTIME_RES_ID 101

#ifdef _WIN32
#pragma message("Embedding FiberRuntime.dll as BIN resource")
#endif

#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    // This script embeds the runtime DLL into the launcher EXE
    // Run: python tools/embed_resource.py build/dist/FiberRuntime.dll build/dist/fiber.exe
    printf("Usage: python tools/embed_resource.py <runtime.dll> <launcher.exe>\n");
    return 0;
}
