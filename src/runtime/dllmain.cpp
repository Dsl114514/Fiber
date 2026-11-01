// Fiber Runtime —— DllMain
//
// 纪律(与探针一致,实测有效):
//   * DllMain 里绝不做重活 → 只记录句柄/建事件/起线程
//   * preload 通道实测加载时机 t≈0.1–0.35s(游戏尚未初始化)→ 一切推迟到工作线程

#include <windows.h>

#include "app.h"

namespace {

HMODULE g_self = nullptr;
HANDLE  g_stop = nullptr;

DWORD WINAPI runtime_thread(LPVOID) {
    fiber::app_main(g_self, g_stop);
    return 0;
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = static_cast<HMODULE>(instance);
        g_stop = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ::DisableThreadLibraryCalls(static_cast<HMODULE>(instance));
        if (HANDLE thread = ::CreateThread(nullptr, 0, runtime_thread, nullptr, 0, nullptr)) {
            ::CloseHandle(thread);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_stop != nullptr) ::SetEvent(g_stop);
    }
    return TRUE;
}