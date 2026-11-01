#include "app.h"

#include "logger.h"
#include "modloader.h"
#include "paths.h"

#include <cstdint>
#include <cstdio>
#include <string>

namespace fiber {

namespace {

// 游戏主窗口类名(2026-11-01 探针实测:class="Bedrock" title="Minecraft")
constexpr const wchar_t* kGameWindowClass = L"Bedrock";

bool game_window_present() {
    return ::FindWindowW(kGameWindowClass, nullptr) != nullptr;
}

uint64_t hash_wide(const std::wstring& s) {
    uint64_t h = 1469598103934665603ull;
    for (const wchar_t c : s) {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

} // namespace

void app_main(HMODULE self, HANDLE stop_event) {
    const std::wstring root = game_root(self);

    Logger logger;
    if (!logger.init(root)) {
        return;   // 连日志都写不了,静默退出,绝不影响游戏
    }

    logger.log(kInfo, "================ Fiber Runtime 启动 ================");
    logger.log(kInfo, "运行时 DLL   : " + display_path(module_path(self)));
    logger.log(kInfo, "运行时基址   : 0x" + [](uintptr_t v) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
        return std::string(buf);
    }(reinterpret_cast<uintptr_t>(self)));
    logger.log(kInfo, "宿主 exe     : " + display_path(exe_path()));
    logger.log(kInfo, "游戏根目录   : " + display_path(root));
    logger.log(kInfo, "线程 id      : " + std::to_string(::GetCurrentThreadId()));

    // ---- 单实例保护(D36)----
    wchar_t mutex_name[128];
    std::swprintf(mutex_name, std::size(mutex_name), L"Local\\FiberRuntime_%016llX",
                  static_cast<unsigned long long>(hash_wide(root)));
    HANDLE mutex = ::CreateMutexW(nullptr, FALSE, mutex_name);
    if (mutex == nullptr) {
        logger.log(kWarn, "单实例互斥体创建失败,继续运行(风险:可能双重加载)");
    } else if (::GetLastError() == ERROR_ALREADY_EXISTS) {
        logger.log(kWarn, "检测到另一个 Fiber Runtime 实例已在本进程运行,本实例退出");
        logger.close();
        return;
    }

    // ---- 加载 Mod ----
    ModLoader loader;
    if (!loader.init(root, &logger)) {
        logger.log(kError, "ModLoader 初始化失败");
    } else {
        logger.log(kInfo, "游戏版本     : " + loader.game_version());
        loader.load_all();
    }

    // ---- 等待退出 ----
    // 优先等 stop_event(正常退出时 DllMain detach 会置位);
    // 同时监视游戏主窗口:曾出现过又消失 → 判定游戏正在退出,主动干净卸载。
    bool window_seen = game_window_present();
    for (;;) {
        if (::WaitForSingleObject(stop_event, 2000) != WAIT_TIMEOUT) {
            logger.log(kInfo, "收到卸载信号(DLL_PROCESS_DETACH)");
            break;
        }
        const bool present = game_window_present();
        if (present) {
            window_seen = true;
        } else if (window_seen) {
            logger.log(kInfo, "游戏主窗口已消失,判定游戏退出 → 主动卸载");
            break;
        }
    }

    loader.shutdown();
    logger.log(kInfo, "================ Fiber Runtime 退出 ================");
    logger.close();

    if (mutex != nullptr) ::CloseHandle(mutex);
}

} // namespace fiber