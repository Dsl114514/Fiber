// Fiber — 通道探针(M1 第一交付物,D38)
//
// 目的:验证 preload 通道能否加载"我们自己命名的 DLL"、加载时机有多早、
//       以及进程内路径推导是否成立。**本阶段只写日志,不装任何 hook**。
//
// 设计纪律(与最终 Runtime 相同):
//   * DllMain 里绝不做重活:只记录自模块句柄/时间戳,然后 CreateThread
//   * 所有文件 IO、模块枚举、路径推导都在工作线程里做
//   * 不等待任何进程级锁,不抛异常,任何 API 失败都写进日志而不是崩掉宿主
//
// 输出:<游戏根目录>\fiber_probe.log(追加写)
// 注:WIN32_LEAN_AND_MEAN / NOMINMAX / UNICODE 由 CMake 目标定义提供(见 src/probe/CMakeLists.txt)

#include <windows.h>
#include <psapi.h>

#include <cstdarg>
#include <cstdio>
#include <iterator>
#include <string>
#include <vector>

namespace {

HMODULE   g_self        = nullptr;
HANDLE    g_stop        = nullptr;
FILE*     g_log         = nullptr;
DWORD     g_attach_tid  = 0;
ULONGLONG g_attach_tick = 0;

// ---------- 基础工具 ----------

std::string u8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                          s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring module_path(HMODULE m) {
    std::wstring buf(32768, L'\0');
    const DWORD n = ::GetModuleFileNameW(m, buf.data(), static_cast<DWORD>(buf.size()));
    buf.resize(n);
    return buf;
}

std::wstring dir_of(const std::wstring& p) {
    const size_t pos = p.find_last_of(L"\\/");
    return pos == std::wstring::npos ? std::wstring{} : p.substr(0, pos);
}

std::wstring file_name_of(const std::wstring& p) {
    const size_t pos = p.find_last_of(L"\\/");
    return pos == std::wstring::npos ? p : p.substr(pos + 1);
}

void log_line(const char* fmt, ...) {
    if (g_log == nullptr) return;
    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    std::fprintf(g_log, "[%02u:%02u:%02u.%03u tid=%lu t=%llums] ",
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 static_cast<unsigned long>(::GetCurrentThreadId()),
                 static_cast<unsigned long long>(::GetTickCount64() - g_attach_tick));
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(g_log, fmt, ap);
    va_end(ap);
    std::fputc('\n', g_log);
    std::fflush(g_log);
}

std::wstring env_w(const wchar_t* name) {
    wchar_t buf[1024];
    const DWORD n = ::GetEnvironmentVariableW(name, buf, static_cast<DWORD>(std::size(buf)));
    return n == 0 ? std::wstring{} : std::wstring(buf, n);
}

// ---------- 模块快照 ----------

struct ModInfo {
    std::wstring name;
    std::wstring path;
    uintptr_t    base = 0;
    size_t       size = 0;
};

std::vector<ModInfo> snapshot_modules() {
    std::vector<ModInfo> out;
    HMODULE mods[1024];
    DWORD need = 0;
    if (!::EnumProcessModules(::GetCurrentProcess(), mods, sizeof(mods), &need)) return out;
    size_t count = need / sizeof(HMODULE);
    if (count > std::size(mods)) count = std::size(mods);
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        ModInfo mi;
        mi.base = reinterpret_cast<uintptr_t>(mods[i]);
        mi.path = module_path(mods[i]);
        mi.name = file_name_of(mi.path);
        MODULEINFO info{};
        if (::GetModuleInformation(::GetCurrentProcess(), mods[i], &info, sizeof(info))) {
            mi.size = info.SizeOfImage;
        }
        out.push_back(std::move(mi));
    }
    return out;
}

// 我们关心的关键模块:出现即说明游戏初始化推进到某个阶段
constexpr const wchar_t* kNotable[] = {
    L"Minecraft.Windows.exe",
    L"PreloadCpp.dll",              // 预加载器本体(证明通道来源)
    L"gdk_patch.dll",               // 已知的同目录载荷
    L"fiber_probe.dll",             // 我们自己(证明探针被加载)
    L"fiber_runtime.dll",           // 将来 Runtime 的占位名
    L"v8.dll",
    L"cohtml.WindowsDesktop.dll",
    L"cohtml_icuuc.dll",
    L"fmod.dll",
    L"Microsoft.WindowsAppRuntime.dll",
    L"PlayFabMultiplayerGDK.dll",
    L"libHttpClient.GDK.dll",
    L"WERHandler.dll",
};

void log_preload_dir(const std::wstring& dir) {
    WIN32_FIND_DATAW fd{};
    const std::wstring pattern = dir + L"\\*";
    HANDLE h = ::FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        log_line("preload 目录无法枚举 (GetLastError=%lu)", ::GetLastError());
        return;
    }
    int files = 0;
    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            const unsigned long long sz =
                (static_cast<unsigned long long>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
            log_line("  preload 条目: %s  (%llu 字节)", u8(fd.cFileName).c_str(), sz);
            ++files;
        }
    } while (::FindNextFileW(h, &fd));
    ::FindClose(h);
    log_line("preload 目录共 %d 个文件", files);
}

// ---------- 窗口出现检测(判断"游戏初始化完成"的粗粒度标记)----------

struct WindowProbe {
    DWORD pid = 0;
    HWND  found = nullptr;
};

BOOL CALLBACK enum_windows_cb(HWND hwnd, LPARAM lp) {
    auto* wp = reinterpret_cast<WindowProbe*>(lp);
    DWORD pid = 0;
    ::GetWindowThreadProcessId(hwnd, &pid);
    if (pid == wp->pid && ::IsWindowVisible(hwnd) != FALSE && ::GetWindow(hwnd, GW_OWNER) == nullptr) {
        wp->found = hwnd;
        return FALSE;
    }
    return TRUE;
}

// ---------- 工作线程 ----------

DWORD WINAPI probe_main(LPVOID) {
    const std::wstring self  = module_path(g_self);
    const std::wstring exe   = module_path(nullptr);
    const std::wstring root  = dir_of(exe);
    const std::wstring dll_dir = dir_of(self);

    {
        FILE* f = nullptr;
        if (_wfopen_s(&f, (root + L"\\fiber_probe.log").c_str(), L"ab") != 0 || f == nullptr) {
            return 0;   // 连日志都写不了就安静退出,绝不影响宿主
        }
        g_log = f;
    }

    log_line("================ fiber_probe 会话开始(通道探针,无 hook)================");
    log_line("宿主 exe        : %s", u8(exe).c_str());
    log_line("宿主 exe 基址   : 0x%llX", static_cast<unsigned long long>(
                 reinterpret_cast<uintptr_t>(::GetModuleHandleW(nullptr))));
    log_line("探针 DLL        : %s", u8(self).c_str());
    log_line("探针 DLL 基址   : 0x%llX", static_cast<unsigned long long>(
                 reinterpret_cast<uintptr_t>(g_self)));
    log_line("DLL 所在目录    : %s", u8(dll_dir).c_str());
    log_line("宿主 exe 目录   : %s", u8(root).c_str());
    log_line("attach 线程 id  : %lu  (DllMain 运行线程;静态/preload 加载时即主线程)",
             static_cast<unsigned long>(g_attach_tid));
    log_line("工作线程 id     : %lu", static_cast<unsigned long>(::GetCurrentThreadId()));

    {
        wchar_t cwd[32768];
        const DWORD n = ::GetCurrentDirectoryW(static_cast<DWORD>(std::size(cwd)), cwd);
        log_line("当前工作目录    : %s", n ? u8(std::wstring(cwd, n)).c_str() : "<n/a>");
    }
    log_line("命令行          : %s", u8(std::wstring(::GetCommandLineW())).c_str());
    {
        BOOL wow = FALSE;
        ::IsWow64Process(::GetCurrentProcess(), &wow);
        log_line("WOW64           : %s", wow ? "是" : "否");
    }

    const wchar_t* kEnvNames[] = {
        L"FIBER_GAME_ROOT", L"FIBER_MODS_DIR", L"FIBER_GAME_VERSION", L"FIBER_RUNTIME_DIR",
        L"FIBER_PROBE",
    };
    for (const wchar_t* nm : kEnvNames) {
        const std::wstring v = env_w(nm);
        log_line("环境变量 %-18s: %s", u8(nm).c_str(), v.empty() ? "<未设置>" : u8(v).c_str());
    }

    log_preload_dir(dll_dir);

    // ---- 细粒度观察 120 秒:模块增长 / 关键模块出现 / 首个窗口 ----
    std::vector<char> seen(std::size(kNotable), 0);
    size_t last_count = 0;
    bool window_seen = false;

    for (int tick = 0; tick < 120; ++tick) {
        if (::WaitForSingleObject(g_stop, 1000) == WAIT_OBJECT_0) break;

        const std::vector<ModInfo> mods = snapshot_modules();
        if (mods.size() != last_count) {
            last_count = mods.size();
            log_line("已加载模块数 = %zu", last_count);
        }
        for (const ModInfo& mi : mods) {
            for (size_t k = 0; k < std::size(kNotable); ++k) {
                if (seen[k] == 0 && mi.name == kNotable[k]) {
                    seen[k] = 1;
                    log_line("关键模块出现  : %-32s base=0x%llX size=0x%zX",
                             u8(mi.name).c_str(),
                             static_cast<unsigned long long>(mi.base), mi.size);
                }
            }
        }
        if (!window_seen) {
            WindowProbe wp;
            wp.pid = ::GetCurrentProcessId();
            ::EnumWindows(enum_windows_cb, reinterpret_cast<LPARAM>(&wp));
            if (wp.found != nullptr) {
                window_seen = true;
                wchar_t title[512] = L"";
                wchar_t cls[256] = L"";
                ::GetWindowTextW(wp.found, title, static_cast<int>(std::size(title)));
                ::GetClassNameW(wp.found, cls, static_cast<int>(std::size(cls)));
                log_line("首个可见窗口出现: class=\"%s\" title=\"%s\"",
                         u8(cls).c_str(), u8(title).c_str());
            }
        }
    }

    // ---- 之后每 30 秒心跳,直到进程退出 ----
    while (::WaitForSingleObject(g_stop, 30000) == WAIT_TIMEOUT) {
        log_line("心跳: 模块数=%zu 窗口=%s", snapshot_modules().size(),
                 window_seen ? "已出现" : "未出现");
    }

    log_line("================ fiber_probe 会话结束(stop 信号)================");
    std::fclose(g_log);
    g_log = nullptr;
    return 0;
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self        = hinst;
        g_attach_tick = ::GetTickCount64();
        g_attach_tid  = ::GetCurrentThreadId();
        g_stop        = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ::DisableThreadLibraryCalls(hinst);
        if (HANDLE t = ::CreateThread(nullptr, 0, probe_main, nullptr, 0, nullptr)) {
            ::CloseHandle(t);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_stop != nullptr) ::SetEvent(g_stop);
    }
    return TRUE;
}