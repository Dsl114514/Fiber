// Fiber 钩子探针(M2 第一交付物,D40)
//
// 目的:用 MinHook 在 9 个主循环候选上装"纯计数"钩子,实测每个函数的
//       调用频率、调用间隔、调用线程 → **直接选定事件分发点**(不做静态先行)。
//
// 为什么用机器码 stub 而不是 C 函数当 detour:
//   候选函数签名未知,可能存在 >4 个参数(第 5 个起在栈上)。C detour 转发时
//   栈上参数会错位。因此 detour 用一段**完整保存/恢复寄存器与标志位**的桩:
//       pushfq / push rax,rcx,rdx,r8,r9,r10,r11 → call 计数助手 → 全部恢复
//       → jmp [trampoline]  → 原函数语义完全不变。
//
// 安全前提:只在游戏主窗口出现并沉降之后才装钩子;装钩子前逐字节校验函数序言,
//           不匹配则跳过(防 RVA 漂移/选错地址)。
// 注:WIN32_LEAN_AND_MEAN / NOMINMAX / UNICODE 由 CMake 目标定义提供

#include <windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <string>
#include <vector>

#pragma warning(push, 0)
#include <MinHook.h>
#pragma warning(pop)

namespace {

HMODULE   g_self = nullptr;
HANDLE    g_stop = nullptr;
FILE*     g_log = nullptr;
DWORD     g_attach_tid = 0;
ULONGLONG g_attach_tick = 0;

// ---------------------------------------------------------------- 日志 ----

std::string u8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), s.data(), n,
                          nullptr, nullptr);
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

// ------------------------------------------------------------ 候选定义 ----

constexpr int kMaxCandidates = 9;

struct Candidate {
    uint32_t    rva;
    const char* name;
    uint8_t     prologue[8];
};

// 序言字节来自 docs/mainloop_research.md(2026-11-01 .pdata/ml_sig 复验)
constexpr Candidate kCandidates[kMaxCandidates] = {
    {0x87AC90,  "MinecraftGame::update(big)",  {0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41}},
    {0x879E10,  "MinecraftGame::update#1",     {0x55, 0x56, 0x57, 0x53, 0x48, 0x81, 0xEC, 0xA8}},
    {0x87A530,  "MinecraftGame::update#2",     {0x55, 0x56, 0x57, 0x48, 0x81, 0xEC, 0x60, 0x03}},
    {0x87AB10,  "MinecraftGame::update#3",     {0x55, 0x56, 0x57, 0x48, 0x81, 0xEC, 0x20, 0x02}},
    {0x1D60D40, "ServerInstance::_update(big)",{0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41}},
    {0x1D5E7D0, "ServerInstance::_update225",  {0x56, 0x57, 0x55, 0x53, 0x48, 0x81, 0xEC, 0xA8}},
    {0x1D77260, "ServerLevel::_subTick403",    {0x55, 0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x38}},
    {0x1D64ED0, "ServerLevel::_subTick581",    {0x55, 0x56, 0x57, 0x48, 0x81, 0xEC, 0x90, 0x00}},
    {0x1D65410, "ServerLevel::_subTick437",    {0x55, 0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x81}},
};

// -------------------------------------------------------------- 计数器 ----

struct Counter {
    volatile LONG64      calls = 0;
    volatile LONG64      last_qpc = 0;         // 上次调用时刻(QPC)
    volatile LONG64      min_delta = 0;        // 最小间隔(QPC),0 = 未设置
    volatile LONG64      sum_delta = 0;        // 间隔总和(用于平均)
    volatile LONG64      delta_samples = 0;
    volatile LONG        tids[4] = {0, 0, 0, 0};   // 观察到的不同线程 id
    volatile LONG64      window_calls = 0;         // 本统计窗口内调用数(监控线程读取)
};

Counter  g_counters[kMaxCandidates];
void*    g_targets[kMaxCandidates] = {};
LONGLONG g_qpc_freq = 0;
size_t   g_installed = 0;

// detour 桩调用的计数助手(x64:第一个参数在 rcx)
extern "C" void fiber_count_helper(uint64_t index) {
    if (index >= static_cast<uint64_t>(kMaxCandidates)) return;
    Counter& c = g_counters[index];

    LARGE_INTEGER now{};
    ::QueryPerformanceCounter(&now);

    ::InterlockedIncrement64(&c.calls);
    ::InterlockedIncrement64(&c.window_calls);

    const LONG64 prev = ::InterlockedExchange64(&c.last_qpc, now.QuadPart);
    if (prev != 0) {
        const LONG64 delta = now.QuadPart - prev;
        ::InterlockedIncrement64(&c.sum_delta);
        ::InterlockedIncrement64(&c.delta_samples);
        LONG64 cur_min = c.min_delta;
        while ((cur_min == 0 || delta < cur_min) &&
               ::InterlockedCompareExchange64(&c.min_delta, delta, cur_min) != cur_min) {
            cur_min = c.min_delta;
        }
    }

    const LONG tid = static_cast<LONG>(::GetCurrentThreadId());
    for (int i = 0; i < 4; ++i) {
        const LONG slot = c.tids[i];
        if (slot == tid) break;
        if (slot == 0 && ::InterlockedCompareExchange(&c.tids[i], tid, 0) == 0) break;
    }
}

// --------------------------------------------------- detour 桩机器码生成 ----

// 生成:pushfq; push rax,rcx,rdx,r8,r9,r10,r11; mov rax,helper; mov rcx,index;
//       call rax; pop r11..rax; popfq; jmp [rip+disp] → 指向末尾的 trampoline 槽
//
// 返回 code(可执行内存)与 trampoline_slot(末尾 8 字节槽的地址)。
// 槽在 MH_CreateHook 返回后回填、MH_EnableHook 之前写入 —— 期间桩不会被执行。
struct Stub {
    void*    code = nullptr;
    uint8_t* trampoline_slot = nullptr;
};

Stub build_stub(size_t index, void* helper, void* trampoline) {
    std::vector<uint8_t> code;
    const auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (const uint8_t b : bytes) code.push_back(b);
    };

    emit({0x9C});                                  // pushfq
    emit({0x50, 0x51, 0x52});                      // push rax, rcx, rdx
    emit({0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});   // push r8..r11
    emit({0x48, 0xB8});                            // mov rax, imm64
    const uint64_t helper_addr = reinterpret_cast<uint64_t>(helper);
    for (int i = 0; i < 8; ++i) code.push_back(static_cast<uint8_t>((helper_addr >> (8 * i)) & 0xFF));
    emit({0x48, 0xB9});                            // mov rcx, imm64
    const uint64_t idx = index;
    for (int i = 0; i < 8; ++i) code.push_back(static_cast<uint8_t>((idx >> (8 * i)) & 0xFF));
    emit({0xFF, 0xD0});                            // call rax
    emit({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58});   // pop r11..r8
    emit({0x5A, 0x59, 0x58});                      // pop rdx, rcx, rax
    emit({0x9D});                                  // popfq

    // jmp qword ptr [rip+disp32] → 末尾 8 字节槽
    const size_t jmp_offset = code.size();
    emit({0xFF, 0x25});
    const size_t disp_offset = code.size();
    emit({0, 0, 0, 0});
    const size_t slot_offset = code.size();
    for (int i = 0; i < 8; ++i) code.push_back(0);   // 占位

    const int32_t disp = static_cast<int32_t>(slot_offset) -
                         static_cast<int32_t>(jmp_offset + 6);
    std::memcpy(code.data() + disp_offset, &disp, sizeof(disp));
    std::memcpy(code.data() + slot_offset, &trampoline, sizeof(trampoline));

    void* mem = ::VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (mem == nullptr) return {};
    std::memcpy(mem, code.data(), code.size());
    ::FlushInstructionCache(::GetCurrentProcess(), mem, code.size());

    Stub stub;
    stub.code = mem;
    stub.trampoline_slot = static_cast<uint8_t*>(mem) + slot_offset;
    return stub;
}

// ---------------------------------------------------------------- 主流程 ----

bool window_present() {
    return ::FindWindowW(L"Bedrock", nullptr) != nullptr;
}

void install_hooks(HMODULE game) {
    const MH_STATUS init = ::MH_Initialize();
    if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED) {
        log_line("MH_Initialize 失败: %d", static_cast<int>(init));
        return;
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(game);
    log_line("游戏模块基址 = 0x%llX,开始校验并安装钩子", static_cast<unsigned long long>(base));

    for (size_t i = 0; i < kMaxCandidates; ++i) {
        const Candidate& cand = kCandidates[i];
        void* target = reinterpret_cast<void*>(base + cand.rva);

        if (std::memcmp(target, cand.prologue, sizeof(cand.prologue)) != 0) {
            log_line("  跳过 %-28s 0x%X: 序言不匹配(期望 %02X %02X %02X %02X ...)",
                     cand.name, cand.rva, cand.prologue[0], cand.prologue[1],
                     cand.prologue[2], cand.prologue[3]);
            continue;
        }

        void* trampoline = nullptr;

        // 先建钩子以取得 MinHook 生成的 trampoline(原函数前几条指令的重定位副本)
        Stub stub = build_stub(i, reinterpret_cast<void*>(&fiber_count_helper), nullptr);
        if (stub.code == nullptr) {
            log_line("  跳过 %-28s 0x%X: 桩分配失败", cand.name, cand.rva);
            continue;
        }

        const MH_STATUS created = ::MH_CreateHook(target, stub.code, &trampoline);
        if (created != MH_OK) {
            log_line("  跳过 %-28s 0x%X: MH_CreateHook 失败 %d", cand.name, cand.rva,
                     static_cast<int>(created));
            continue;
        }

        // 回填 trampoline 槽(此刻钩子尚未启用,桩不会被执行)
        std::memcpy(stub.trampoline_slot, &trampoline, sizeof(trampoline));
        ::FlushInstructionCache(::GetCurrentProcess(), stub.code, 16);

        const MH_STATUS enabled = ::MH_EnableHook(target);
        if (enabled != MH_OK) {
            log_line("  跳过 %-28s 0x%X: MH_EnableHook 失败 %d", cand.name, cand.rva,
                     static_cast<int>(enabled));
            ::MH_RemoveHook(target);
            continue;
        }

        g_targets[i] = target;
        ++g_installed;
        log_line("  已挂钩 %-28s 0x%X (trampoline=0x%llX, stub=0x%llX)",
                 cand.name, cand.rva,
                 static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(trampoline)),
                 static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(stub.code)));
    }

    log_line("钩子安装完毕: %zu/%d 个候选成功", g_installed, kMaxCandidates);
}

void dump_window(bool reset_window) {
    log_line("---- 统计窗口(%.1f 秒)----", 1.0);
    for (size_t i = 0; i < kMaxCandidates; ++i) {
        Counter& c = g_counters[i];
        const LONG64 calls = c.calls;
        const LONG64 win = reset_window ? ::InterlockedExchange64(&c.window_calls, 0) : 0;
        if (calls == 0) {
            log_line("  %-28s 0x%X: 从未被调用", kCandidates[i].name, kCandidates[i].rva);
            continue;
        }
        const double avg_ms = (c.delta_samples > 0 && g_qpc_freq > 0)
                                  ? (static_cast<double>(c.sum_delta) /
                                     static_cast<double>(c.delta_samples) /
                                     static_cast<double>(g_qpc_freq) * 1000.0)
                                  : 0.0;
        const double min_ms = (c.min_delta > 0 && g_qpc_freq > 0)
                                  ? (static_cast<double>(c.min_delta) /
                                     static_cast<double>(g_qpc_freq) * 1000.0)
                                  : 0.0;
        log_line("  %-28s 0x%X: 累计 %lld | 本窗口 %lld | 平均间隔 %.2f ms | 最小 %.2f ms | 线程 %lu,%lu,%lu,%lu",
                 kCandidates[i].name, kCandidates[i].rva, calls, win, avg_ms, min_ms,
                 static_cast<unsigned long>(c.tids[0]), static_cast<unsigned long>(c.tids[1]),
                 static_cast<unsigned long>(c.tids[2]), static_cast<unsigned long>(c.tids[3]));
    }
    log_line("---- 统计窗口结束 ----");
}

DWORD WINAPI probe_main(LPVOID) {
    const std::wstring self = module_path(g_self);
    const std::wstring root = dir_of(module_path(nullptr));
    const std::wstring dll_dir = dir_of(self);

    std::wstring logpath = root + L"\\fiber_hookprobe.log";
    {
        wchar_t override_path[1024];
        const DWORD n = ::GetEnvironmentVariableW(L"FIBER_PROBE_LOG", override_path,
                                                 static_cast<DWORD>(std::size(override_path)));
        if (n > 0) logpath.assign(override_path, n);
    }
    FILE* f = nullptr;
    if (_wfopen_s(&f, logpath.c_str(), L"ab") != 0 || f == nullptr) return 0;
    g_log = f;

    LARGE_INTEGER freq{};
    ::QueryPerformanceFrequency(&freq);
    g_qpc_freq = freq.QuadPart;

    log_line("============ fiber_hookprobe 启动(计数钩子探针)============");
    log_line("探针 DLL   : %s", u8(self).c_str());
    log_line("DLL 目录   : %s", u8(dll_dir).c_str());
    log_line("游戏根     : %s", u8(root).c_str());
    log_line("attach tid : %lu | worker tid : %lu",
             static_cast<unsigned long>(g_attach_tid),
             static_cast<unsigned long>(::GetCurrentThreadId()));
    log_line("QPC 频率   : %lld Hz", static_cast<long long>(g_qpc_freq));

    HMODULE game = ::GetModuleHandleW(nullptr);
    log_line("等待游戏主窗口(class=\"Bedrock\")出现后再装钩子 …");

    // 等待主窗口出现(实测:受着色器编译影响可能 1–100 秒)
    const ULONGLONG wait_start = ::GetTickCount64();
    while (!window_present()) {
        if (::WaitForSingleObject(g_stop, 1000) != WAIT_TIMEOUT) {
            log_line("收到退出信号,未装钩子即结束");
            std::fclose(g_log);
            g_log = nullptr;
            return 0;
        }
        if (::GetTickCount64() - wait_start > 10 * 60 * 1000ULL) {
            log_line("等待主窗口超时(10 分钟),放弃装钩子");
            std::fclose(g_log);
            g_log = nullptr;
            return 0;
        }
    }
    log_line("主窗口已出现(t=%llums from attach),沉降 3 秒后安装钩子",
             static_cast<unsigned long long>(::GetTickCount64() - g_attach_tick));
    if (::WaitForSingleObject(g_stop, 3000) != WAIT_TIMEOUT) {
        log_line("沉降期间收到退出信号,结束");
        std::fclose(g_log);
        g_log = nullptr;
        return 0;
    }

    install_hooks(game);

    // 每 10 秒输出一次统计,直到退出
    int window_index = 0;
    while (::WaitForSingleObject(g_stop, 10000) == WAIT_TIMEOUT) {
        ++window_index;
        log_line("=== 统计窗口 #%d ===", window_index);
        dump_window(true);
    }

    log_line("=== 最终统计(会话结束)===");
    dump_window(false);
    log_line("============ fiber_hookprobe 结束 ============");
    std::fclose(g_log);
    g_log = nullptr;
    return 0;
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self        = static_cast<HMODULE>(instance);
        g_attach_tick = ::GetTickCount64();
        g_attach_tid  = ::GetCurrentThreadId();
        g_stop        = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ::DisableThreadLibraryCalls(static_cast<HMODULE>(instance));
        if (HANDLE t = ::CreateThread(nullptr, 0, probe_main, nullptr, 0, nullptr)) {
            ::CloseHandle(t);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_stop != nullptr) ::SetEvent(g_stop);
    }
    return TRUE;
}