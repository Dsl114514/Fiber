// Fiber 采样探针(M2,第二轮实证)
//
// 背景:第一版钩子探针(按 __FUNCSIG__ 反向引用静态推出的 9 个候选)实测每个
//       146 秒只被调用 1 次 —— 静态候选选错了(它们不是帧循环)。
//
// 本探针改为**实测驱动**:
//   阶段 1(30 秒):按 ~1ms 轮询,依次采样进程内各线程的 RIP,累计“游戏模块内的
//                   热地址”直方图(每 10 秒输出 Top 25)。
//   阶段 2(45 秒):从直方图里挑出游戏 .text 内最热且函数体足够的 8 个地址,
//                   用寄存器安全桩装计数钩子,直接测出**每秒调用率** → 分发点候选。
//
// 采样与钩子都不改变游戏语义:采样只是 SuspendThread+GetThreadContext+Resume;
// 钩子桩完整保存/恢复寄存器与标志位。

#include <windows.h>
#include <timeapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <map>
#include <set>
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
LONGLONG  g_qpc_freq = 0;

uintptr_t g_game_base = 0;
uint32_t  g_text_lo = 0;
uint32_t  g_text_hi = 0;

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

// -------------------------------------------------------- 游戏模块区段 ----

bool discover_text_range(HMODULE game) {
    const auto* base = reinterpret_cast<const uint8_t*>(game);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (std::memcmp(sec->Name, ".text", 5) == 0) {
            g_text_lo = sec->VirtualAddress;
            g_text_hi = sec->VirtualAddress + sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

bool rva_in_text(uint32_t rva) {
    return rva >= g_text_lo && rva < g_text_hi;
}

// ------------------------------------------------------------ 采样器 ----

struct Site {
    uint64_t hits = 0;
    LONG     tids[4] = {0, 0, 0, 0};
};

std::map<uint32_t, Site> g_histogram;   // key = 游戏模块内 RVA
std::map<DWORD, uint64_t> g_thread_hits;
uint64_t g_samples_total = 0;
uint64_t g_samples_in_game = 0;

std::vector<DWORD> enumerate_threads() {
    std::vector<DWORD> tids;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return tids;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    const DWORD self_pid = ::GetCurrentProcessId();
    if (::Thread32First(snap, &te) != FALSE) {
        do {
            if (te.th32OwnerProcessID == self_pid && te.th32ThreadID != ::GetCurrentThreadId()) {
                tids.push_back(te.th32ThreadID);
            }
        } while (::Thread32Next(snap, &te) != FALSE);
    }
    ::CloseHandle(snap);
    return tids;
}

void record_site(uint32_t rva, DWORD tid) {
    Site& site = g_histogram[rva];
    ++site.hits;
    for (int i = 0; i < 4; ++i) {
        if (site.tids[i] == static_cast<LONG>(tid)) break;
        if (site.tids[i] == 0) { site.tids[i] = static_cast<LONG>(tid); break; }
    }
    ++g_thread_hits[tid];
}

// 轮转采样:每次调用采样一个线程(由调用方控制频率)
void sample_one_thread(DWORD tid) {
    HANDLE h = ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                            FALSE, tid);
    if (h == nullptr) return;

    if (::SuspendThread(h) != static_cast<DWORD>(-1)) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;   // x64: 含 Rip / Rsp
        if (::GetThreadContext(h, &ctx) != FALSE) {
            ++g_samples_total;
            const uintptr_t rip = static_cast<uintptr_t>(ctx.Rip);
            if (rip >= g_game_base) {
                const uint64_t off = rip - g_game_base;
                if (off < 0xFFFFFFFFull) {
                    const uint32_t rva = static_cast<uint32_t>(off);
                    if (rva_in_text(rva)) {
                        ++g_samples_in_game;
                        record_site(rva, tid);
                    }
                }
            }
        }
        ::ResumeThread(h);
    }
    ::CloseHandle(h);
}

std::vector<std::pair<uint32_t, uint64_t>> top_sites(size_t n) {
    std::vector<std::pair<uint32_t, uint64_t>> all;
    all.reserve(g_histogram.size());
    for (const auto& kv : g_histogram) all.emplace_back(kv.first, kv.second.hits);
    std::sort(all.begin(), all.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    if (all.size() > n) all.resize(n);
    return all;
}

void report_histogram(const char* title, size_t top_n) {
    log_line("---- %s(总采样 %llu,其中游戏模块内 %llu)----", title,
             static_cast<unsigned long long>(g_samples_total),
             static_cast<unsigned long long>(g_samples_in_game));
    const auto top = top_sites(top_n);
    for (size_t i = 0; i < top.size(); ++i) {
        const auto& [rva, hits] = top[i];
        const Site& site = g_histogram[rva];
        const double pct = (g_samples_in_game > 0)
                               ? (100.0 * static_cast<double>(hits) /
                                  static_cast<double>(g_samples_in_game))
                               : 0.0;
        log_line("  #%02zu RVA 0x%08X: %llu 次 (%.1f%%) 线程 %lu,%lu,%lu,%lu", i + 1, rva,
                 static_cast<unsigned long long>(hits), pct,
                 static_cast<unsigned long>(site.tids[0]),
                 static_cast<unsigned long>(site.tids[1]),
                 static_cast<unsigned long>(site.tids[2]),
                 static_cast<unsigned long>(site.tids[3]));
    }
    log_line("---- %s 结束 ----", title);
}

// ------------------------------------------------- 计数钩子(阶段 2)----

constexpr int kMaxHooks = 8;

struct Counter {
    volatile LONG64 calls = 0;
    volatile LONG64 window_calls = 0;
    volatile LONG64 last_qpc = 0;
    volatile LONG64 min_delta = 0;
    volatile LONG64 sum_delta = 0;
    volatile LONG64 delta_samples = 0;
    volatile LONG    tids[4] = {0, 0, 0, 0};
};

Counter g_counters[kMaxHooks];
uint32_t g_hooked_rva[kMaxHooks] = {};
int g_hooked_count = 0;

extern "C" void fiber_sample_helper(uint64_t index) {
    if (index >= static_cast<uint64_t>(kMaxHooks)) return;
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
        if (c.tids[i] == tid) break;
        if (c.tids[i] == 0 && ::InterlockedCompareExchange(&c.tids[i], tid, 0) == 0) break;
    }
}

struct Stub {
    void*    code = nullptr;
    uint8_t* trampoline_slot = nullptr;
};

Stub build_stub(size_t index, void* helper) {
    std::vector<uint8_t> code;
    const auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (const uint8_t b : bytes) code.push_back(b);
    };

    emit({0x9C});                                             // pushfq
    emit({0x50, 0x51, 0x52});                                  // push rax, rcx, rdx
    emit({0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});    // push r8..r11
    emit({0x48, 0xB8});                                        // mov rax, helper
    const uint64_t helper_addr = reinterpret_cast<uint64_t>(helper);
    for (int i = 0; i < 8; ++i) code.push_back(static_cast<uint8_t>((helper_addr >> (8 * i)) & 0xFF));
    emit({0x48, 0xB9});                                        // mov rcx, index
    const uint64_t idx = index;
    for (int i = 0; i < 8; ++i) code.push_back(static_cast<uint8_t>((idx >> (8 * i)) & 0xFF));
    emit({0xFF, 0xD0});                                        // call rax
    emit({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58});    // pop r11..r8
    emit({0x5A, 0x59, 0x58});                                  // pop rdx, rcx, rax
    emit({0x9D});                                              // popfq

    const size_t jmp_offset = code.size();
    emit({0xFF, 0x25});                                        // jmp [rip+disp32]
    const size_t disp_offset = code.size();
    emit({0, 0, 0, 0});
    const size_t slot_offset = code.size();
    for (int i = 0; i < 8; ++i) code.push_back(0);

    const int32_t disp = static_cast<int32_t>(slot_offset) - static_cast<int32_t>(jmp_offset + 6);
    std::memcpy(code.data() + disp_offset, &disp, sizeof(disp));
    void* null_tramp = nullptr;
    std::memcpy(code.data() + slot_offset, &null_tramp, sizeof(null_tramp));

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

void install_hooks_from_histogram() {
    const MH_STATUS init = ::MH_Initialize();
    if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED) {
        log_line("MH_Initialize 失败: %d", static_cast<int>(init));
        return;
    }

    const auto top = top_sites(64);
    for (const auto& [rva, hits] : top) {
        if (g_hooked_count >= kMaxHooks) break;
        void* target = reinterpret_cast<void*>(g_game_base + rva);

        Stub stub = build_stub(static_cast<size_t>(g_hooked_count),
                               reinterpret_cast<void*>(&fiber_sample_helper));
        if (stub.code == nullptr) continue;

        void* trampoline = nullptr;
        if (::MH_CreateHook(target, stub.code, &trampoline) != MH_OK) continue;
        std::memcpy(stub.trampoline_slot, &trampoline, sizeof(trampoline));
        ::FlushInstructionCache(::GetCurrentProcess(), stub.code, 16);
        if (::MH_EnableHook(target) != MH_OK) {
            ::MH_RemoveHook(target);
            continue;
        }
        g_hooked_rva[g_hooked_count] = rva;
        ++g_hooked_count;
        log_line("  已挂钩热地址 RVA 0x%08X(采样命中 %llu 次)",
                 rva, static_cast<unsigned long long>(hits));
    }
    log_line("阶段 2 就绪:已挂钩 %d 个热地址", g_hooked_count);
}

void report_hooked(const char* title, bool reset_window) {
    log_line("---- %s ----", title);
    for (int i = 0; i < g_hooked_count; ++i) {
        Counter& c = g_counters[i];
        const LONG64 win = reset_window ? ::InterlockedExchange64(&c.window_calls, 0) : 0;
        const double rate = (g_qpc_freq > 0)
                                ? (100.0 * static_cast<double>(win) /
                                   (static_cast<double>(g_qpc_freq)) * 1000.0)
                                : 0.0;
        const double avg_ms = (c.delta_samples > 0 && g_qpc_freq > 0)
                                  ? (static_cast<double>(c.sum_delta) /
                                     static_cast<double>(c.delta_samples) /
                                     static_cast<double>(g_qpc_freq) * 1000.0)
                                  : 0.0;
        const double min_ms = (c.min_delta > 0 && g_qpc_freq > 0)
                                  ? (static_cast<double>(c.min_delta) /
                                     static_cast<double>(g_qpc_freq) * 1000.0)
                                  : 0.0;
        log_line("  RVA 0x%08X: 累计 %lld | 本窗口 %lld (%.1f 次/秒) | 平均间隔 %.2f ms | 最小 %.2f ms | 线程 %lu,%lu,%lu,%lu",
                 g_hooked_rva[i], static_cast<long long>(c.calls), static_cast<long long>(win),
                 rate, avg_ms, min_ms,
                 static_cast<unsigned long>(c.tids[0]),
                 static_cast<unsigned long>(c.tids[1]),
                 static_cast<unsigned long>(c.tids[2]),
                 static_cast<unsigned long>(c.tids[3]));
    }
    log_line("---- %s 结束 ----", title);
}

// ---------------------------------------------------------------- 主流程 ----

bool window_present() {
    return ::FindWindowW(L"Bedrock", nullptr) != nullptr;
}

void wait_for_game_window() {
    const ULONGLONG start = ::GetTickCount64();
    while (!window_present()) {
        if (::WaitForSingleObject(g_stop, 1000) != WAIT_TIMEOUT) return;
        if (::GetTickCount64() - start > 10 * 60 * 1000ULL) return;
    }
}

DWORD WINAPI probe_main(LPVOID) {
    const std::wstring self = module_path(g_self);
    const std::wstring root = dir_of(module_path(nullptr));

    std::wstring logpath = root + L"\\fiber_sampler.log";
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
    ::timeBeginPeriod(1);

    HMODULE game = ::GetModuleHandleW(nullptr);
    g_game_base = reinterpret_cast<uintptr_t>(game);
    const bool text_ok = discover_text_range(game);

    log_line("============ fiber_sampler 启动(RIP 采样 → 热地址 → 计数)============");
    log_line("探针 DLL   : %s", u8(self).c_str());
    log_line("游戏根     : %s", u8(root).c_str());
    log_line("游戏基址   : 0x%llX", static_cast<unsigned long long>(g_game_base));
    if (text_ok) {
        log_line(".text 区间 : RVA 0x%08X – 0x%08X", g_text_lo, g_text_hi);
    } else {
        log_line(".text 区间解析失败,采样将统计全部模块内地址");
        g_text_lo = 0;
        g_text_hi = 0xFFFFFFFF;
    }
    log_line("QPC 频率   : %lld Hz", static_cast<long long>(g_qpc_freq));

    log_line("等待游戏主窗口(class=\"Bedrock\")出现 …");
    wait_for_game_window();
    if (::WaitForSingleObject(g_stop, 3000) != WAIT_TIMEOUT) {
        log_line("等待期间收到退出信号,结束");
        std::fclose(g_log);
        return 0;
    }
    log_line("主窗口已出现,开始阶段 1(采样 30 秒)");

    // ---- 阶段 1:采样 30 秒 ----
    std::vector<DWORD> threads;
    ULONGLONG last_report = ::GetTickCount64();
    size_t rr = 0;
    const ULONGLONG phase1_end = ::GetTickCount64() + 30000;
    while (::GetTickCount64() < phase1_end) {
        if (::WaitForSingleObject(g_stop, 0) != WAIT_TIMEOUT) break;
        if (threads.empty() || (rr % 512) == 0) threads = enumerate_threads();
        if (!threads.empty()) {
            sample_one_thread(threads[rr % threads.size()]);
            ++rr;
        }
        // 约 1ms 一次(受 timeBeginPeriod(1) 与系统调度影响,实际 ~1–2ms)
        if ((rr % 8) == 0) ::Sleep(1);

        if (::GetTickCount64() - last_report >= 10000) {
            last_report = ::GetTickCount64();
            report_histogram("阶段 1 采样直方图 Top 25", 25);
        }
    }

    report_histogram("阶段 1 最终直方图 Top 25", 25);

    // ---- 阶段 2:按热地址装计数钩子,测每秒调用率 ----
    log_line("开始阶段 2:按热地址安装计数钩子");
    install_hooks_from_histogram();

    int window_index = 0;
    while (::WaitForSingleObject(g_stop, 10000) == WAIT_TIMEOUT) {
        ++window_index;
        log_line("=== 阶段 2 统计窗口 #%d ===", window_index);
        report_hooked("调用率统计(窗口 10 秒)", true);
        if (window_index % 3 == 0) report_histogram("持续采样直方图 Top 15", 15);
    }

    log_line("=== 最终统计 ===");
    report_hooked("最终调用统计", false);
    report_histogram("最终直方图 Top 25", 25);
    log_line("============ fiber_sampler 结束 ============");

    ::timeEndPeriod(1);
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