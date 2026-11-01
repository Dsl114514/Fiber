// Fiber 示例 Mod —— 演示 M1 的多入口契约与 API 表
//
// 三个入口(D6 / ADR 0002):
//   Fiber_GetDescriptor  可选:身份声明,Runtime 与清单交叉校验
//   Fiber_OnLoad         必须:返回 0 表示成功,非 0 则 Runtime 拒绝该 Mod
//   Fiber_OnUnload       可选:卸载前调用(正常退出 / 热重载)

#include "fiber_api.h"

#include <string>

namespace {

const FiberApi* g_api = nullptr;
unsigned        g_load_count = 0;

std::string describe(const FiberApi* api) {
    std::string out;
    out += "game=";
    out += (api->GetGameVersion() != nullptr) ? api->GetGameVersion() : "?";
    out += " modid=";
    out += (api->GetModId() != nullptr) ? api->GetModId() : "?";
    out += " mod_dir=";
    out += (api->GetModDir() != nullptr) ? api->GetModDir() : "?";
    out += " mods_dir=";
    out += (api->GetModsDir() != nullptr) ? api->GetModsDir() : "?";
    return out;
}

} // namespace

FIBER_EXPORT int __cdecl Fiber_GetDescriptor(FiberModDescriptor* out) {
    if (out == nullptr || out->struct_size < sizeof(FiberModDescriptor)) return 1;
    out->required_api = 1;
    out->modid        = "sample_mod";
    out->name         = "Sample Mod";
    out->version      = "1.0.0";
    return 0;
}

FIBER_EXPORT int __cdecl Fiber_OnLoad(const FiberApi* api) {
    if (api == nullptr) return 1;
    g_api = api;
    ++g_load_count;

    const std::string info = describe(api);
    api->Log(FIBER_LOG_INFO, ("OnLoad 开始(第 " + std::to_string(g_load_count) + " 次)").c_str());
    api->Log(FIBER_LOG_INFO, info.c_str());
    api->Log(FIBER_LOG_INFO, "OnLoad 完成 —— M1 验收:本行日志出现即表示 Mod 已成功加载");
    return 0;
}

FIBER_EXPORT void __cdecl Fiber_OnUnload(void) {
    if (g_api != nullptr) {
        g_api->Log(FIBER_LOG_INFO, "OnUnload 被调用 —— M1 验收:干净卸载");
        g_api = nullptr;
    }
}