// Fiber Runtime —— Mod 加载器
//
// D14 / ADR 0004  影子副本加载(源 DLL 永不被锁)+ 静默期卸载(热重载基础)
// D18             身份以清单为准,描述符交叉校验
// D31             .disabled 标记文件 = 禁用
// D36             单实例保护由 app 层负责;本层只关心"加载什么、怎么加载"
//
// 依赖解析(加载前完成,绝不带病加载):
//   缺失依赖 / 依赖不可用 / 版本范围不满足 / 循环依赖 → 拒绝该 Mod 并记日志

#pragma once

#include "fiber_api.h"
#include "logger.h"
#include "manifest.h"

#include <windows.h>

#include <string>
#include <vector>

namespace fiber {

struct ModInstance {
    Manifest        manifest;
    HMODULE         module = nullptr;
    std::wstring    loaded_path;   // 实际加载的 DLL(影子副本;复制失败则退回原文件)
    FiberOnUnloadFn on_unload = nullptr;
    bool            used_shadow_copy = false;
};

class ModLoader {
public:
    bool init(const std::wstring& game_root, Logger* logger);
    void load_all();
    void shutdown();

    size_t loaded_count() const { return loaded_.size(); }
    const FiberApi* api() const { return &api_; }
    const std::string& game_version() const { return game_version_; }

private:
    std::vector<Manifest> discover() const;
    std::vector<size_t>   resolve(std::vector<Manifest>& mods, std::vector<char>& viable);
    bool                  load_one(const Manifest& manifest, ModInstance& out);
    void                  unload_one(ModInstance& instance);
    std::wstring          shadow_copy(const Manifest& manifest);

    std::wstring game_root_;
    std::wstring mods_dir_;
    std::wstring cache_dir_;
    std::string  game_version_ = "unknown";
    Logger*      logger_ = nullptr;
    FiberApi     api_{};
    std::vector<ModInstance> loaded_;
};

} // namespace fiber