#include "modloader.h"

#include "paths.h"
#include "semver_check.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace fiber {

namespace {

ModLoader*   g_loader = nullptr;
Logger*      g_logger = nullptr;
std::string  g_mods_dir_utf8;
std::string  g_unknown_version = "unknown";

// D8:全部 Mod 回调在游戏主线程;M1 阶段 Mod 代码只在 OnLoad/OnUnload 内运行,
// 因此用 thread_local 绑定"当前 Mod"即可正确归属 API 调用。
thread_local ModInstance* g_current_mod = nullptr;
thread_local std::string  g_mod_dir_utf8;

// ---------------- Mod 面 API 实现(fiber_api.h 定义的函数表)----------------

void api_log(int level, const char* message) {
    if (g_logger == nullptr || message == nullptr) return;
    const std::string modid = (g_current_mod != nullptr) ? g_current_mod->manifest.modid
                                                         : std::string("<mod>");
    g_logger->mod_log(modid, level, message);
}

const char* api_game_version(void) {
    if (g_loader == nullptr) return g_unknown_version.c_str();
    return g_loader->game_version().c_str();
}

const char* api_mods_dir(void) {
    return g_mods_dir_utf8.c_str();
}

const char* api_mod_id(void) {
    if (g_current_mod == nullptr) return "";
    return g_current_mod->manifest.modid.c_str();
}

const char* api_mod_dir(void) {
    if (g_current_mod == nullptr) return "";
    g_mod_dir_utf8 = display_path(g_current_mod->manifest.dir);
    return g_mod_dir_utf8.c_str();
}

uint64_t fnv1a(const std::vector<char>& data) {
    uint64_t h = 1469598103934665603ull;
    for (const char c : data) {
        h ^= static_cast<unsigned char>(c);
        h *= 1099511628211ull;
    }
    return h;
}

bool write_bytes(const std::wstring& path, const std::vector<char>& data) {
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    size_t total = 0;
    while (total < data.size()) {
        DWORD written = 0;
        const DWORD want = static_cast<DWORD>(std::min<size_t>(data.size() - total, 1u << 20));
        if (!::WriteFile(h, data.data() + total, want, &written, nullptr) || written == 0) {
            ::CloseHandle(h);
            return false;
        }
        total += written;
    }
    ::CloseHandle(h);
    return true;
}

} // namespace

// ---------------------------------------------------------------- init ----

bool ModLoader::init(const std::wstring& game_root, Logger* logger) {
    if (logger == nullptr) return false;

    game_root_ = game_root;
    logger_    = logger;
    mods_dir_  = join_path(game_root_, L"mods");
    cache_dir_ = join_path(join_path(game_root_, L".fiber"), L"cache");
    g_logger   = logger;
    g_loader   = this;
    g_mods_dir_utf8 = display_path(mods_dir_);

    game_version_ = exe_version_string();
    if (game_version_.empty()) game_version_ = "unknown";

    // 函数表(D17:版本号 + 表尾追加)
    api_ = FiberApi{};
    api_.version        = FIBER_API_VERSION_MAJOR;
    api_.Log            = &api_log;
    api_.GetGameVersion = &api_game_version;
    api_.GetModsDir     = &api_mods_dir;
    api_.GetModId       = &api_mod_id;
    api_.GetModDir      = &api_mod_dir;

    logger_->log(kInfo, "mods 目录: " + display_path(mods_dir_));
    return true;
}

// ------------------------------------------------------------ discover ----

std::vector<Manifest> ModLoader::discover() const {
    std::vector<Manifest> found;

    if (!dir_exists(mods_dir_)) {
        logger_->log(kInfo, "mods 目录不存在,本次不加载任何 Mod");
        return found;
    }

    std::set<std::string> seen_ids;
    WIN32_FIND_DATAW fd{};
    const std::wstring pattern = join_path(mods_dir_, L"*");
    HANDLE h = ::FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        logger_->log(kWarn, "mods 目录无法枚举 (GetLastError=" +
                                std::to_string(::GetLastError()) + ")");
        return found;
    }

    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        if (::wcscmp(fd.cFileName, L".") == 0 || ::wcscmp(fd.cFileName, L"..") == 0) continue;

        const std::wstring dir = join_path(mods_dir_, fd.cFileName);
        const std::string  leaf = to_utf8(fd.cFileName);

        if (file_exists(join_path(dir, L".disabled"))) {
            logger_->log(kInfo, "跳过已禁用 Mod: " + leaf + "(.disabled 存在)");
            continue;
        }

        ParseResult pr = parse_manifest(dir);
        if (!pr.ok) {
            logger_->log(kError, "清单无效 [" + leaf + "]: " + pr.error);
            continue;
        }
        if (!seen_ids.insert(pr.manifest.modid).second) {
            logger_->log(kError, "重复 modid \"" + pr.manifest.modid + "\",跳过 [" + leaf + "]");
            continue;
        }

        logger_->log(kInfo, "found mod: " + pr.manifest.modid + " v" + pr.manifest.version +
                                " (" + pr.manifest.name + ")");
        found.push_back(std::move(pr.manifest));
    } while (::FindNextFileW(h, &fd) != FALSE);

    ::FindClose(h);
    return found;
}

// ------------------------------------------------------------- resolve ----

std::vector<size_t> ModLoader::resolve(std::vector<Manifest>& mods, std::vector<char>& viable) {
    const size_t n = mods.size();
    viable.assign(n, 1);

    std::map<std::string, size_t> index;
    for (size_t i = 0; i < n; ++i) index.emplace(mods[i].modid, i);

    // 1) 依赖校验 + 不可用传播(直到不动点)
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = 0; i < n; ++i) {
            if (viable[i] == 0) continue;
            for (const Dependency& d : mods[i].dependencies) {
                const auto it = index.find(d.modid);
                if (it == index.end()) {
                    logger_->log(kError, "拒绝加载 " + mods[i].modid + ": 缺少依赖 " + d.modid);
                    viable[i] = 0; changed = true; break;
                }
                if (viable[it->second] == 0) {
                    logger_->log(kError, "拒绝加载 " + mods[i].modid + ": 依赖 " + d.modid +
                                             " 已被拒绝");
                    viable[i] = 0; changed = true; break;
                }
                std::string err;
                if (!version_satisfies(mods[it->second].version, d.range, &err)) {
                    logger_->log(kError, "拒绝加载 " + mods[i].modid + ": 依赖 " + d.modid +
                                             " 版本 " + mods[it->second].version +
                                             " 不满足 \"" + d.range + "\"" +
                                             (err.empty() ? std::string() : " (" + err + ")"));
                    viable[i] = 0; changed = true; break;
                }
            }
        }
    }

    // 2) Kahn 拓扑排序;环内节点判为不可用
    std::vector<int> indeg(n, 0);
    std::vector<std::vector<size_t>> out(n);
    for (size_t i = 0; i < n; ++i) {
        if (viable[i] == 0) continue;
        for (const Dependency& d : mods[i].dependencies) {
            const size_t j = index.at(d.modid);
            if (viable[j] == 0) continue;
            out[j].push_back(i);
            ++indeg[i];
        }
    }

    std::vector<size_t> order;
    std::vector<size_t> queue;
    for (size_t i = 0; i < n; ++i) {
        if (viable[i] != 0 && indeg[i] == 0) queue.push_back(i);
    }
    for (size_t qi = 0; qi < queue.size(); ++qi) {
        const size_t cur = queue[qi];
        order.push_back(cur);
        for (const size_t nxt : out[cur]) {
            if (--indeg[nxt] == 0) queue.push_back(nxt);
        }
    }

    const size_t viable_count =
        static_cast<size_t>(std::count(viable.begin(), viable.end(), static_cast<char>(1)));
    if (order.size() != viable_count) {
        for (size_t i = 0; i < n; ++i) {
            if (viable[i] != 0 && indeg[i] > 0) {
                logger_->log(kError, "拒绝加载 " + mods[i].modid + ": 依赖存在循环");
                viable[i] = 0;
            }
        }
        // 清掉因环而失去依赖的节点(保持 order 与 viable 一致)
        order.erase(std::remove_if(order.begin(), order.end(),
                                   [&](size_t i) { return viable[i] == 0; }),
                    order.end());
    }

    return order;
}

// -------------------------------------------------------- shadow copy ----

std::wstring ModLoader::shadow_copy(const Manifest& manifest) {
    const std::wstring src = join_path(manifest.dir, to_wide(manifest.entry));
    std::vector<char> bytes;
    if (!read_file_bytes(src, bytes)) {
        logger_->log(kError, "Mod " + manifest.modid + ": 读不到入口 DLL " +
                                 display_path(src));
        return {};
    }

    if (!create_dirs(cache_dir_)) {
        logger_->log(kWarn, "Mod " + manifest.modid + ": 无法创建影子副本目录,直接加载原文件");
        return src;
    }

    wchar_t name[160];
    std::swprintf(name, std::size(name), L"%s_%016llX.dll",
                  to_wide(manifest.modid).c_str(),
                  static_cast<unsigned long long>(fnv1a(bytes)));
    const std::wstring dst = join_path(cache_dir_, name);

    if (!file_exists(dst) && !write_bytes(dst, bytes)) {
        logger_->log(kWarn, "Mod " + manifest.modid + ": 影子副本写入失败,直接加载原文件");
        return src;
    }
    return dst;
}

// ------------------------------------------------------------- loading ----

bool ModLoader::load_one(const Manifest& manifest, ModInstance& out) {
    const std::wstring dll = shadow_copy(manifest);
    if (dll.empty()) return false;

    HMODULE module = ::LoadLibraryW(dll.c_str());
    if (module == nullptr) {
        logger_->log(kError, "Mod " + manifest.modid + ": LoadLibrary 失败 (GetLastError=" +
                                 std::to_string(::GetLastError()) + ")");
        return false;
    }

    auto on_load = reinterpret_cast<FiberOnLoadFn>(
        reinterpret_cast<void*>(::GetProcAddress(module, "Fiber_OnLoad")));
    if (on_load == nullptr) {
        logger_->log(kError, "Mod " + manifest.modid + ": 缺少导出 Fiber_OnLoad");
        ::FreeLibrary(module);
        return false;
    }

    auto on_unload = reinterpret_cast<FiberOnUnloadFn>(
        reinterpret_cast<void*>(::GetProcAddress(module, "Fiber_OnUnload")));

    // 描述符交叉校验(D18:身份以清单为准)
    auto get_desc = reinterpret_cast<FiberGetDescriptorFn>(
        reinterpret_cast<void*>(::GetProcAddress(module, "Fiber_GetDescriptor")));
    if (get_desc != nullptr) {
        FiberModDescriptor desc{};
        desc.struct_size = sizeof(FiberModDescriptor);
        if (get_desc(&desc) == 0) {
            const std::string d_id  = (desc.modid != nullptr) ? desc.modid : "";
            const std::string d_ver = (desc.version != nullptr) ? desc.version : "";
            if (d_id != manifest.modid) {
                logger_->log(kError, "Mod " + manifest.modid + ": 描述符 modid 不一致(\"" + d_id +
                                         "\"),拒绝加载");
                ::FreeLibrary(module);
                return false;
            }
            if (!d_ver.empty() && d_ver != manifest.version) {
                logger_->log(kError, "Mod " + manifest.modid + ": 描述符版本不一致(清单 " +
                                         manifest.version + " vs DLL " + d_ver + "),拒绝加载");
                ::FreeLibrary(module);
                return false;
            }
            if (desc.required_api > FIBER_API_VERSION_MAJOR) {
                logger_->log(kError, "Mod " + manifest.modid + ": 需要 API " +
                                         std::to_string(desc.required_api) + ",本 Runtime 提供 " +
                                         std::to_string(FIBER_API_VERSION_MAJOR));
                ::FreeLibrary(module);
                return false;
            }
        } else {
            logger_->log(kWarn, "Mod " + manifest.modid + ": Fiber_GetDescriptor 返回失败,跳过校验");
        }
    }

    // 先记日志再填充(out 被 move 后 manifest 会空 —— 旧项目踩过的坑)
    logger_->log(kInfo, "loaded mod: modid=" + manifest.modid + " name=" + manifest.name +
                            " version=" + manifest.version +
                            "(dll=" + display_path(dll) + ")");

    out.manifest         = manifest;
    out.module           = module;
    out.loaded_path      = dll;
    out.on_unload        = on_unload;
    out.used_shadow_copy = (dll != join_path(manifest.dir, to_wide(manifest.entry)));

    g_current_mod = &out;
    const int rc = on_load(&api_);
    g_current_mod = nullptr;

    if (rc != 0) {
        logger_->log(kError, "Mod " + manifest.modid + ": Fiber_OnLoad 返回 " +
                                 std::to_string(rc) + ",拒绝加载");
        ::FreeLibrary(module);
        out = ModInstance{};
        return false;
    }
    return true;
}

void ModLoader::unload_one(ModInstance& instance) {
    if (instance.module == nullptr) return;

    // 静默期(ADR 0004):M1 阶段没有事件派发,no-op;M4 热重载时在此排空队列、等在途回调
    if (instance.on_unload != nullptr) {
        g_current_mod = &instance;
        instance.on_unload();
        g_current_mod = nullptr;
    }
    logger_->log(kInfo, "unloaded mod: modid=" + instance.manifest.modid);

    ::FreeLibrary(instance.module);
    instance.module = nullptr;
    if (instance.manifest.modid.empty()) return;
    g_logger->close_mod_log(instance.manifest.modid);
}

// ------------------------------------------------------------ lifecycle ----

void ModLoader::load_all() {
    std::vector<Manifest> mods = discover();
    if (mods.empty()) {
        logger_->log(kInfo, "mod 加载结束: 未发现任何 Mod");
        return;
    }

    std::vector<char> viable;
    const std::vector<size_t> order = resolve(mods, viable);

    for (const size_t i : order) {
        ModInstance instance;
        if (load_one(mods[i], instance)) {
            loaded_.push_back(std::move(instance));
        }
    }

    logger_->log(kInfo, "mod 加载结束: 发现 " + std::to_string(mods.size()) + " 个,成功加载 " +
                            std::to_string(loaded_.size()) + " 个");
}

void ModLoader::shutdown() {
    if (loaded_.empty()) return;

    // 逆序卸载(依赖者先卸)
    for (auto it = loaded_.rbegin(); it != loaded_.rend(); ++it) {
        unload_one(*it);
    }
    loaded_.clear();
    logger_->log(kInfo, "全部 Mod 已卸载");
}

} // namespace fiber