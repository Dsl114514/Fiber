// Fiber Runtime —— 清单解析(manifest.toml)
//
// D5  / ADR 0001  清单格式 = TOML
// D18             字段 = modid/name/version/authors/description/entry/api_version + [dependencies]
//                 身份以清单为准;DLL 描述符仅用于交叉校验
// D31             .disabled 标记文件 = 该 Mod 被禁用

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace fiber {

struct Dependency {
    std::string modid;
    std::string range;   // 完整 semver range(D19),例如 ">=1.0.0 <2.0.0 || >=3.0.0"
};

struct Manifest {
    std::string              modid;
    std::string              name;
    std::string              version;
    std::string              description;
    std::string              entry;        // 入口 DLL 文件名
    std::vector<std::string> authors;
    uint32_t                 api_version = 0;
    std::vector<Dependency>  dependencies;

    std::wstring dir;    // 该 Mod 的目录
    std::wstring path;   // manifest.toml 的完整路径
};

struct ParseResult {
    bool        ok = false;
    std::string error;
    Manifest    manifest;
};

// 读取并校验 <mod_dir>\manifest.toml;失败时 error 为人类可读原因
ParseResult parse_manifest(const std::wstring& mod_dir);

// 校验 modid 合法(^[a-z0-9_]{1,64}$)
bool is_valid_modid(const std::string& modid);

} // namespace fiber