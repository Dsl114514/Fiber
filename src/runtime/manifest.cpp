#include "manifest.h"

#include "paths.h"

#include <string_view>

#pragma warning(push, 0)
#include <toml++/toml.hpp>
#pragma warning(pop)

namespace fiber {

namespace {

// 去掉首尾空白
std::string trim(std::string s) {
    const auto not_space = [](unsigned char c) { return std::isspace(c) == 0; };
    while (!s.empty() && !not_space(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && !not_space(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

} // namespace

bool is_valid_modid(const std::string& modid) {
    if (modid.empty() || modid.size() > 64) return false;
    for (const char c : modid) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
    }
    return true;
}

ParseResult parse_manifest(const std::wstring& mod_dir) {
    ParseResult result;
    result.manifest.dir = mod_dir;
    result.manifest.path = join_path(mod_dir, L"manifest.toml");

    std::vector<char> bytes;
    if (!read_file_bytes(result.manifest.path, bytes)) {
        result.error = "无法读取 manifest.toml(文件缺失或不可读)";
        return result;
    }

    toml::table tbl;
    try {
        tbl = toml::parse(std::string_view(bytes.data(), bytes.size()),
                          display_path(result.manifest.path));
    } catch (const toml::parse_error& err) {
        result.error = std::string("TOML 语法错误: ") + err.description().data();
        return result;
    } catch (const std::exception& err) {
        result.error = std::string("TOML 解析异常: ") + err.what();
        return result;
    }

    Manifest& m = result.manifest;

    m.modid       = trim(tbl["modid"].value_or<std::string>(""));
    m.name        = trim(tbl["name"].value_or<std::string>(""));
    m.version     = trim(tbl["version"].value_or<std::string>(""));
    m.description = tbl["description"].value_or<std::string>("");
    m.entry       = trim(tbl["entry"].value_or<std::string>(""));

    const int64_t api = tbl["api_version"].value_or<int64_t>(0);
    if (api < 1 || api > 1000) {
        result.error = "api_version 缺失或非法(应为正整数)";
        return result;
    }
    m.api_version = static_cast<uint32_t>(api);

    if (const toml::array* authors = tbl["authors"].as_array()) {
        for (const auto& node : *authors) {
            if (const auto value = node.value<std::string>()) m.authors.push_back(*value);
        }
    }

    if (const toml::table* deps = tbl["dependencies"].as_table()) {
        for (const auto& [key, node] : *deps) {
            Dependency d;
            d.modid = std::string(key.str());
            d.range = trim(node.value_or<std::string>(""));
            m.dependencies.push_back(std::move(d));
        }
    }

    // ---- 校验 ----
    if (!is_valid_modid(m.modid)) {
        result.error = "modid 缺失或非法(只允许 [a-z0-9_],1–64 字符)";
        return result;
    }
    if (m.name.empty()) {
        result.error = "name 缺失";
        return result;
    }
    if (m.version.empty()) {
        result.error = "version 缺失";
        return result;
    }
    if (m.entry.empty()) {
        result.error = "entry 缺失(入口 DLL 文件名)";
        return result;
    }
    for (const Dependency& d : m.dependencies) {
        if (!is_valid_modid(d.modid)) {
            result.error = "dependencies 中存在非法 modid: " + d.modid;
            return result;
        }
        if (d.range.empty()) {
            result.error = "依赖 " + d.modid + " 缺少版本范围";
            return result;
        }
    }

    result.ok = true;
    return result;
}

} // namespace fiber