// Fiber Runtime —— 路径工具
//
// 关键约束(2026-11-01 探针实测):
//   * preload 通道下没有任何 FIBER_* 环境变量 → 游戏根必须自行推导
//   * 探针 DLL 位于 <游戏根>\preload\ → 游戏根 = 其父目录
//   * 宿主 exe 路径 = <游戏根>\Minecraft.Windows.exe → 也可直接取目录
//   两条推导在实测中一致,本模块优先用 exe 目录,失败再退回"父目录"逻辑。
//   * ASLR 生效 → 任何模块基址必须运行时获取,不得硬编码

#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace fiber {

std::string  to_utf8(const std::wstring& s);
std::wstring to_wide(const std::string& s);

std::wstring join_path(const std::wstring& a, const std::wstring& b);
std::wstring dir_of(const std::wstring& path);
std::wstring file_name_of(const std::wstring& path);
std::wstring parent_of(const std::wstring& dir);

std::wstring module_path(HMODULE module);
std::wstring exe_path();

bool file_exists(const std::wstring& path);
bool dir_exists(const std::wstring& path);
bool create_dirs(const std::wstring& path);

// 读取整个文件(二进制);失败返回 false
bool read_file_bytes(const std::wstring& path, std::vector<char>& out);

// 游戏根目录推导(见文件头注释)
std::wstring game_root(HMODULE self);

// 读宿主 exe 的版本资源得到游戏版本串(如 "1.26.33.1");失败返回空串
std::string exe_version_string();

// 把路径里的 \ 统一成 /(仅用于日志展示)
std::string display_path(const std::wstring& path);

} // namespace fiber