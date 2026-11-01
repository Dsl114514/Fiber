#include "paths.h"

#include <winver.h>

#include <algorithm>
#include <cwctype>

namespace fiber {

std::string to_utf8(const std::wstring& s) {
    if (s.empty()) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                          out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                        nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                          out.data(), n);
    return out;
}

std::wstring join_path(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    std::wstring out = a;
    if (out.back() != L'\\' && out.back() != L'/') out.push_back(L'\\');
    out += b;
    return out;
}

std::wstring dir_of(const std::wstring& path) {
    const size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? std::wstring{} : path.substr(0, pos);
}

std::wstring file_name_of(const std::wstring& path) {
    const size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

std::wstring parent_of(const std::wstring& dir) {
    if (dir.empty()) return {};
    std::wstring d = dir;
    while (d.size() > 3 && (d.back() == L'\\' || d.back() == L'/')) d.pop_back();
    const size_t pos = d.find_last_of(L"\\/");
    if (pos == std::wstring::npos || pos < 2) return {};
    return d.substr(0, pos);
}

std::wstring module_path(HMODULE module) {
    std::wstring buf(32768, L'\0');
    const DWORD n = ::GetModuleFileNameW(module, buf.data(), static_cast<DWORD>(buf.size()));
    buf.resize(n);
    return buf;
}

std::wstring exe_path() {
    return module_path(nullptr);
}

bool file_exists(const std::wstring& path) {
    const DWORD attr = ::GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool dir_exists(const std::wstring& path) {
    const DWORD attr = ::GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool create_dirs(const std::wstring& path) {
    if (path.empty() || dir_exists(path)) return true;
    std::wstring cur;
    for (size_t i = 0; i < path.size(); ++i) {
        cur.push_back(path[i]);
        const bool at_sep = (path[i] == L'\\' || path[i] == L'/');
        const bool at_end = (i + 1 == path.size());
        if (!at_sep && !at_end) continue;
        if (cur.size() <= 3 && cur.back() == L'\\') continue;   // "E:\" 之类
        if (!dir_exists(cur) && !::CreateDirectoryW(cur.c_str(), nullptr)) {
            const DWORD err = ::GetLastError();
            if (err != ERROR_ALREADY_EXISTS) return false;
        }
    }
    return dir_exists(path);
}

bool read_file_bytes(const std::wstring& path, std::vector<char>& out) {
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(h, &size) || size.QuadPart < 0 || size.QuadPart > (1ll << 30)) {
        ::CloseHandle(h);
        return false;
    }
    out.resize(static_cast<size_t>(size.QuadPart));
    size_t total = 0;
    while (total < out.size()) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(std::min<size_t>(out.size() - total, 1u << 20));
        if (!::ReadFile(h, out.data() + total, want, &got, nullptr) || got == 0) {
            ::CloseHandle(h);
            return false;
        }
        total += got;
    }
    ::CloseHandle(h);
    return true;
}

std::wstring game_root(HMODULE self) {
    // 1) 首选宿主 exe 目录(实测:BedrockBoot 直接拉起 <游戏根>\Minecraft.Windows.exe)
    const std::wstring exe = exe_path();
    if (!exe.empty()) {
        const std::wstring dir = dir_of(exe);
        if (!dir.empty() && file_exists(join_path(dir, L"Minecraft.Windows.exe"))) {
            return dir;
        }
    }
    // 2) 退回:自身模块目录若名为 preload,则游戏根 = 其父目录
    const std::wstring self_dir = dir_of(module_path(self));
    std::wstring leaf = file_name_of(self_dir);
    std::transform(leaf.begin(), leaf.end(), leaf.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(::towlower(c)); });
    if (leaf == L"preload") return parent_of(self_dir);
    // 3) 最后:自身目录
    return self_dir;
}

std::string display_path(const std::wstring& path) {
    std::string s = to_utf8(path);
    std::replace(s.begin(), s.end(), '\\', '/');
    return s;
}

std::string exe_version_string() {
    const std::wstring exe = exe_path();
    if (exe.empty()) return {};

    DWORD handle = 0;
    const DWORD size = ::GetFileVersionInfoSizeW(exe.c_str(), &handle);
    if (size == 0) return {};

    std::vector<char> buf(size);
    if (!::GetFileVersionInfoW(exe.c_str(), 0, size, buf.data())) return {};

    VS_FIXEDFILEINFO* info = nullptr;
    UINT info_len = 0;
    if (!::VerQueryValueW(buf.data(), L"\\", reinterpret_cast<LPVOID*>(&info), &info_len) ||
        info == nullptr) {
        return {};
    }
    if (info->dwSignature != 0xFEEF04BDu) return {};

    const unsigned major = (info->dwFileVersionMS >> 16) & 0xFFFFu;
    const unsigned minor = info->dwFileVersionMS & 0xFFFFu;
    const unsigned build = (info->dwFileVersionLS >> 16) & 0xFFFFu;
    const unsigned rev   = info->dwFileVersionLS & 0xFFFFu;

    char out[64];
    std::snprintf(out, sizeof(out), "%u.%u.%u.%u", major, minor, build, rev);
    return out;
}

} // namespace fiber