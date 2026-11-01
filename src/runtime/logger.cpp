#include "logger.h"

#include "paths.h"

#include <cstdarg>

namespace fiber {

namespace {

const char* level_name(int level) {
    switch (level) {
        case kInfo:  return "INFO ";
        case kWarn:  return "WARN ";
        case kError: return "ERROR";
        default:     return "?????";
    }
}

} // namespace

Logger::~Logger() {
    close();
}

bool Logger::init(const std::wstring& game_root) {
    std::lock_guard<std::mutex> lock(mu_);

    logs_dir_ = join_path(game_root, L"logs");
    if (!create_dirs(logs_dir_)) {
        // 建不了 logs\ 不致命:Mod 日志会退回主日志
        logs_dir_.clear();
    }

    const std::wstring path = join_path(game_root, L"fiber.log");
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"ab") != 0 || f == nullptr) {
        return false;
    }
    main_ = f;

    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    std::fprintf(main_,
                 "\n===== Fiber Runtime 会话开始 %04u-%02u-%02u %02u:%02u:%02u =====\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    std::fflush(main_);
    return true;
}

void Logger::write_line(std::FILE* f, const std::string& tag, int level,
                        const std::string& message) {
    if (f == nullptr) return;
    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    if (tag.empty()) {
        std::fprintf(f, "[%02u:%02u:%02u.%03u tid=%lu] %s %s\n",
                     st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                     static_cast<unsigned long>(::GetCurrentThreadId()),
                     level_name(level), message.c_str());
    } else {
        std::fprintf(f, "[%02u:%02u:%02u.%03u tid=%lu] %s [%s] %s\n",
                     st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                     static_cast<unsigned long>(::GetCurrentThreadId()),
                     level_name(level), tag.c_str(), message.c_str());
    }
    std::fflush(f);
}

void Logger::log(int level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mu_);
    write_line(main_, std::string(), level, message);
}

void Logger::mod_log(const std::string& modid, int level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mu_);

    std::FILE* f = nullptr;
    const auto it = mods_.find(modid);
    if (it != mods_.end()) {
        f = it->second;
    } else if (!logs_dir_.empty()) {
        const std::wstring path = join_path(logs_dir_, to_wide(modid) + L".log");
        FILE* opened = nullptr;
        if (_wfopen_s(&opened, path.c_str(), L"ab") == 0 && opened != nullptr) {
            f = opened;
            mods_.emplace(modid, f);
        }
    }

    if (f == nullptr) {
        // 退回主日志,标明来源
        write_line(main_, modid, level, message);
        return;
    }
    write_line(f, std::string(), level, message);
}

void Logger::close_mod_log(const std::string& modid) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto it = mods_.find(modid);
    if (it == mods_.end()) return;
    if (it->second != nullptr) std::fclose(it->second);
    mods_.erase(it);
}

void Logger::close() {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& kv : mods_) {
        if (kv.second != nullptr) std::fclose(kv.second);
    }
    mods_.clear();
    if (main_ != nullptr) {
        std::fclose(main_);
        main_ = nullptr;
    }
}

} // namespace fiber