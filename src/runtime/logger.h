// Fiber Runtime —— 日志
//
// D16:Runtime 自身日志写 <游戏根>\fiber.log;每个 Mod 独立 logs\<modid>.log
// 线程安全(内部互斥);所有写入立即 flush(便于崩溃后取证)

#pragma once

#include <cstdio>
#include <map>
#include <mutex>
#include <string>

namespace fiber {

// 与 FiberLogLevel 取值对齐(fiber_api.h)
enum LogLevel : int { kInfo = 0, kWarn = 1, kError = 2 };

class Logger {
public:
    Logger() = default;
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // game_root: 游戏根目录;内部会创建 logs\ 子目录
    bool init(const std::wstring& game_root);
    void close();

    void log(int level, const std::string& message);

    // 每 Mod 日志(首次调用时惰性打开;失败则退回主日志并在行内标注)
    void mod_log(const std::string& modid, int level, const std::string& message);
    void close_mod_log(const std::string& modid);

    bool ok() const { return main_ != nullptr; }

private:
    void write_line(std::FILE* f, const std::string& tag, int level, const std::string& message);

    std::mutex                      mu_;
    std::FILE*                      main_ = nullptr;
    std::wstring                    logs_dir_;
    std::map<std::string, std::FILE*> mods_;
};

} // namespace fiber