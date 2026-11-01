// Fiber Runtime —— 应用层(工作线程入口)
//
// 职责:
//   1. 推导游戏根(无环境变量可用,2026-11-01 探针实测)
//   2. 初始化日志、记录启动事实
//   3. 单实例保护(D36:双通道同时生效不得双重加载)
//   4. 驱动 ModLoader;等待退出信号 / 主窗口消失后干净卸载
//
// 注:关键清理**不能只依赖 DLL_PROCESS_DETACH** —— 实测进程被强杀时 detach 不触发。

#pragma once

#include <windows.h>

namespace fiber {

void app_main(HMODULE self, HANDLE stop_event);

} // namespace fiber