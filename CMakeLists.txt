cmake_minimum_required(VERSION 3.20)

project(Fiber VERSION 0.1.0 LANGUAGES C CXX)

# ---- 语言与规范(D9:全 MSVC + C++20,严格规范,不引入第三方构建系统) ----
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT MSVC)
    message(FATAL_ERROR "Fiber 只支持 MSVC(C++20);检测到编译器: ${CMAKE_CXX_COMPILER_ID}")
endif ()

# 静态 CRT(/MT),Mod 与 Runtime 之间不共享 CRT 状态
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# 警告即错误 + 严格一致性
add_compile_options(
    /W4
    /WX
    /permissive-
    /utf-8
    /EHsc
    /Zc:__cplusplus
    /Zc:preprocessor
    /MP
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ---- 第三方(vendor)----
add_subdirectory(third_party)

# ---- 目标 ----
# M1:通道探针(验证 preload 通道,不装 hook)
add_subdirectory(src/probe)

# M2:钩子探针(MinHook 计数 9 个主循环候选 → 定事件分发点)
add_subdirectory(src/hookprobe)

# M1:Runtime 骨架(TOML 清单 / 多入口契约 / 影子副本 / 独立日志)
add_subdirectory(src/runtime)

# 示例 Mod(M1 验收用)
add_subdirectory(src/sample_mod)

# M2+:事件总线 —— 随里程碑推进逐个加入