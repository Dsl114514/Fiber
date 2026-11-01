// Fiber Mod SDK —— Mod 与 Runtime 之间的 C ABI 契约
//
// 决策依据:
//   D6  / ADR 0002  Mod 契约 = 多入口导出(Fiber_GetDescriptor / Fiber_OnLoad / Fiber_OnUnload)
//   D17            API 兼容 = 版本号 + N-1 后向兼容;加函数只在表尾追加,不改既有字段顺序
//   D18            身份以 manifest.toml 为准;本头里的描述符仅用于交叉校验
//   D20 / ADR 0005 事件总线 = 通用 C 核心 + header-only C++ 强类型封装(事件部分 M2 加入)
//
// 本文件是**稳定 C ABI**:Mod 用任何 MSVC 版本编译都能链接,不需要导入库。

#pragma once

#include <stdint.h>

#ifdef __cplusplus
#define FIBER_EXPORT extern "C" __declspec(dllexport)
#else
#define FIBER_EXPORT __declspec(dllexport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// 版本
// ---------------------------------------------------------------------------

// Runtime 提供的 API 主版本。Mod 在 Fiber_OnLoad 中被调用时,可据 api->version 判断。
#define FIBER_API_VERSION_MAJOR 1u
#define FIBER_API_VERSION_MINOR 0u

// ---------------------------------------------------------------------------
// 日志级别
// ---------------------------------------------------------------------------

typedef enum FiberLogLevel {
    FIBER_LOG_INFO  = 0,
    FIBER_LOG_WARN  = 1,
    FIBER_LOG_ERROR = 2
} FiberLogLevel;

// ---------------------------------------------------------------------------
// 函数表(Mod → Runtime)
//
// 兼容规则(D17):只能追加到表尾;既有字段的顺序与语义不得变更。
// 表尾追加时同时提升 FIBER_API_VERSION_MINOR。
// ---------------------------------------------------------------------------

typedef struct FiberApi {
    /* 表版本 = FIBER_API_VERSION_MAJOR */
    uint32_t version;

    /* ---- v1 ---- */

    /* 写入该 Mod 自己的日志文件 logs\<modid>.log(D16) */
    void        (*Log)(int level, const char* message);

    /* 游戏版本字符串,例如 "1.26.33.1"(由 Runtime 探测,非环境变量) */
    const char* (*GetGameVersion)(void);

    /* mods 目录绝对路径(UTF-8) */
    const char* (*GetModsDir)(void);

    /* 当前 Mod 的 modid(由 Runtime 绑定,Mod 无需自报) */
    const char* (*GetModId)(void);

    /* 当前 Mod 自己的目录绝对路径(UTF-8),用于放配置/资源 */
    const char* (*GetModDir)(void);

} FiberApi;

// ---------------------------------------------------------------------------
// Mod 描述符(与 manifest.toml 交叉校验,D18)
// ---------------------------------------------------------------------------

typedef struct FiberModDescriptor {
    /* 调用方应填 sizeof(FiberModDescriptor),Runtime 据此判断结构版本 */
    uint32_t    struct_size;
    /* Mod 需要的 API 主版本;与 Runtime 不兼容时 Runtime 拒绝加载 */
    uint32_t    required_api;
    const char* modid;
    const char* name;
    const char* version;
} FiberModDescriptor;

// ---------------------------------------------------------------------------
// 导出契约(三个入口)
//
//   Fiber_GetDescriptor  可选。填 *out 并返回 0 表示成功;Runtime 会与清单比对
//                        (modid / name / version),不一致则拒绝加载。
//   Fiber_OnLoad         必须。返回 0 表示成功;非 0 则 Runtime 拒绝该 Mod
//                        (记日志,不影响其他 Mod)。
//   Fiber_OnUnload       可选。Runtime 在卸载前调用(正常退出、热重载、手动禁用),
//                        调用时该 Mod 的全部事件订阅已被注销。
//
// 注意:OnUnload 之后 Runtime 才会 FreeLibrary,因此 OnUnload 内不应再依赖
//       其他线程上的回调(D8:全部回调都在游戏主线程,故无并发回调)。
// ---------------------------------------------------------------------------

typedef int  (__cdecl *FiberGetDescriptorFn)(FiberModDescriptor* out);
typedef int  (__cdecl *FiberOnLoadFn)(const FiberApi* api);
typedef void (__cdecl *FiberOnUnloadFn)(void);

#ifdef __cplusplus
} // extern "C"
#endif

// ---------------------------------------------------------------------------
// C++ 侧便利宏(仅为省事;不改变 ABI)
// ---------------------------------------------------------------------------

#ifdef __cplusplus

/* 在 Mod 源码里这样写:
 *
 *   FIBER_MOD_BEGIN
 *   FIBER_MOD_DESCRIPTOR("my_mod", "My Mod", "1.0.0", 1u)
 *   FIBER_MOD_ON_LOAD(api) {
 *       api->Log(FIBER_LOG_INFO, "my_mod loaded");
 *       return 0;
 *   }
 *   FIBER_MOD_ON_UNLOAD() {
 *       api->Log(FIBER_LOG_INFO, "my_mod unloading");
 *   }
 *   FIBER_MOD_END
 */

#define FIBER_IMPL_DESCRIPTOR(modid_, name_, version_, api_)                    \
    FIBER_EXPORT int __cdecl Fiber_GetDescriptor(FiberModDescriptor* out) {     \
        if (out == nullptr ||                                                   \
            out->struct_size < sizeof(FiberModDescriptor)) {                    \
            return 1;                                                           \
        }                                                                       \
        out->required_api = (api_);                                             \
        out->modid        = (modid_);                                           \
        out->name         = (name_);                                            \
        out->version      = (version_);                                         \
        return 0;                                                               \
    }

#define FIBER_IMPL_ON_LOAD(api_ptr_)                                            \
    FIBER_EXPORT int __cdecl Fiber_OnLoad(const FiberApi* api_ptr_)

#define FIBER_IMPL_ON_UNLOAD()                                                  \
    FIBER_EXPORT void __cdecl Fiber_OnUnload(void)

#endif // __cplusplus