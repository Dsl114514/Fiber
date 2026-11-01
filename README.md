# Fiber — Minecraft Bedrock 原生 Mod Loader(二代)

把原生 C++ Mod 加载进 Minecraft Bedrock (Windows 1.26.33.1),通过**事件总线**让 Mod 参与游戏运行,并在 v1 就支持**热重载**。

> 本项目是**完全重制**:旧 Fiber(现 `E:\mcb\Fiber-old`)已废弃,仅作参考。
> 设计与决策见 [CONTEXT.md](./CONTEXT.md)、术语见 [GLOSSARY.md](./GLOSSARY.md)、取舍原因见 [docs/adr/](./docs/adr/)。
> 现状:**设计已冻结,尚未开始编码**。

## 架构

```
fiber.exe (补丁器, C# / WinUI 3)
  ├── 给游戏 exe 打入口 stub 补丁(可选通道)
  ├── 一键部署 FiberRuntime.dll 到游戏根目录
  ├── 检测游戏更新 / 补丁失效 → 一键重补
  └── 还原(从 .bak 备份)

FiberRuntime.dll (运行时, C++20)
  ├── 解析 mods\<modid>\manifest.toml(TOML)
  ├── 依赖解析(完整 semver range)→ 拓扑序加载
  ├── 影子副本加载 + 静默期卸载(热重载)
  ├── 事件总线:订阅/优先级/取消,SEH 隔离
  ├── 主线程分发(入队 → 主循环分发点)
  └── 日志:fiber.log / logs\<modid>.log

Mod SDK (fiber_api.h)
  ├── C ABI 核心(稳定,N-1 兼容)
  └── header-only C++ 强类型事件封装

Mod (mods\<modid>\)
  ├── manifest.toml
  └── <modid>.dll  导出 Fiber_GetDescriptor / Fiber_OnLoad / Fiber_OnUnload
```

## 加载通道(双轨,ADR 0006)

| 通道 | 机制 | 定位 |
|---|---|---|
| **preload(主)** | 把 `FiberRuntime.dll` 放进游戏根目录 `preload\`;BedrockBoot 自带的 `PreLoadCpp.dll` 预加载器在启动时 LoadLibrary 它 | 零 PE 修改、开发迭代秒级 |
| **入口 stub 补丁(兜底)** | 改 `AddressOfEntryPoint` → 新增段中的 stub(`LoadLibraryW(FiberRuntime.dll)` → 跳回原入口) | 不依赖启动器,任意启动方式生效 |

- Runtime 内置**单实例保护**(双通道同时生效不会双重 hook)
- preload 加载时机极早 → **hook 安装必须延后**到游戏初始化完成
- 不依赖启动器环境变量:由 Runtime 从自身模块路径推导游戏根

## Mod 契约

`mods/<modid>/manifest.toml`:

```toml
modid = "sample"
name = "Sample Mod"
version = "1.0.0"
authors = ["you"]
description = "..."
entry = "sample.dll"
api_version = 2

[dependencies]
other_mod = ">=1.0.0 <2.0.0"   # 完整 semver range
```

身份以清单为准,DLL 内描述符交叉校验,不一致拒载。v1 为文件夹制。

## 事件系统(ADR 0003 / 0005)

- **统一事件总线** + **C 核心 API**(`fiber_Subscribe(event_id, cb, priority, ctx)` / `fiber_Unsubscribe`)+ **header-only C++ 强类型封装**
- 事件可**取消/消费**;订阅带**优先级**
- **全部 Mod 回调在游戏主线程执行**(入队 → 主循环分发点),Mod 作者无需考虑加锁
- 每个回调套 **SEH**:崩溃 → 记日志 + **自动禁用该 Mod**(重载成功后解除)
- 首批事件:**聊天双向 + tick + 输入**;聊天先做 incoming(TextPacketPayload)

## 热重载(v1 范围,ADR 0004)

监视 `mods\` 变化 → 影子副本加载(源 DLL 永不被锁)→ 静默期卸载(停派发 / 排空队列 / 等在途回调 / `Fiber_OnUnload` / 按 modid 注销全部订阅 / FreeLibrary)。
重载失败 → **保持旧版继续运行**,下次文件变化再试。`.disabled` 标记文件控制启停。不做状态保持。

## 里程碑

| # | 内容 | 状态 |
|---|---|---|
| **M1** | **通道探针**(验证 preload 通道;**并顺带实测 9 个主循环候选的调用频率/线程归属,为 M2 直接定分发点**) → Runtime 骨架:TOML 清单 + 多入口契约 + 影子副本 + 独立日志。验收 = Mod 加载 + 日志输出 modid + 全游戏会话存活 + 退出时 `Fiber_OnUnload` 被调用且无崩溃 | 待开始 |
| M2 | 事件总线 + 主循环分发点(由 M1 探针实测结果直接选定,不做静态先行)+ tick 事件 | |
| M3 | 聊天 incoming(TextPacketPayload) | |
| M4 | 热重载 | |
| M5 | GUI 补丁器 + 一键部署(WinUI 3 + C#) | |
| M6 | 输入事件 + 聊天 outgoing(Command::execute) | |

## 逆向资产(已就位)

| 资产 | 内容 |
|---|---|
| 聊天 hook 点 | `TextPacketPayload` handler,RVA `0x32495B9`–`0x324ABD9`(LEA 引用 `0x3249CBE`) |
| 主循环候选 | 9 个候选(含 `.pdata` 区间、虚表槽、序言锚点):首选 `MinecraftGame::update` `0x87AC90`(15KB)。见 [docs/mainloop_research.md](./docs/mainloop_research.md) |
| preload 机制 | 第三方(启动器自带)预加载器 `PreLoadCpp.dll`,非 Mojang 组件。见 [docs/preload_investigation.md](./docs/preload_investigation.md) |
| 补丁通道事实 | exe 有 TLS 回调(RVA `0xE527750`);导入表位于非标段 `.addImp`;导出表含 `GIT_SHA`/`GIT_COMMIT_TIME` 等构建标记(可直接做版本识别) |
| 二进制性质 | **RTTI 已剥离**(无 `.?AV...` 装饰名);虚表存**绝对 VA**(`ImageBase 0x140000000`);`.pdata` 覆盖 855,165 个函数 |
| 工具 | `tools/`(15 个脚本)+ `docs/re_imports.py`(PE 解析)+ `docs/ml_*.py`(边界/虚表/序言复验) |

## 工程

- 仓库:`https://github.com/Dsl114514/Fiber`
- 工具链:C++20 / MSVC / CMake + Ninja(`/MT`);GUI 用 C# / .NET 10 + WinUI 3
- vendor 依赖:toml++(清单)、MinHook(hook 引擎)、semver 单头库
- 不写单元测试(用户决定);v1 无配置文件;无安装器(绿色部署)