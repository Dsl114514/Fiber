# CONTEXT: Fiber — Bedrock 原生 Mod Loader(二代,完全重制)

> 本文件记录项目的 目标 / 事实 / 术语 / 决策。风格继承自 Fiber-old 的 CONTEXT.md。
> 术语定义见 GLOSSARY.md;重大取舍的"为什么"见 docs/adr/。

## 目标(GOAL)
为 Minecraft Bedrock (Windows, 1.26.33.1) 完全重新制作原生模组加载器 **Fiber**:
- 注入加载原生 Mod DLL,提供 C++ API;
- 范围比旧 Fiber 更大:除聊天拦截外,要建设 **tick/事件系统与完整 API 面**;
- 架构上预留多版本支持(hook 点特征码定位,不硬编码 RVA)。

## 环境事实(FACTS)
- 版本目录: `E:\mcb\bedrock_versions\1.26.3301`,版本 1.26.33.1
- 主可执行文件: `Minecraft.Windows.exe`(339,816,272 字节)
- 打包为 `Microsoft.MinecraftUWP` 1.26.3301.0, x64, `runFullTrust`,关闭文件系统/注册表虚拟化 → 真实可写文件系统,利于注入
- 游戏二进制硬事实(PE 头非标、文件偏移→RVA 映射、TextPacketPayload handler 位置等)见 `docs/RE_progress.md`(自 Fiber-old 平移)
- **preload 侧载通道已证实(2026-10 取证 + 2026-11-01 探针实测,报告 `docs/preload_investigation.md`)**:`preload\` 下 DLL 确实会自动加载,但机制**不是** Minecraft 自身目录扫描 —— 游戏静态导入 `PreloadCpp.dll`,而本机该文件是 **BedrockBoot 启动器自带的预加载器**(Round-Studio / "PreLoadCpp - BedrockBoot DLL Preloader" / 26.7.19 / Detours / 无签名 / 导出 `Load`),由它枚举 `preload\` 并 LoadLibrary。**实测确认(探针 `fiber_probe.dll`)**:BedrockBoot 日志明确枚举加载任意命名 DLL("Successfully loaded 2 DLL(s)");加载时机 **t ≈ 0.1–0.35 s**(游戏初始化之前)→ hook 必须延后;路径推导(父目录=游戏根 / exe 路径 / CWD)三条独立一致且**无任何 `FIBER_*` 环境变量**;启动命令为直接拉起 exe、无参数;`DLL_PROCESS_DETACH` 不保证触发(进程可能被强杀);ASLR 生效,基址必须运行时获取。该通道属启动器,不属游戏。
- **补丁通道事实(同日取证)**:exe 存在 TLS 目录与真实 TLS 回调(RVA `0xE527750`,紧邻导出目录);导入表物理上位于非标段 `.addImp`(rva `0x11A13000`,~47MB 以零填充为主,段首与证书目录重叠);导出表含 `GIT_SHA`/`BUILD_ID`/`GIT_BRANCH`/`GIT_COMMIT_TIME` 构建标记 → **版本识别可直接读导出符号,无需哈希整个 339MB exe**(服务于 D30)
- 逆向工具链(15 个分析脚本)已平移至 `tools/`;新增自研 `docs/re_imports.py`(PE 导入/导出/TLS/证书解析器,适配非标 PE)
- 无官方源码,需逆向工程;开发环境: Windows, .NET 10, Python 3.14.3, VS2026, CMake+Ninja

## 术语(TERMS)
见 GLOSSARY.md。

## 决策(DECISIONS)

### 继承的(逆向相关)
- **D-R1**: 逆向路线 = **定点逆向**(RTTI/字符串引用/特征码定位 hook 点),不做全量反编译
- **D-R2**: 逆向资产(tools/ + RE_progress.md)自 Fiber-old 平移,视为已交付的客观事实
- **D-R3**: 游戏二进制事实已确认:`config\BedrockBoot2\row\Minecraft.Windows.exe` 与根目录 exe 为同一程序(row 是基岩内部渲染器代号);聊天 hook 点已定位:TextPacketPayload handler RVA `0x32495B9`–`0x324ABD9`(详见 RE_progress.md)

### 新定的(本轮拷问)
- **D1**: 旧 Fiber 废弃原因 = 代码实现质量 + 架构方向 + 功能范围三项都不满意 → 新项目**不自动继承**旧代码与旧决策,仅继承逆向资产(D-R2)
- **D2**: 项目位置 = `E:\mcb\Fiber`(新代码),旧项目改名 `E:\mcb\Fiber-old` 完整保留备查
- **D3**: 目标版本策略 = **单版本优先(1.26.33.1),架构预留多版本** → hook 点以特征码定位,不硬编码 RVA
- **D4**: 核心验收范围 = **不止聊天命令拦截**,要建设 tick/事件系统 + 完整 API 面
- **D5**: 清单格式 = **TOML**(mod 重构字段:依赖带版本约束),ADR 0001
- **D6**: Mod 契约 = **多入口导出**(Fiber_OnLoad / Fiber_OnUnload / Fiber_GetDescriptor,C ABI),ADR 0002
- **D7**: 事件系统 = **内核统一事件总线 + 强类型封装**(Subscribe(event_id, cb, priority),支持取消/消费)
- **D8**: 线程契约 = **全部 Mod 回调在游戏主线程**(入队 → 主循环分发点分发),ADR 0003
- **D9**: 工具链 = **C++20 / MSVC / CMake+Ninja(/MT)**,质量靠严格规范(warnings-as-errors、模块边界、clang-format),不靠换语言
- **D10**: M1 验收 = **加强版**:Mod 加载 + 日志输出 modid + 全游戏会话存活 + 退出时 Fiber_OnUnload 被调用且无崩溃
- **D11**: 部署形态 = **三件套**(fiber.exe / FiberRuntime.dll / mods\)拷入游戏根目录,零安装、绿色可卸载
- **D12**: 第三方依赖策略 = **vendor 质量库**:toml++(清单解析)+ MinHook(蹦床引擎);旧自研 hook 引擎因本质缺陷(未拷贝原指令即 UD2)不继承
- **D13**: 崩溃隔离 = 每个 Mod 回调套 SEH,崩溃 → 日志 + **自动禁用该 Mod**(重载成功后自动解除),游戏不倒
- **D14**: 生命周期 = **v1 全热重载**(文件监视 + 影子副本加载 + 静默期卸载),ADR 0004;状态保持不做(每次重载 = 全新状态)
- **D15**: v1 首批事件 = **聊天双向 + tick + 输入事件**三族;聊天先做 **incoming**(TextPacketPayload,RVA 已定位),outgoing(Command::execute)后续补
- **D16**: 日志 = **每 Mod 独立文件** `logs\<modid>.log`;Runtime 自身日志仍写 fiber.log
- **D17**: API 兼容 = **版本号 + N-1 后向兼容**(破坏性变更升 major,加函数只在表尾追加)
- **D18**: 清单 schema = modid/name/version/authors/description/entry/api_version + [dependencies] 版本范围表;**身份以清单为准**,DLL 描述符交叉校验,不一致拒载;v1 文件夹制(mods\<modid>\)
- **D19**: 依赖版本范围 = **完整 semver range 规范**(含 ||、预发布规则)
- **D20**: 总线 API 形态 = **通用 C 核心 + header-only C++ 强类型封装**,ADR 0005
- **D21**(Q37 修订): 路线图 = **总线先行**:M1 骨架链路(**临时注入器过渡**)→ M2 事件总线+主循环分发点+tick → M3 聊天 incoming → M4 热重载 → **M5 GUI 补丁器+一键部署(CLI 原型提前到 M1 配套)** → M6 输入事件+聊天 outgoing
- **D22**(已定稿): 注入哲学 = fiber.exe 为 **GUI 补丁器**:指定游戏 EXE → 产出加载 FiberRuntime 的修改版 EXE
- **D23**: 补丁输出 = **双模式**:默认**原位补丁**(自动备份 .bak,任何启动器透明生效)+ 可选导出补丁副本;还原 = 从备份恢复
- **D24**: GUI 范围 = **完整状态面板**:路径选择 + 补丁/还原 + 版本检测/补丁状态/游戏运行检测/mod 目录快捷打开 + 日志区
- **D25**: GUI 技术栈 = **C# / WinUI 3**(环境已有 .NET 10);补丁核心逻辑随之用 C# 实现
- **D26**: DLL 寻路 = 修改版 exe **同目录相对寻路** FiberRuntime.dll;找不到 → 游戏原样运行(无 Fiber 不崩溃)
- **D27**: 热重载失败回退 = **保持旧版继续运行**,日志记录失败原因,下次文件变化再试
- **D28**: 重复补丁语义 = GUI/CLI 检测已补丁 → 提示确认 → **从原始备份重新补丁**(幂等)
- **D29**: semver range 解析 = **vendor 单头库**(third_party/,Neargye/semver 风格)
- **D30**: 游戏更新失效 = GUI 检测 exe 与备份不一致 → 提示"补丁失效" + **一键重补**
- **D31**: Mod 禁用状态 = **mod 文件夹内 `.disabled` 标记文件**(随文件夹走,资源管理器可手工启停,热重载响应标记变化)
- **D32**: Runtime 配置 = **v1 无配置文件**(全部合理默认;真需求出现再加)
- **D33**: Runtime 部署 = **GUI 一键部署**(复制 FiberRuntime.dll 为补丁流程一部分,可选装示例 mod)
- **D34**: 工程治理 = **git 仓库**(E:\mcb\Fiber) + **远程仓库 GitHub: Dsl114514/Fiber**(后续用户指定);v1 不做单测(用户选择)
- **D35**(Q38 修订): M1 加载通道 = 见 D36;临时注入器不再是首选
- **D36**: 加载通道 = **双轨**:preload 为主(零 PE 修改、开发迭代秒级)+ 自持补丁为兜底(官方启动器/无 preload 环境可用),ADR 0006;Runtime 必须内置**单实例保护**(命名互斥体 + 模块已加载检测),且不得依赖启动器环境变量
- **D37**: BedrockBoot 启动器自有 mod 系统(`mods\` + `mods.json`)= **v1 不集成**,列入 backlog;"启动器无关"不作为硬原则,将来需要再评估
- **D38**(2026-11-01 实测通过): M1 加载通道 = **preload 直上** —— 探针 `fiber_probe.dll` 已被 BedrockBoot 枚举加载成功(其日志 "Successfully loaded 2 DLL(s)"),任意命名 DLL 生效、路径推导成立、无需环境变量;**D35 的临时注入器作废**。Runtime 必须:延后装 hook(等游戏初始化)、运行时取模块基址(ASLR)、不依赖 DLL_PROCESS_DETACH 做关键清理
- **D39**: 补丁兜底技术 = **入口 stub 补丁**(改 `AddressOfEntryPoint` 指向新增段内的 stub:`LoadLibraryW(FiberRuntime.dll)` → 跳回原入口);**不改动** `.addImp` 导入表与证书目录,幂等/还原实现最简
- **D40**(Q42 重答): 分发点选定方法 = **直接运行时探针实测,不做静态先行** —— 探针 DLL 在**一次游戏会话**内测出 9 个候选的调用次数/间隔/线程 ID,直接定论(前提:M1 的 DLL 构建链先就位);该探针与 D38 的通道探针**合并为同一交付物**

## 开放问题(OPEN)
- 分发点最终选定:静态分析完成后仍需一次运行时验证(探针 DLL 仅计数,借 preload 通道跑一次会话)
- `onTick` / `startFrame` / `endFrame` 的反向引用尚未取得(串 RVA 已知:`0xE3C941F` / `0xE3C9970` / `0xE3C99E3`)
- 补丁幂等标记的具体实现;M2 起各里程碑细化(顺序已定 D21)
- BedrockBoot `mods.json` 语义未逆向(仅当将来要集成时才需要)

## 历史参考(HISTORY)
- Fiber-old(E:\mcb\Fiber-old):M1 链路(挂起拉起→远程线程注入→manifest 解析→Fiber_Init 调用)曾验证通过;M2 的 HookEngine/ChatHookManager 代码写了一半未接线。其 AGENTS.md 中有踩坑记录(std::move 顺序、PE 非标、14 字节 JMP 蹦床等),新项目实现时可参考但需重新验证。
