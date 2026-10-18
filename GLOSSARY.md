# Fiber

Minecraft Bedrock (Windows) 的原生模组加载器:把第三方 Mod DLL 注入游戏进程,并通过事件系统让 Mod 参与游戏运行。

## Language

### 核心概念

**Fiber**:
本项目。注入式原生模组加载器。旧 Fiber(现 Fiber-old)已废弃,仅作参考。
_Avoid_: BedrockBoot、旧 Fiber(指代本项目时)

**Patcher(补丁器)**:
fiber.exe,GUI 应用(C#/WinUI 3):给游戏 EXE 打补丁、一键部署 Runtime、管理还原与重补丁。不参与游戏运行期。
_Avoid_: 注入器、加载器、启动器

**补丁(Patch)**:
对游戏 EXE 的最小修改,使游戏启动时自动加载 FiberRuntime.dll。默认原位补丁 + 自动备份,可选导出副本。
_Avoid_: 破解、魔改

**补丁桩(Patch Stub)**:
补丁写入 EXE 的引导代码:启动时从 EXE 同目录寻找并加载 FiberRuntime.dll;找不到则游戏原样运行。

**加载通道(Loading Channel)**:
Runtime 进入游戏进程的途径。最终形态 = 补丁桩加载;临时远程线程注入器仅作 M1 过渡。
_Avoid_: 注入(不再作为产品概念)

**部署(Deploy)**:
把 FiberRuntime.dll(及可选示例 Mod)复制到游戏根目录的一键动作,由补丁器完成。
_Avoid_: 安装

**Runtime(运行时)**:
注入进游戏进程后常驻的 DLL。发现、解析、加载 Mod,运营事件总线,向 Mod 暴露 API。
_Avoid_: 注入 DLL、核心(指代这个组件时)

**Mod(模组)**:
交付给 Fiber 的第三方功能扩展单元,物理形态为原生 C++ DLL + 清单,以 modid 唯一标识。
_Avoid_: 插件、 addon(避免与基岩官方行为包/资源包概念混淆)

**modid**:
Mod 的全局唯一标识符,用于加载顺序、依赖解析、事件注销。由清单声明。
_Avoid_: name(那是展示名,可重复)

### 加载与依赖

**Manifest(清单)**:
Mod 自带的 TOML 描述文件,声明身份、依赖、入口。
_Avoid_: 元数据文件、config

**依赖解析**:
加载前对全部 Mod 依赖做的校验:缺失 / 循环 / 版本不满足 → 拒绝加载并报告,绝不带病加载。
_Avoid_: 依赖检查(口语可用,文档统一用"依赖解析")

**加载顺序**:
由依赖图拓扑序决定,与目录枚举顺序无关。
_Avoid_: 优先级(priority 属于事件分发,不是加载顺序)

### 事件系统

**事件总线(Event Bus)**:
Runtime 内核的统一订阅与分发机构。所有游戏内事件经它流转。
_Avoid_: 消息队列、信号系统

**订阅(Subscribe)**:
Mod 向事件总线登记回调的动作,可带优先级。底层入口,Mod 作者通常用强类型封装。
_Avoid_: 注册(在文档中统一用"订阅")

**事件(事件)**:
游戏内一次可观察动作的通知(聊天、tick 等),携带载荷。订阅者可标记事件为已消费,阻断后续订阅者。
_Avoid_: 消息、hook(hook 专指内核对游戏函数的拦截)

**强类型封装(Typed Wrapper)**:
内核统一订阅接口之上,按事件类型封出的舒适 API(如 chat 事件的具名载荷)。Mod 作者的日常入口。
_Avoid_: 二级 API、helper

**主线程分发(Main-thread Dispatch)**:
线程契约:全部 Mod 回调都在游戏主线程执行,Runtime 内部入队、主循环统一定义分发点。Mod 回调内无需加锁。
_Avoid_: 线程池分发、异步回调

### 注入与逆向

**Hook 点**:
游戏进程内被内核拦截的函数。以特征码定位,不硬编码 RVA(多版本预留)。
_Avoid_: 偏移、地址(单独使用时)

**事件分发点(Dispatch Site)**:
主循环中被 hook 的函数,是主线程分发的执行位置。属于内核实现,Mod 不感知。
_Avoid_: tick hook(实现名,文档用语义名)

### 环境与资产

**目标版本**:
Minecraft Bedrock Windows 1.26.33.1(E:\mcb\bedrock_versions\1.26.3301)。多版本仅作架构预留。
_Avoid_: 支持版本列表(当前只有这一个)

**RE 资产**:
tools/ 下逆向脚本 + docs/ 下逆向发现文档(RE_progress、preload_investigation、mainloop_research),记录游戏二进制硬事实,视为客观资料。
_Avoid_: 旧代码(那是 Fiber-old 的实现,不属 RE 资产)

**Fiber-old**:
已废弃的前代项目(E:\mcb\Fiber-old)。经验与逆向结论可参考;代码与决策不自动继承。
_Avoid_: v1、旧版(避免暗示存在版本延续关系)

**入口会话(Loaded Session)**:
一次从 Runtime 注入到游戏退出的完整生命周期。M1 验收以单个入口会话为单位。
_Avoid_: 运行实例
