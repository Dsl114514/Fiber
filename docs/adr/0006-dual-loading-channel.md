# 加载通道双轨:preload 优先,自持补丁兜底

加载通道定为两条并存:**主通道** = 把 `FiberRuntime.dll` 放入游戏根目录的 `preload\`,由 BedrockBoot 启动器自带的 `PreLoadCpp.dll` 预加载器在游戏启动时 LoadLibrary;**兜底通道** = 自持补丁,给 `Minecraft.Windows.exe` 打入口 stub,使任意启动方式(官方启动器/直接双击)都加载 FiberRuntime.dll。

为什么两条都要:preload 通道是本机真实游玩路径下的零 PE 修改、开发迭代秒级方案(取证见 `docs/preload_investigation.md`),但它的存在、版本与行为由启动器的私有组件(Round-Studio "PreLoadCpp - BedrockBoot DLL Preloader",非 Mojang 组件)决定 —— 官方 Xbox 应用启动、游戏重装、启动器更新都可能让它失效,且**失效是静默的**(不产生 `fiber.log`)。自持补丁不依赖任何第三方组件,但实现成本与风险显著更高(非标 PE、`.addImp` 段、证书目录重叠、版本漂移)。二者互补:日常与开发走 preload,可移植性与自主性靠补丁。

# Considered Options
- 纯 preload:产品最简,但把 Fiber 的可用性绑在启动器的私有组件上,失败静默,无法自证存活。
- 纯自持补丁:自主性最强,但首版就要啃非标 PE 补丁 + 版本漂移处理,并放弃现成的零成本通道。

# Consequences
- Runtime 必须内置**单实例保护**(命名互斥体 + 模块已加载检测):双通道同时生效会导致 FiberRuntime 被加载两次 → 双重 hook / 事件被派发两遍。
- Runtime 不得依赖启动器传入的环境变量:preload 通道下没有 Launcher 传递 D14 式变量,必须从自身模块路径推导游戏根(与 D26 同源)。
- preload 加载时机极早(游戏尚未初始化)→ **hook 安装必须延后**到游戏初始化完成(等待/轮询);这条约束对两条通道均成立。
- 部署文档与 GUI 需分别覆盖两条通道;补丁器 GUI(D24)保留,但优先级低于"preload 通道打通"。