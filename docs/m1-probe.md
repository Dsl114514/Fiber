# M1 通道探针(第一个交付物)

## 它是干什么的

回答 D38 的三个问题 —— **只写日志,不装任何 hook**,对游戏行为零影响:

1. **preload 通道会不会加载"我们自己命名的 DLL"?** —— 探针名为 `fiber_probe.dll`,不是 `gdk_patch.dll`;它出现在日志里就说明通道对任意命名 DLL 生效。
2. **加载时机有多早?** —— 探针记录 attach 时的线程 id、模块总数增长曲线、关键模块(v8.dll / cohtml / fmod / WindowsAppRuntime …)出现的先后、首个可见窗口出现的时间。
3. **进程内路径推导是否成立?** —— 记录宿主 exe 路径、探针 DLL 路径、DLL 所在目录、当前工作目录、命令行。

顺带记录:宿主 exe 的模块基址(后续 RVA→VA 换算用)、`FIBER_*` 环境变量是否存在(验证"Runtime 不能依赖启动器传参"的假设)、`preload\` 目录条目清单。

## 部署(已完成)

```
E:\mcb\bedrock_versions\1.26.3301\preload\fiber_probe.dll   ← 由 build\dist\ 拷入
```

## 测试步骤

1. 用**平时的方式**启动游戏(BedrockBoot2 / 官方启动器 / 直接双击均可 —— 探针的目的之一就是看清不同启动方式下的差异)
2. 进主菜单、加载一个世界、玩 1–2 分钟(能看到游戏画面即可)
3. 正常退出游戏
4. 检查 `E:\mcb\bedrock_versions\1.26.3301\fiber_probe.log` 是否出现

## 判读要点(我会做)

| 现象 | 结论 |
|---|---|
| 日志出现"fiber_probe 会话开始" | ✅ preload 通道可用,任意命名 DLL 会被加载 |
| 日志完全没出现 | ❌ 通道对 DLL 有白名单/或只在特定启动方式下生效 → 需要改用补丁通道 |
| attach 线程 id 与工作线程 id 相同/不同 | 判断加载发生在主线程还是加载器线程 |
| 关键模块出现时间线 | 判断"游戏初始化完成"的时点 → 决定 hook 安装的延后策略 |
| 首个可见窗口时间 | 主线程分发点可用的最早时刻参考 |
| 命令行 / 工作目录 | 看清启动器到底怎么拉起游戏(与 D26 路径推导策略对照) |

## 卸载

删除 `preload\fiber_probe.dll` 即可,不留任何痕迹(日志文件可自行删除)。

## 已完成的验证(交付前)

主代理在把探针交给你之前,先做了一次**无害宿主冒烟测试**:用 `LoadLibraryW` 把 `fiber_probe.dll` 加载进一个临时 PowerShell 进程,确认 DllMain 与工作线程不会崩、日志能正常写出。

结果:LoadLibrary 返回 `0x7FFB5D7E0000`(成功),日志完整写出(路径推导 / 线程 id / `preload` 目录枚举 / 模块数 81 / 关键模块识别全部正常)。

测试用环境变量 `FIBER_PROBE_LOG=<路径>` 可覆盖日志输出位置(不设则写宿主 exe 所在目录)。

## 重新构建

```powershell
E:\mcb\Fiber\build.ps1 -Config Release
# 产物: E:\mcb\Fiber\build\dist\fiber_probe.dll
```

工具链:C++20 / MSVC(VS18 Community)/ CMake(Ninja)/ `/MT` / `/W4 /WX`(警告即错误,D9)。

## 源码

- `src/probe/probe.cpp` —— 探针本体(DllMain 只起线程,所有工作在 worker)
- `src/probe/CMakeLists.txt`
- 根 `CMakeLists.txt`、`build.ps1`

## 下一步(探针通过后)

1. Runtime 骨架(`src/runtime/`):TOML 清单解析(toml++ 已 vendor)、多入口契约、影子副本加载、`fiber.log` / `logs\<modid>.log`
2. 探针第二版:用 MinHook(vendor 已就位)挂 9 个主循环候选计数 → 实测频率/线程 → **直接选定 M2 的事件分发点**(D40)