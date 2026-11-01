# preload 侧载机制取证报告

> 本报告由主代理在取证子代理失败退出后,基于其遗留产物 + 独立复验重建。
> 取证日期:2026-10-18 扫描 / 2026-11-01 复验。目标: `E:\mcb\bedrock_versions\1.26.3301`

## 判定(CONFIRMED,但机制被纠正)

**`preload\` 目录下的 DLL 确实会在游戏启动时被自动加载 —— 但这不是 Minecraft 自身的功能,也不是游戏 exe 的目录扫描。**

真实链路:

1. `Minecraft.Windows.exe` **静态导入** `PreloadCpp.dll`(导入表最后一个条目,证据见下)
2. 本机游戏根目录的 `PreloadCpp.dll` **不是 Mojang 组件,而是 BedrockBoot 启动器自带的预加载器**:
   - 版本信息: `CompanyName=Round-Studio`,`FileDescription=PreLoadCpp - BedrockBoot DLL Preloader`,`FileVersion=26.7.19`
   - PDB 路径 `D:\a\PreLoadCpp\PreLoadCpp\src\x64\Release\PreloadCpp.pdb`,仓库线索 `https://github.com/Round-Studio/PreLoadCpp`
   - 段名 `.detourc` / `.detourd` → 使用 Microsoft Detours(hook 库)
   - 导出 `Load` / `GetCommitHash` / `GetDllVersion`;**无 Authenticode 签名目录**
   - 导入 `FindFirstFileW` / `FindFirstFileExW` / `FindNextFileW` + `LoadLibraryA`;字符串含 `\preload`、`preload`
3. 该预加载器枚举 `preload\` 并 LoadLibrary 其中 DLL。`preload\gdk_patch.dll` 就是此类载荷(UPX 加壳、无导出、16KB)。

## 关键证据(带偏移)

### A. 游戏 exe 导入表引用 PreloadCpp.dll
```
dir[1] import  rva=0x11A13000  size=0x6A4      (位于 .addImp 段内)
导入名 "PreloadCpp.dll" 位于 file=0x117016A4 / rva=0x11A136A4
```
导入表完整清单(约 80 项)以 `PreloadCpp.dll` 结尾;同时含 `Microsoft.WindowsAppRuntime.Bootstrap.dll`、`libHttpClient.GDK.dll`、`cohtml.WindowsDesktop.dll`、`fmod.dll`、`PlayFabMultiplayerGDK.dll`、`WERHandler.dll`、`PreloadCpp.dll`。

> **对补丁方案的意义**:导入表结构标准(descriptor + ILT/IAT),但物理上落在非标准段 `.addImp`(rva=0x11A13000, vsize=0x2D0F800≈47MB, 熵=0.14 → 绝大部分为零填充;段首同时承载 dir[4] certificate=file 0x11701000)。**"加一个导入项"的补丁可行,但必须处理该段的巨大零区与证书目录重叠,属中等风险实现。**

### B. 游戏 exe 有 TLS 目录与 TLS 回调 → TLS 补丁通道存在
```
dir[9] tls   rva=0xE02B060 size=0x28        (在 .rdata 内,非 .tls 段)
.tls  段:    rva=0x11926000 vsize=0x2C6D file=0x11617200 熵=0.00
TLS struct:  EndAddressOfRawData(VA)=0x151928C6C → RVA 0x11928C6C(恰为 .tls 段末尾)
             AddressOfCallBacks(VA)=0x14E527750 → RVA 0xE527750
             紧邻 dir[0] export rva=0xE527788(同区)
```
即:**TLS 回调数组真实存在且位于 .rdata 导出目录附近**。TLS 回调在入口点之前执行,是一条可用的"最早加载"补丁通道。

### C. 游戏 exe 导出了构建标记(可用于版本识别)
```
dir[0] export rva=0xE527788 size=0x145,7 个导出:
  ?GIT_SHA@stamp@@3QEBDEB        ← 字符串
  ?BUILD_ID@stamp@@3QEBDEB
  ?GIT_BRANCH@stamp@@3QEBDEB
  ?MERGE_BASE_SHA@stamp@@3QEBDEB
  ?GIT_COMMIT_TIME@stamp@@3_JB   ← int64 时间戳
  AmdPowerXpressRequestHighPerformance / NvOptimusEnablement(显卡标志)
```
> **对补丁器 GUI(D30 游戏更新检测)的价值**:不必哈希整个 339MB exe,直接读导出表里的 `GIT_SHA` / `GIT_COMMIT_TIME` 字符串即可精确识别构建版本。

### D. 游戏二进制本身**没有** preload 目录扫描逻辑
`docs/preload_scan_results.txt`:9 处 ASCII "preload" 命中**全部无关**,逐条性质:

| 偏移(file/rva) | 内容性质 |
|---|---|
| 0xE0731B8 | `commands.tickingarea-preload.count`(命令本地化串) |
| 0xE08A562 / 0xE08A592 / 0xE08A5B7 | `commands.tickingarea-preload.success` 等 |
| 0xE101920 / 0xE1019F2 | `commands.tickingarea-preload...failure` |
| 0xE136A75 / 0xE136ABC / 0xE136AD0 | `TickingAreaModePreload`、`Waiting For Preload`、`force_texture_reload` |
| 0x10829C36 / 0x10829D16 / 0x1089CC08 … | RTTI: `ZipPackAccessStrategy::_preloadSubFolders`、`PreloadCache@Resources@Bedrock`、`addPreloadedPath`、`WorldPreloading` —— 资源包/贴图预载缓存 |

同时:全文件搜索 `preload\%s.dll` 形式格式串 **0 命中**;`LdrLoadDll` / `LoadPackagedLibrary` 原始串 **0 命中**。

### E. gdk_patch.dll 性质
```
16,384 字节;machine=x64;sections=3:UPX0(vsize 0x8000/raw 0/熵 0.00)、UPX1(熵 7.76)、.rsrc
无导出目录;导入 CRT(api-ms-win-crt-*)+KERNEL32+USER32+MSVCP140+VCRUNTIME140
有 dir[3] exception、dir[10] loadcfg
```
即:**UPX 加壳、无导出、非微软签名**的第三方载荷,与 BedrockBoot 的 preload 通道一致(启动时被 LoadLibrary,靠 DllMain 副作用工作)。它不是 Mojang 组件。

## 未确认部分(诚实边界)

1. **预加载器是否按 `*.dll` 通配枚举**(而非硬编码名单):未反汇编验证。`FileDescription="DLL Preloader"` + `FindFirstFileW/FindNextFileW` + `\preload` 字符串构成强推断,但**没有直接看到通配串**。
   - 补齐手段:反汇编 `PreloadCpp.dll` 中 `FindFirstFileW` 调用点(其 `.text` rva=0x1000 vsize=0x1C1B1,规模很小,IDA 分钟级),或运行时用 Process Monitor 观察对 `preload\*` 的文件枚举。
2. **加载时机与顺序**:推测在 DllMain 阶段(早于游戏初始化),未验证;是否递归子目录、是否按字母序、是否等待加载完成均未验证。
3. **是否校验签名/名单**:未验证。

## 对 Fiber 设计的影响

- **免补丁通道真实存在**:把 `FiberRuntime.dll` 放进 `preload\`,在 **BedrockBoot 启动流程下即自动加载**,零 PE 修改、零注入代码。
- **但该通道属于启动器,不属游戏**:若用官方 Xbox 应用启动、或启动器更新/移除该预加载器,则静默不加载(失败模式:无 `fiber.log` 产生)。Fiber 无法控制其存在与版本。
- **运行时路径推导需自主**:preload 通道下没有 Launcher 传环境变量的可能(旧 D14 环境变量通讯在此通道失效),必须由 Runtime 从自身模块路径推导游戏根 —— 这与 D26(exe 同目录相对寻路)一致,已验证可行。
- **加载极早 → hook 必须延后**:预加载阶段游戏尚未初始化,事件分发点(MinecraftGame::update 等)尚未就绪;Runtime 必须自行等待/轮询到游戏初始化后再装 hook。
- **旁证**:`config\BedrockBoot2\` 下另有 `mods\`(空)与 `mods.json`(2 字节 = `[]`),说明 BedrockBoot 自身有一套 mod 清单机制(与 preload 通道并列),未来若要"在启动器 UI 里管理 Fiber mod"需另行逆向。