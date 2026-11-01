# M1 验收记录(2026-11-01,通过)

## 验收标准(D10)

> M1 = Mod 加载 + 日志输出 modid + 全游戏会话存活 + 退出时 `Fiber_OnUnload` 被调用且无崩溃

## 实测环境

- 游戏:`E:\mcb\bedrock_versions\1.26.3301`,版本 **1.26.33.1**(Runtime 自行探测所得,非人工填写)
- 启动方式:BedrockBoot2 → 直接拉起 `Minecraft.Windows.exe`
- 部署:`preload\fiber_runtime.dll`(392,192 字节)+ `mods\sample_mod\{manifest.toml, sample_mod.dll}`
- 会话时间:2026-11-01 17:01:01 → 17:02:20(约 79 秒)

## 证据

### `fiber.log`(Runtime 自身日志)
```
===== Fiber Runtime 会话开始 2026-11-01 17:01:01 =====
[17:01:01.998 tid=5108] INFO  ================ Fiber Runtime 启动 ================
[17:01:01.998 tid=5108] INFO  运行时 DLL   : E:/mcb/bedrock_versions/1.26.3301/preload/fiber_runtime.dll
[17:01:01.998 tid=5108] INFO  运行时基址   : 0x7FFB5B070000
[17:01:01.998 tid=5108] INFO  宿主 exe     : E:/mcb/bedrock_versions/1.26.3301/Minecraft.Windows.exe
[17:01:01.998 tid=5108] INFO  游戏根目录   : E:/mcb/bedrock_versions/1.26.3301
[17:01:01.998 tid=5108] INFO  mods 目录: E:/mcb/bedrock_versions/1.26.3301/mods
[17:01:01.998 tid=5108] INFO  游戏版本     : 1.26.33.1
[17:01:01.998 tid=5108] INFO  found mod: sample_mod v1.0.0 (Sample Mod)
[17:01:02.164 tid=5108] INFO  loaded mod: modid=sample_mod name=Sample Mod version=1.0.0(dll=E:/mcb/bedrock_versions/1.26.3301/.fiber/cache/sample_mod_7BD0372E7C1E98FA.dll)
[17:01:02.164 tid=5108] INFO  mod 加载结束: 发现 1 个,成功加载 1 个
[17:02:20.765 tid=5108] INFO  游戏主窗口已消失,判定游戏退出 → 主动卸载
[17:02:20.765 tid=5108] INFO  unloaded mod: modid=sample_mod
[17:02:20.765 tid=5108] INFO  全部 Mod 已卸载
[17:02:20.765 tid=5108] INFO  ================ Fiber Runtime 退出 ================
```

### `logs\sample_mod.log`(每 Mod 独立日志,D16)
```
[17:01:02.164 tid=5108] INFO  OnLoad 开始(第 1 次)
[17:01:02.164 tid=5108] INFO  game=1.26.33.1 modid=sample_mod mod_dir=.../mods/sample_mod mods_dir=.../mods
[17:01:02.164 tid=5108] INFO  OnLoad 完成 —— M1 验收:本行日志出现即表示 Mod 已成功加载
[17:02:20.765 tid=5108] INFO  OnUnload 被调用 —— M1 验收:干净卸载
```

### 影子副本
```
.fiber\cache\sample_mod_7BD0372E7C1E98FA.dll   118,272 字节
```
源 DLL(`mods\sample_mod\sample_mod.dll`)在整个会话中未被进程锁定 → 可随时覆盖(热重载 ADR 0004 的基础)。

## 逐项判定

| 验收项 | 判定 | 依据 |
|---|---|---|
| Mod 加载成功 | ✅ | `found mod` + `loaded mod`(含 modid/name/version) |
| Mod 输出自己的 modid | ✅ | `logs\sample_mod.log` 的 M1 验收行 + API 返回的 modid |
| 全游戏会话存活 | ✅ | 79 秒会话,无崩溃,日志连贯无断点 |
| 干净卸载(`Fiber_OnUnload`) | ✅ | `OnUnload 被调用` + `全部 Mod 已卸载` + `Fiber Runtime 退出` |

## 附带验证(本不在 M1 标准内,但一并成立)

1. **影子副本加载**:实际 LoadLibrary 路径为 `.fiber/cache/<modid>_<FNV1a>.dll`
2. **版本探测**:`GetFileVersionInfo` 读出 `1.26.33.1`,与目标版本一致(D30 的游戏更新识别可直接复用)
3. **无环境变量路径推导**:preload 通道下推导出正确游戏根(与 2026-11-01 探针结论一致)
4. **API 表可用**:`GetGameVersion` / `GetModId` / `GetModDir` / `GetModsDir` 四个函数返回值全部正确
5. **单实例保护**:探针 DLL 与 Runtime DLL 同处 `preload\`,未出现重复加载
6. **主窗口监视器**:进程若被强杀则 detach 不触发(探针会话 1 已证),因此增加"曾出现又消失 → 主动卸载"的判定;本次会话正是由它触发干净卸载
7. **依赖解析/清单校验代码路径**:本次只有单个无依赖 Mod,未覆盖缺失依赖/版本不满足/循环依赖分支 → **待补测**(造几个坏清单即可,M2 期间一并做)

## 未覆盖项(诚实边界)

- 多 Mod 与依赖拓扑、版本范围(||、预发布)真实用例
- `.disabled` 标记禁用路径
- 描述符与清单不一致时的拒载路径
- LoadLibrary 失败 / 缺少 `Fiber_OnLoad` 导出等错误路径