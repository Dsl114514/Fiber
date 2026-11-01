# 主循环 / 事件分发点候选取证报告

> 由主代理在取证子代理失败退出后重建:基于其遗留产物(`docs/research_scripts/`)与本次独立复验
> (`.pdata` 函数边界 / 虚表指针槽 / 函数序言字节)。取证日期:2026-10-18 原始扫描 / 2026-11-01 复验。
> 目标: `E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe`(339,816,272 字节)

## 结论速览

| # | 候选 | 函数体 RVA | `.pdata` 区间 | 大小 | 虚表槽(RVA) | 置信度 |
|---|---|---|---|---|---|---|
| 1 | **MinecraftGame::update(big)** | `0x87AC90` | `[0x87AC90, 0x87E7B8)` | 15,144 | `0xDBDADB0` | **高** |
| 2 | ServerInstance::\_update(big) | `0x1D60D40` | `[0x1D60D40, 0x1D633C4)` | 9,860 | `0xDCC73B8` | 中高 |
| 3 | MinecraftGame::update(#1) | `0x879E10` | `[0x879E10, 0x879F7F)` | 367 | `0xDBDAD98` | 中 |
| 4 | MinecraftGame::update(#2) | `0x87A530` | `[0x87A530, 0x87A622)` | 242 | `0xDBDADA0` | 中 |
| 5 | MinecraftGame::update(#3) | `0x87AB10` | `[0x87AB10, 0x87AC48)` | 312 | `0xDBDADA8` | 中 |
| 6 | ServerInstance::\_update(225B) | `0x1D5E7D0` | `[0x1D5E7D0, 0x1D5E8B1)` | 225 | `0xDCC7380` | 中 |
| 7 | ServerLevel::\_subTick(581B) | `0x1D64ED0` | `[0x1D64ED0, 0x1D65115)` | 581 | `0xDCC8198` | 中 |
| 8 | ServerLevel::\_subTick(403B) | `0x1D77260` | `[0x1D77260, 0x1D773F3)` | 403 | `0xDCC8190` | 中 |
| 9 | ServerLevel::\_subTick(437B) | `0x1D65410` | `[0x1D65410, 0x1D655C5)` | 437 | `0xDCC81A0` | 中 |

**首选推荐:`MinecraftGame::update` 的 15KB 实现(`0x87AC90`)** —— 体积最大(真实工作量)、位于虚表连续槽段、与同族 4 个 update 候选构成一组虚函数;最符合"引擎每帧通过虚表驱动一次"的形态。

## 证据链(按顺序)

### 1. 签名串:是 `__FUNCSIG__`,不是 RTTI
- 串本身确实存在于 `.rdata`,内容为 `void __cdecl MinecraftGame::onTick(void)`(`0xE3C941F`)、`virtual void __cdecl MinecraftGame::update(void)`(`0xE3C9852`)、`waitForPreviousFrame(void)`(`0xE3C99C8`)等(见 `research_scripts/c4_sigrvas.json`)。
- **但装饰名 RTTI 全部不存在**:`.?AVMinecraftGame@@` / `.?AVServerInstance@@` / `.?AVServerLevel@@` / `.?AVMinecraft@@` / `.?AVBackgroundWorker@@` 在 339MB 中 **0 命中**。
- 推论:该 exe 为 **RTTI 剥离/关闭**构建;这些串是游戏代码自带的 `__FUNCSIG__` 剖析/日志串。
- **对 Fiber 的意义**:不能靠 RTTI 类名做类型识别或虚表定位,但**这些串是极佳的静态锚点**(精确标注函数签名 + 位置固定),可用于特征码定位(D3)。

### 2. 反向引用(子代理产物 `c10_pairs.json`)
引用上述串的代码位置,例如 `virtual void __cdecl MinecraftGame::update(void)` ← `0x879E10`/`0x87A530`/`0x87AB10`/`0x87AC90`;`ServerInstance::_update` ← `0x31D990`/`0x1D5E6B0`/`0x1D5E740`/`0x1D5E7D0`/`0x1D771B0`/`0x1D60D40`;`ServerLevel::_subTick` ← `0x1643EA0`/`0x1643F80`/`0x16459E0`/`0x1D77260`/`0x1D64ED0`/`0x1D65410`。

### 3. 函数边界(`.pdata`,本次复验)
`.pdata`(dir[3] rva=`0x10F5C000`, size=`0x9C95DC`)= **855,165 条有效 RUNTIME_FUNCTION**,精确给出每个需要 unwind 的函数区间 → 上表区间均由此而来。
- 反例:`0x1643EA0` / `0x1643F80` / `0x16459E0` 是**叶子小函数**(形如 `48 8B 81 D8 03 00 00 48 8B 40 20 C3` = `mov rax,[rcx+3D8h]; mov rax,[rax+20h]; ret`),无 unwind 信息故不在 `.pdata` 中 —— 它们是内联访问器,不是主循环候选。
- 另一反例:`0xDA8A3F0` 是导入跳转桩(`FF 25 42 15 AA 00` = `jmp qword ptr [rip+0xAA1542]`),非函数。

### 4. 调用关系:全部为间接调用
对 `.text` 全段(rva `0x1000`, size `0xDA89C00`)扫描 `E8 rel32` 直接调用 → **上表所有候选的直接调用者 = 0**。
结合虚表槽存在,判定:**这些函数全部通过函数指针/虚表被间接调用**(与"引擎通过虚表驱动 update/tick"的形态一致)。

### 5. 虚表槽(本次复验,关键修正)
- `.rdata`/`.data` 中的 8 字节函数指针槽**存的是绝对 VA(`ImageBase 0x140000000` + RVA),不是裸 RVA** —— 按裸 RVA 匹配仅 93,174 命中,按 VA 匹配 406,936 命中(差 4 倍)。**后续任何虚表扫描必须按 VA 匹配**。
- MinecraftGame 的 4 个 update 候选位于**连续槽**:`0xDBDAD98 / 0xDBDADA0 / 0xDBDADA8 / 0xDBDADB0`(所在连续指针段 `0xDBDAD90..0xDBDADB0`,5 槽)。
- ServerInstance/\_update 族:`0xDCC7370 / 0xDCC7378 / 0xDCC7380` 连续段(所在段 `0xDCC7268..0xDCC7380`,36 槽)。
- ServerLevel::\_subTick 族:`0xDCC8190 / 0xDCC8198 / 0xDCC81A0`(所在段 `0xDCC8190..0xDCC8A30`,**277 槽**)。
- 虚表**头部的 RTTI COL 指针未在紧邻位置出现**(前一词为 `0x0`/`0xF`/`0x11`/`0x3000000039` 等非指针值),与第 1 条的"RTTI 剥离"一致。

### 6. 函数序言(= 未来特征码锚点,前 16 字节)
```
0x87AC90  MinecraftGame::update(big)   55 41 57 41 56 41 55 41 54 56 57 53 48 81 EC 78 03
0x879E10  MinecraftGame::update#1      55 56 57 53 48 81 EC A8 02 00 00 48 8D AC 24 80 00
0x87A530  MinecraftGame::update#2      55 56 57 48 81 EC 60 03 00 00 48 8D AC 24 80 00
0x87AB10  MinecraftGame::update#3      55 56 57 48 81 EC 20 02 00 00 48 8D AC 24 80 00
0x1D60D40 ServerInstance::_update(big) 55 41 57 41 56 41 55 41 54 56 57 53 48 81 EC 98 01
0x1D5E7D0 ServerInstance::_update225   56 57 55 53 48 81 EC A8 00 00 00 84 D2 0F 84 C1 00
0x1D77260 ServerLevel::_subTick403     55 56 57 53 48 83 EC 38 48 8D 6C 24 30 48 C7 45 00 FE
0x1D64ED0 ServerLevel::_subTick581     55 56 57 48 81 EC 90 00 00 00 48 8D AC 24 80 00 00 00
0x1D65410 ServerLevel::_subTick437     55 41 56 56 57 53 48 81 EC 80 02 00 00 48 8D AC 24 80 00
```
> 注:序言本身不够唯一(同族函数共享骨架),**真正稳健的锚点 = 序言 + 函数体内引用自身 `__FUNCSIG__` 串的相对位移**(即 `lea reg,[rip+disp]` 指向 §1 的串地址)。实现特征码时按这个组合构造。

## 未验证部分(诚实边界)

1. **调用频率未验证** —— 上表置信度依据的是"体积 + 虚表 + 命名",**没有实测**它是否真的每帧/每 tick 调用一次。
2. **线程归属未验证** —— 是否在游戏主线程被调用(D8 的硬要求)未测。
3. **`onTick` / `startFrame` / `endFrame` 的引用点缺失** —— 子代理只产出了 update / \_update / \_subTick 三族的引用;这三个串的 RVA 已知(`0xE3C941F` / `0xE3C9970` / `0xE3C99E3`)但反向引用尚未取得。
4. 4 个 MinecraftGame::update 候选之间的关系(重载?拆分块?不同子类的覆盖?)未确定;137 个未展开的候选同族函数也未逐一分析。

## 建议的下一步(按性价比排序)

1. **运行时探针实测(强烈推荐,一次定音)**:借 D36 已定的 preload 通道,写一个**只做计数**的探针 DLL(MinHook 挂上表 9 个候选,记录每个函数 10 秒内的调用次数、平均间隔、调用线程 ID),落日志。**这比 IDA 静态读代码更快也更有决定性** —— 一次游戏会话即可判定"谁每帧一次、谁在主线程"。判定通过后再把事件分发点定下来写进 CONTEXT。
2. IDA 定点反编译(若探针结果存疑):候选地址清单见上表;重点看 `0x87AC90` 的函数体是否含帧步进/时间参数、以及谁调用它。
3. 补齐 `onTick`/`startFrame`/`endFrame` 的反向引用(用 §1 串地址做 `lea` 位移扫描)。

## 附带确认的二进制事实(供其他里程碑复用)

- 虚表/函数指针表在 `.rdata`,存绝对 VA;**扫描必须用 `ImageBase + RVA`**(`ImageBase = 0x140000000`)。
- `.pdata` 覆盖 855,165 个函数,可用于任何函数的边界界定与"某地址是不是函数体"的判定。
- 无 unwind 信息的小函数不在 `.pdata` 中,需另判(序言/ret 桩特征)。
- 该 exe **无装饰名 RTTI**,任何依赖 `.?AV...` 的方案(如按类名找虚表)在此版本不可行。