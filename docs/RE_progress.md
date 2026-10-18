# M2 逆向分析进度 - 聊天 Hook 点

## ✅ 已确认: TextPacketPayload 反序列化函数

**函数地址: RVA 0x32495B9 - 0x324ABD9** (大小 0x1620)

- 引用 `TextPacketPayload` 字符串 (RVA 0xE134B84) 通过 LEA at RVA 0x3249CBE
- 函数含 76 个 CALL + 48 个 LEA 引用
- 包含 `operator new` 分配 + 字符串常量
- **这是聊天包处理函数, 拦截它可捕获所有聊天消息**

验证方法:
- `.text` 节扫描 LEA rip-relative (`48 8D 05`) 定位到 0x3249CBE
- 计算 LEA 目标 = RVA 0xE134B84 = `TextPacketPayload` 字符串
- 函数边界: 反向扫描 RET → 0x32495B9 (start), 正向扫描 RET → 0x324ABD9 (end)

## 关键符号定位 (文件偏移 → RVA)

| 符号 | 文件偏移 | RVA | 用途 |
|------|---------|-----|------|
| ChatScreenController | 0x108DF707 | 0x108E0707 | 聊天 UI |
| Command::execute vtable | 0xE06CE81 | 0xE06DE81 | 命令执行 |
| TextPacketPayload | 0xE133B84 | 0xE134B84 | 聊天包 |
| TextPacketPayload 处理函数 | - | **0x32495B9** | **聊天 hook 点** |
| MinecraftPacketIds | - | 0xE09DA62 | 包 ID 表 |
| ServerNetworkHandler | 0xE07E29A | 0xE07E0B6 | 网络处理器 |
| FilterTextPacket | 0xE07FBB2 | 0xE07F9CE | 文本过滤 |

## Hook 策略

### 推荐方案: Hook TextPacketPayload 处理函数 (RVA 0x32495B9)
- 优点: 覆盖所有聊天 (命令 + 普通消息 + 系统消息)
- 实现: 14-byte JMP trampoline 钩住函数入口
- 风险: 函数带 5 参数 (this, payload ref, network, etc.), 需要理解调用约定

### 备选方案: Command::execute vtable hook
- 只覆盖命令, 不覆盖普通聊天
- 需要 VTable hook, 复杂度更高

## 待完成
- [x] 定位 TextPacketPayload 处理函数
- [ ] 理解函数签名 (参数/返回值)
- [ ] 实现 detour hook
- [ ] 升级 FiberApi v2 添加 chat hook
- [ ] 编写 chat hook 示例 Mod