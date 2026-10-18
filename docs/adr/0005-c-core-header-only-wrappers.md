# 事件总线 API:通用 C 核心 + 头文件强类型封装

事件总线的 Mod 侧 API 分两层:核心是稳定 C ABI —— `fiber_Subscribe(event_id, cb, priority, ctx) → handle`、`fiber_Unsubscribe(handle)`,回调接收 `fiber_Event*`(事件 id / 载荷指针 / 取消标志);各事件类型(聊天、tick、输入)的强类型封装是 header-only C++,编进每个 Mod,不跨 DLL 边界,因此不构成 ABI 承诺。内核加事件零成本(新 event_id + 新头),Mod 作者拿到的却是具名载荷的舒适 API。

# Considered Options
- 纯 C 每事件类型化:每加一类事件都要改 C 头并动版本,SDK 演化僵硬。
- C++ 虚接口/模板直暴:表达力最强,但 MSVC 版本差异即 ABI 差异,与 C ABI 稳定原则冲突。

# Consequences
- fiber_api.h 拆分:核心 C 头(受 N-1 兼容约束)+ 事件封装头(随版本发布,不承诺跨版本 ABI)。
- 事件载荷以版本化 struct 传递,封装层负责把 `fiber_Event*` 安全下转。
