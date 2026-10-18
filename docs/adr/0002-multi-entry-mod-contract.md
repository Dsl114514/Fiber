# Mod 契约采用多入口导出设计

Mod 对外契约从旧 Fiber 的单入口 `Fiber_Init(api, version)` 换为多入口导出:`Fiber_OnLoad` / `Fiber_OnUnload` / `Fiber_GetDescriptor`。动机:生命周期与身份声明各归其位 —— 描述符让 Runtime 不加载 DLL 就能读到 modid/版本/依赖(清单校验失败时无需 LoadLibrary/FreeLibrary 折腾),加载/卸载回调让资源归属清晰。仍是纯 C ABI(extern "C"),保持跨编译器兼容与无导入库链接。

# Considered Options
- 单入口继承(入口不变、函数表重设计):旧 Fiber 验证过稳定,但身份信息必须加载后才能读,生命周期语义混在一个函数里。
- 每事件一个导出函数:免订阅,但导出面随事件类型膨胀,无法表达优先级/动态订阅。

# Consequences
- 旧 sample_mod 及一切旧 Mod 不兼容,需按新契约重写(符合"不继承旧代码"的大方向)。
- 清单(manifest.toml)与描述符导出的关系需要后续明确:身份以哪个为准(倾向:清单为准,描述符用于交叉校验)。
