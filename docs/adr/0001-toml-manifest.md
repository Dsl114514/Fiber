# Mod 清单采用 TOML

Mod 清单从旧 Fiber 的 JSON 换为 TOML。用户明确要人工编辑友好的格式;TOML 无 YAML 的缩进陷阱与"挪威问题",注释支持好,是 hand-authored 配置的主流选择。代价是 Runtime 需要内置一个 TOML 解析器(无第三方依赖原则下自研或单头库移植),清单字段结构同时重构:依赖从字符串数组升级为带版本约束的对象。

# Considered Options
- 保留 JSON 并重构字段:工具链零成本,但手写体验差(无注释、逗号陷阱),用户已否决。
- YAML:表达力强,但规范复杂、隐式类型转换坑多,解析器实现成本反而更高。

# Consequences
- Fiber-old 的 json.cpp 不可直接复用,清单层是新代码。
- 存量 sample_mod 等示例清单需按新 schema 重写。
- 自研 TOML 解析器是新增实现风险点,应尽早独立验证。
