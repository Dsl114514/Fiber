// Fiber Runtime —— 版本范围校验(包装 vendored semver)
//
// D19  依赖版本范围 = 完整 semver range 规范(含 ||、预发布规则)
// D29  vendor 单头库:third_party/semver/include/semver.hpp(Neargye/semver,MIT)

#pragma once

#include <string>

namespace fiber {

// version 是否满足 range;解析失败时返回 false 并(可选)填充 error
bool version_satisfies(const std::string& version, const std::string& range,
                       std::string* error);

// 版本号本身是否合法
bool is_valid_version(const std::string& version);

} // namespace fiber