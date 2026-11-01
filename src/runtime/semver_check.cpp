#include "semver_check.h"

#include <string_view>
#include <system_error>

#pragma warning(push, 0)
#include <semver.hpp>
#pragma warning(pop)

namespace fiber {

bool is_valid_version(const std::string& version) {
    semver::version v;
    const auto parsed = semver::parse(version, v);
    return parsed.ec == std::errc{};
}

bool version_satisfies(const std::string& version, const std::string& range,
                       std::string* error) {
    semver::version v;
    const auto version_result = semver::parse(version, v);
    if (version_result.ec != std::errc{}) {
        if (error != nullptr) *error = "版本号非法: " + version;
        return false;
    }

    semver::range_set ranges;
    const auto range_result = semver::parse(std::string_view(range), ranges);
    if (range_result.ec != std::errc{}) {
        if (error != nullptr) *error = "版本范围非法: " + range;
        return false;
    }

    return ranges.contains(v);
}

} // namespace fiber