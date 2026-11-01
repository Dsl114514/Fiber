add_library(fiber_probe SHARED probe.cpp)

target_compile_definitions(fiber_probe PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(fiber_probe PRIVATE psapi)

set_target_properties(fiber_probe PROPERTIES
    OUTPUT_NAME "fiber_probe"
    PREFIX ""
    SUFFIX ".dll"
)