add_library(fiber_hookprobe SHARED hookprobe.cpp)

target_include_directories(fiber_hookprobe PRIVATE ${CMAKE_SOURCE_DIR}/src/sdk)

target_compile_definitions(fiber_hookprobe PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(fiber_hookprobe PRIVATE minhook)

set_target_properties(fiber_hookprobe PROPERTIES
    OUTPUT_NAME "fiber_hookprobe"
    PREFIX ""
    SUFFIX ".dll"
)