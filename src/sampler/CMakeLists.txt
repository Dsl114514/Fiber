add_library(fiber_sampler SHARED sampler.cpp)

target_compile_definitions(fiber_sampler PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(fiber_sampler PRIVATE minhook winmm)

set_target_properties(fiber_sampler PROPERTIES
    OUTPUT_NAME "fiber_sampler"
    PREFIX ""
    SUFFIX ".dll"
)