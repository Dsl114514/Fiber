add_library(sample_mod SHARED sample_mod.cpp)

target_include_directories(sample_mod PRIVATE ${CMAKE_SOURCE_DIR}/src/sdk)

target_compile_definitions(sample_mod PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

set_target_properties(sample_mod PROPERTIES
    OUTPUT_NAME "sample_mod"
    PREFIX ""
    SUFFIX ".dll"
)

# 一键产出可部署形态:dist\mods\sample_mod\{sample_mod.dll, manifest.toml}
add_custom_command(TARGET sample_mod POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
            ${CMAKE_BINARY_DIR}/dist/mods/sample_mod
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:sample_mod>
            ${CMAKE_BINARY_DIR}/dist/mods/sample_mod/
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/manifest.toml
            ${CMAKE_BINARY_DIR}/dist/mods/sample_mod/
)