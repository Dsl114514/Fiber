add_library(fiber_runtime SHARED
    dllmain.cpp
    app.cpp
    logger.cpp
    manifest.cpp
    modloader.cpp
    paths.cpp
    semver_check.cpp
)

target_include_directories(fiber_runtime PRIVATE
    ${CMAKE_SOURCE_DIR}/src/sdk
    ${CMAKE_SOURCE_DIR}/third_party/tomlplusplus/include
    ${CMAKE_SOURCE_DIR}/third_party/semver/include
)

target_compile_definitions(fiber_runtime PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(fiber_runtime PRIVATE version)

set_target_properties(fiber_runtime PROPERTIES
    OUTPUT_NAME "fiber_runtime"
    PREFIX ""
    SUFFIX ".dll"
)