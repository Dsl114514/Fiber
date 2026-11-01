# 第三方依赖(D12:vendor 质量库,源码入库可审计)
#
# 本文件只编译**需要编译的**第三方库;单头库(toml++ / semver)由使用方直接 include。
# 第三方代码以 /W0 编译:我们自己的代码是 /W4 /WX,但不替上游代码背警告债。

# ---- MinHook(hook 引擎,D12)----
add_library(minhook STATIC
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src/buffer.c
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src/hook.c
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src/trampoline.c
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src/hde/hde32.c
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src/hde/hde64.c
)

target_include_directories(minhook PUBLIC
    ${CMAKE_SOURCE_DIR}/third_party/minhook/include
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src
)

set_source_files_properties(
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src/buffer.c
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src/hook.c
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src/trampoline.c
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src/hde/hde32.c
    ${CMAKE_SOURCE_DIR}/third_party/minhook/src/hde/hde64.c
    PROPERTIES COMPILE_OPTIONS "/W0"
)