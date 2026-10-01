cmake_minimum_required(VERSION 3.20)
project(EpsHax LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Lua (auto-download) ──────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
    lua
    URL https://www.lua.org/ftp/lua-5.4.7.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP true
)
FetchContent_GetProperties(lua)
if(NOT lua_POPULATED)
    FetchContent_Populate(lua)
    add_library(lua STATIC
        ${lua_SOURCE_DIR}/src/lapi.c
        ${lua_SOURCE_DIR}/src/lauxlib.c
        ${lua_SOURCE_DIR}/src/lbaselib.c
        ${lua_SOURCE_DIR}/src/lcode.c
        ${lua_SOURCE_DIR}/src/ldblib.c
        ${lua_SOURCE_DIR}/src/ldebug.c
        ${lua_SOURCE_DIR}/src/ldo.c
        ${lua_SOURCE_DIR}/src/ldump.c
        ${lua_SOURCE_DIR}/src/lfunc.c
        ${lua_SOURCE_DIR}/src/lgc.c
        ${lua_SOURCE_DIR}/src/linit.c
        ${lua_SOURCE_DIR}/src/liolib.c
        ${lua_SOURCE_DIR}/src/llex.c
        ${lua_SOURCE_DIR}/src/lmathlib.c
        ${lua_SOURCE_DIR}/src/lmem.c
        ${lua_SOURCE_DIR}/src/lcorolib.c
        ${lua_SOURCE_DIR}/src/lctype.c
        ${lua_SOURCE_DIR}/src/loadlib.c
        ${lua_SOURCE_DIR}/src/lobject.c
        ${lua_SOURCE_DIR}/src/lopcodes.c
        ${lua_SOURCE_DIR}/src/loslib.c
        ${lua_SOURCE_DIR}/src/lparser.c
        ${lua_SOURCE_DIR}/src/lstate.c
        ${lua_SOURCE_DIR}/src/lstring.c
        ${lua_SOURCE_DIR}/src/lstrlib.c
        ${lua_SOURCE_DIR}/src/ltable.c
        ${lua_SOURCE_DIR}/src/ltablib.c
        ${lua_SOURCE_DIR}/src/ltm.c
        ${lua_SOURCE_DIR}/src/lundump.c
        ${lua_SOURCE_DIR}/src/lutf8lib.c
        ${lua_SOURCE_DIR}/src/lvm.c
        ${lua_SOURCE_DIR}/src/lzio.c
    )
    target_include_directories(lua PUBLIC ${lua_SOURCE_DIR}/src)
endif()

# ── EpsHook (in-tree, see EpsHookV2 repo) ─────────────────────────────

# ── ImGui (Win32 + OpenGL3 backend) ─────────────────────────────────
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/libs/imgui)
if(NOT EXISTS ${IMGUI_DIR}/imgui.h)
    message(FATAL_ERROR
        "ImGui not found!\n"
        "Run:\n"
        "  git clone https://github.com/ocornut/imgui.git libs/imgui")
endif()

add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(imgui PUBLIC
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

# ── DLL ───────────────────────────────────────────────────────────────
add_library(EpsHax SHARED
    src/dllmain.cpp
    src/lua_api.cpp
    src/lua_bothax.cpp
    src/itemdb.cpp
    src/hook.cpp
    src/scanner.cpp
    src/native_hook.cpp
    src/lua_state_finder.cpp
    src/epshook.cpp
    src/discord_rpc.cpp
)
target_include_directories(EpsHax PRIVATE src)
target_link_libraries(EpsHax PRIVATE imgui lua opengl32 ws2_32 winhttp)
target_compile_definitions(EpsHax PRIVATE EPSHAX_EXPORTS)
# CreativeGrowtopia.exe holds build\Debug\EpsHax.dll open (loaded) and
# Growtopia holds EpsHax3 — link side-by-side; inject_run.py picks newest.
set_target_properties(EpsHax PROPERTIES OUTPUT_NAME "EpsHax6")

# ── bothax API host test (no game — stubs in test/stubs.cpp) ────────────
add_executable(ApiTest
    test/api_test.cpp
    test/stubs.cpp
    src/lua_api.cpp
    src/lua_bothax.cpp
    src/itemdb.cpp
)
target_include_directories(ApiTest PRIVATE src test)
target_link_libraries(ApiTest PRIVATE lua winhttp user32 shell32 ws2_32)

# ── Discord rich presence smoke test ───────────────────────────────────
add_executable(DiscordRpcTest test/rpc_test.cpp src/discord_rpc.cpp)
target_include_directories(DiscordRpcTest PRIVATE src)

# ── Loader (injects EpsHax.dll into Growtopia) ────────────────────────
add_executable(EpsHaxLoader src/loader.cpp)
target_link_libraries(EpsHaxLoader PRIVATE user32 advapi32 shell32 psapi)
target_link_options(EpsHaxLoader PRIVATE "/MANIFESTUAC:level='requireAdministrator'")
