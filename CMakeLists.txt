cmake_minimum_required(VERSION 3.25)
project(switch_recomp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()
if(MINGW)
    # Every program and the client DLL carry the C++ runtime inside, so that
    # none depends on which libstdc++ DLL is found first on PATH.
    add_link_options(-static-libgcc -static-libstdc++ -static)
endif()

# Host-side Horizon kernel: handles, ports, sessions and HIPC message copy.
add_library(hkernel
    src/kernel/kernel.cpp
    src/kernel/hipc.cpp)
if(WIN32)
    target_sources(hkernel PRIVATE src/kernel/platform_win32.cpp)
else()
    target_sources(hkernel PRIVATE src/kernel/platform_posix.cpp)
    find_package(Threads REQUIRED)
    target_link_libraries(hkernel PUBLIC Threads::Threads)
endif()
target_include_directories(hkernel
    PUBLIC include
    PRIVATE src/kernel)

# Tests are registered only when this is the top-level project, not when a
# title's runtime adds it as a subdirectory to build module_client.
enable_testing()
function(switch_recomp_test name target)
    if(PROJECT_IS_TOP_LEVEL)
        add_test(NAME ${name} COMMAND ${target})
    endif()
endfunction()

add_executable(ipc_test
    tests/ipc_test.cpp
    tests/echo_server.cpp)
target_link_libraries(ipc_test PRIVATE hkernel)
switch_recomp_test(ipc ipc_test)

# The echo server in its own host process, driven over a pipe link.
add_executable(echo_host
    tests/echo_host.cpp
    tests/echo_server.cpp)
target_link_libraries(echo_host PRIVATE hkernel)

# Native services for module hosts: sm, the CMIF host and stubs. No firmware.
add_library(native_services
    src/services/sm.cpp
    src/services/native.cpp
    src/services/stubs.cpp
    src/services/application.cpp
    src/services/nvdrv.cpp
    src/services/vi.cpp
    src/services/content.cpp
    src/services/probe.cpp)
target_include_directories(native_services PUBLIC src)
target_link_libraries(native_services PUBLIC hkernel)

# The title-side client of a module host: starts it as a linked child process
# and sends CMIF requests to the ports it registers.
add_library(module_client src/client/module_link.cpp)
target_include_directories(module_client PUBLIC src)
target_link_libraries(module_client PUBLIC hkernel)

# The same as a DLL with a C interface (include/hk/module_client.h), for
# titles in C or built with another toolchain.
add_library(hk_module_client SHARED src/client/module_client_c.cpp)
target_compile_definitions(hk_module_client PRIVATE HK_MODULE_CLIENT_BUILD)
target_include_directories(hk_module_client PUBLIC include)
target_link_libraries(hk_module_client PRIVATE module_client)
# The static libraries it links go into a shared object, which ELF platforms
# require to be position-independent.
set_target_properties(hkernel module_client PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(cmif_host tests/cmif_host.cpp)
target_link_libraries(cmif_host PRIVATE native_services)

add_executable(client_test tests/client_test.cpp tests/linked_child.cpp)
target_link_libraries(client_test PRIVATE module_client)
add_dependencies(client_test cmif_host)
switch_recomp_test(client client_test)

add_executable(client_c_test tests/client_c_test.c)
target_link_libraries(client_c_test PRIVATE hk_module_client)
add_dependencies(client_c_test cmif_host)
switch_recomp_test(client_c client_c_test)

add_executable(native_test tests/native_test.cpp)
target_link_libraries(native_test PRIVATE native_services)
switch_recomp_test(native native_test)

add_executable(sync_test tests/sync_test.cpp)
target_link_libraries(sync_test PRIVATE hkernel)
switch_recomp_test(sync sync_test)

add_executable(transport_test tests/transport_test.cpp tests/linked_child.cpp)
target_link_libraries(transport_test PRIVATE hkernel)
add_dependencies(transport_test echo_host)
switch_recomp_test(transport transport_test)

add_executable(game_abi_test tests/game_abi_test.c tests/game_abi_check.cpp)
target_include_directories(game_abi_test PRIVATE include)
switch_recomp_test(game_abi game_abi_test)

# Round-trip cost of a request in one kernel and across a link (not a test).
add_executable(roundtrip_bench tests/roundtrip_bench.cpp tests/echo_server.cpp tests/linked_child.cpp)
target_link_libraries(roundtrip_bench PRIVATE module_client)
add_dependencies(roundtrip_bench echo_host)

# A module lifted by tools/lift.py, run by module_host. Off unless
# SWITCH_RECOMP_LIFTED names the lift output directory: the generated code
# comes from the user's own firmware and is never part of the default build.
set(SWITCH_RECOMP_LIFTED "" CACHE PATH "Directory written by tools/lift.py")
if(SWITCH_RECOMP_LIFTED AND NOT WIN32)
    # module_host's guest address space (src/runtime/guest_space.cpp) is
    # Windows only so far.
    message(FATAL_ERROR "module_host runs on Windows hosts only so far")
endif()
if(SWITCH_RECOMP_LIFTED)
    file(GLOB lifted_sources CONFIGURE_DEPENDS "${SWITCH_RECOMP_LIFTED}/lifted_*.cpp")
    add_library(lifted_module STATIC ${lifted_sources})
    target_include_directories(lifted_module PUBLIC include "${SWITCH_RECOMP_LIFTED}")
    if(MSVC)
        target_compile_options(lifted_module PRIVATE /W0 /bigobj /MP)
    else()
        target_compile_options(lifted_module PRIVATE -w)
    endif()

    add_executable(module_host
        src/runtime/host.cpp
        src/runtime/guest_space.cpp)
    target_link_libraries(module_host PRIVATE native_services lifted_module)

    # Compares the lifted pctl with mk8-recomp's verified service, without
    # the game (see the file for its arguments).
    add_executable(pctl_shadow tests/pctl_shadow.cpp)
    target_link_libraries(pctl_shadow PRIVATE module_client)
endif()
