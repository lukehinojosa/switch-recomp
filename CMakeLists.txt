cmake_minimum_required(VERSION 3.25)
project(switch_recomp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Host-side Horizon kernel: handles, ports, sessions and HIPC message copy.
add_library(hkernel
    src/kernel/kernel.cpp
    src/kernel/hipc.cpp)
if(WIN32)
    target_sources(hkernel PRIVATE src/kernel/platform_win32.cpp)
else()
    message(FATAL_ERROR "Only Windows hosts are implemented so far (src/kernel/platform_win32.cpp)")
endif()
target_include_directories(hkernel
    PUBLIC include
    PRIVATE src/kernel)

enable_testing()

add_executable(ipc_test
    tests/ipc_test.cpp
    tests/echo_server.cpp)
target_link_libraries(ipc_test PRIVATE hkernel)
add_test(NAME ipc COMMAND ipc_test)

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
    src/services/probe.cpp)
target_include_directories(native_services PUBLIC src)
target_link_libraries(native_services PUBLIC hkernel)

add_executable(native_test tests/native_test.cpp)
target_link_libraries(native_test PRIVATE native_services)
add_test(NAME native COMMAND native_test)

add_executable(sync_test tests/sync_test.cpp)
target_link_libraries(sync_test PRIVATE hkernel)
add_test(NAME sync COMMAND sync_test)

add_executable(transport_test tests/transport_test.cpp)
target_link_libraries(transport_test PRIVATE hkernel)
add_dependencies(transport_test echo_host)
add_test(NAME transport COMMAND transport_test)

# A module lifted by tools/lift.py, run by module_host. Off unless
# SWITCH_RECOMP_LIFTED names the lift output directory: the generated code
# comes from the user's own firmware and is never part of the default build.
set(SWITCH_RECOMP_LIFTED "" CACHE PATH "Directory written by tools/lift.py")
if(SWITCH_RECOMP_LIFTED)
    file(GLOB lifted_sources CONFIGURE_DEPENDS "${SWITCH_RECOMP_LIFTED}/lifted_*.cpp")
    add_library(lifted_module STATIC ${lifted_sources})
    target_include_directories(lifted_module PUBLIC include "${SWITCH_RECOMP_LIFTED}")
    if(MSVC)
        target_compile_options(lifted_module PRIVATE /W0 /bigobj)
    else()
        target_compile_options(lifted_module PRIVATE -w)
    endif()

    add_executable(module_host
        src/runtime/host.cpp
        src/runtime/guest_space.cpp)
    target_link_libraries(module_host PRIVATE native_services lifted_module)
endif()
