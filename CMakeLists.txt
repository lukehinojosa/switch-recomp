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

add_executable(transport_test tests/transport_test.cpp)
target_link_libraries(transport_test PRIVATE hkernel)
add_dependencies(transport_test echo_host)
add_test(NAME transport COMMAND transport_test)
