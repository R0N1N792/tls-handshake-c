cmake_minimum_required(VERSION 3.14)
project(tls_handshake_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- libsodium (cross-platform, through FetchContent) ---
include(FetchContent)
FetchContent_Declare(Sodium
        GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
        GIT_TAG e5b985ad0dd235d8c4307ea3a385b45e76c74c6a # HEAD, april 2025
)
set(SODIUM_DISABLE_TESTS ON)
FetchContent_MakeAvailable(Sodium)

# --- shared crypto library ---
add_library(crypto_lib STATIC
        src/crypto.h
        src/crypto.c)
target_include_directories(crypto_lib PUBLIC src)
target_link_libraries(crypto_lib PUBLIC sodium)

# --- main executable ---
add_executable(tls_handshake_c main.c)
target_link_libraries(tls_handshake_c PRIVATE crypto_lib)

# --- test executable ---
add_executable(test_crypto test/test_crypto.c
        test/test_utils.h)
target_include_directories(test_crypto PRIVATE test)
target_link_libraries(test_crypto PRIVATE crypto_lib)

# --- shared networking library ---
add_library(net_lib STATIC
        src/net.h
        src/net.c)
target_include_directories(net_lib PUBLIC src)

# --- server executable ---
add_executable(server src/server.c )
target_link_libraries(server PRIVATE net_lib crypto_lib)

# --- client executable ---
add_executable(client src/client.c )
target_link_libraries(client PRIVATE net_lib crypto_lib)

# --- Winsock linking only for Windows ---
if (WIN32)
    target_link_libraries(tls_handshake_c PRIVATE ws2_32)
    target_link_libraries(test_crypto PRIVATE ws2_32)
    target_link_libraries(client PRIVATE ws2_32)
    target_link_libraries(server PRIVATE ws2_32)
endif()

# --- Tests ---
enable_testing()
add_test(NAME test_crypto COMMAND test_crypto)


# --- warning flags ---
add_library(project_warnings INTERFACE)
if (MSVC)
    target_compile_options(project_warnings INTERFACE /W4)
else()
    target_compile_options(project_warnings INTERFACE -Wall -Wextra -Wpedantic)
endif()

target_link_libraries(crypto_lib   PRIVATE project_warnings)
target_link_libraries(net_lib      PRIVATE project_warnings)
target_link_libraries(server       PRIVATE project_warnings)
target_link_libraries(client       PRIVATE project_warnings)
target_link_libraries(test_crypto  PRIVATE project_warnings)