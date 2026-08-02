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

# --- Winsock linking only for Windows ---
if (WIN32)
    target_link_libraries(tls_handshake_c PRIVATE ws2_32)
    target_link_libraries(test_crypto PRIVATE ws2_32)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Sanitize")
    add_compile_options(-fsanitize=address -g -O1)
    add_link_options(-fsanitize=address)
endif()