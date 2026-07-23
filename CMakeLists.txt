cmake_minimum_required(VERSION 4.1)
project(tls_handshake_c C)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(tls_handshake_c main.c
        src/crypto.h
        src/crypto.c)
target_include_directories(tls_handshake_c PRIVATE src ${SODIUM_INCLUDE_DIRS})
target_link_libraries(tls_handshake_c PRIVATE ${SODIUM_LIBRARIES})

add_executable(test_generator test/test_generator.c
        test/test_utils.h
        src/crypto.h
        src/crypto.c)
target_include_directories(test_generator PRIVATE src test ${SODIUM_INCLUDE_DIRS})
target_link_libraries(test_generator PRIVATE ${SODIUM_LIBRARIES})