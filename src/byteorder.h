#pragma once
#include <stdint.h>

/**
 * @brief Writes a 64-bit value into 8 bytes in big-endian (network) order.
 *
 *
 * @param out buffer of at least 8 bytes to receive the encoding
 * @param v   value to encode
 */
static inline void put_u64_be(unsigned char out[8], uint64_t v) {
    for (int i = 0; i < 8; i++)
        out[7 - i] = (unsigned char)(v >> (8 * i));
}

/**
 * @brief Reads a big-endian 64-bit value produced by put_u64_be().
 *
 * @param in buffer of at least 8 bytes holding the encoding
 * @return the decoded value
 */
static inline uint64_t get_u64_be(const unsigned char in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | in[i];
    return v;
}