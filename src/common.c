#include <stddef.h>
#include <stdint.h>

#include "common.h"

/// Verify that two bytes are equal. Returns 0 if they are equal, 1 otherwise.
uint8_t byte_neq(uint8_t a, uint8_t b) {
    return (-(uint64_t)(a ^ b)) >> 63;
}

/// Verify that the bytearrays are equal. Returns 0 if
/// they are equal, 1 otherwise.
///
/// Runs in constant time.
///
/// @param[in] a    first bytearray (of length >= len)
/// @param[in] b    second bytearray (of length >= len)
/// @param[in] len  number of bytes to compare
/// @return         0 if bytearrays are equal, 1 otherwise
int verify(const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t i;
    uint8_t r = 0;

    for (i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }

    return (-(uint64_t)r) >> 63;
}

/// Move bytearray from x to r if b=1. Otherwise b=0: leave r unmodified.
///
/// Runs in constant time.
///
/// @param[out] r    sink bytearray (of length >= len)
/// @param[in]  x    source bytearray (of length >= len)
/// @param[in]  len  number of bytes to move
/// @param[in]  b    condition bit (must be 0 or 1)
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
    size_t i;

    b = -b;
    for (i = 0; i < len; i++) {
        r[i] ^= b & (r[i] ^ x[i]);
    }
}

/// Swap bytearrays x and y if b=1. Otherwise b=0: leave x and y unmodified.
///
/// Runs in constant time.
///
/// @param[in,out] x    first bytearray (of length >= len)
/// @param[in,out] y    second bytearray (of length >= len)
/// @param[in]     len  number of bytes to move
/// @param[in]     b    condition bit (must be 0 or 1)
void cswap(uint8_t *x, uint8_t *y, size_t len, uint8_t b)
{
    size_t i;
    uint8_t tmp;

    b = -b;
    for (i = 0; i < len; i++) {
        tmp = x[i] ^ y[i];
        tmp &= b;
        x[i] ^= tmp;
        y[i] ^= tmp;
    }
}

