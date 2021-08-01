#include <stddef.h>
#include <stdint.h>

#include "common.h"

int verify(const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t i;
    uint8_t r = 0;

    for (i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }

    return (-(uint64_t)r) >> 63;
}

void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
    size_t i;

    b = -b;
    for (i = 0; i < len; i++) {
        r[i] ^= b & (r[i] ^ x[i]);
    }
}

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

