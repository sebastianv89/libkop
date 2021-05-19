#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

uint8_t byte_neq(uint8_t a, uint8_t b);
int verify(const uint8_t *a, const uint8_t *b, size_t len);
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);
void cswap(uint8_t *x, uint8_t *y, size_t len, uint8_t b);

#endif
