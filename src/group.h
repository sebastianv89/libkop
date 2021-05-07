#ifndef GROUP_H
#define GROUP_H

#include <stdint.h>
#include "params.h"

void add_pk(uint8_t r[PK_BYTES], const uint8_t a[PK_BYTES], const uint8_t b[PK_BYTES]);
void sub_pk(uint8_t r[PK_BYTES], const uint8_t a[PK_BYTES], const uint8_t b[PK_BYTES]);
void random_pk(uint8_t pk[PK_BYTES]);
void hash_pks(uint8_t pk[PK_BYTES], const uint8_t * const pks[OTKEM_N - 1], const uint8_t hid[HID_BYTES]);

#endif
