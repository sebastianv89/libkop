#ifndef GROUP_H
#define GROUP_H

#include <stdint.h>
#include "params.h"

/// Hash ID, used for random oracle cloning
typedef struct {
    uint8_t sid[KOP_SID_BYTES]; // user index
    uint8_t oenc;               // oblivious encoding index (0 or 1)
    uint8_t ot;                 // oblivious transfer index (0 to sigma)
    uint8_t kem;                // kem index (0 to N)
} hid_t;

void add_pk(uint8_t r[KOP_PK_BYTES], const uint8_t a[KOP_PK_BYTES], const uint8_t b[KOP_PK_BYTES]);
void sub_pk(uint8_t r[KOP_PK_BYTES], const uint8_t a[KOP_PK_BYTES], const uint8_t b[KOP_PK_BYTES]);
void random_pk(uint8_t pk[KOP_PK_BYTES]);
void hash_pks(uint8_t pk[KOP_PK_BYTES], const uint8_t * const pks[KOP_OT_N - 1], const hid_t *hid);

#endif
