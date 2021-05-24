#ifndef GROUP_H
#define GROUP_H

#include <stdint.h>
#include "params.h"
#include "kem.h"
#include "types.h"

/// Hash ID, used for domain separation (random oracle cloning)
typedef struct {
    uint8_t sid[KOP_SID_BYTES]; // session id
    uint8_t oenc;               // oblivious encoding index (0 or 1)
    uint8_t ot;                 // oblivious transfer index (0 to sigma)
    uint8_t kem;                // kem index (0 to N)
} hid_t;

void add_pk(
    kop_kem_pk_s *r,
    const kop_kem_pk_s *a,
    const kop_kem_pk_s *b);

void sub_pk(
    kop_kem_pk_s *r,
    const kop_kem_pk_s *a,
    const kop_kem_pk_s *b);

void random_pk(
    kop_kem_pk_s *r);

void hash_pks(
    kop_kem_pk_s *r,
    const uint8_t * const pks_serialized[KOP_OT_N - 1],
    hid_t hid);

#endif
