#ifndef KOP_GROUP_H
#define KOP_GROUP_H

#include <stdint.h>

#include "params.h"
#include "kem.h"
#include "pq.h"

/// Hash ID, used for domain separation (random oracle cloning)
typedef struct {
    uint8_t sid[KOP_SID_BYTES]; // session id
    uint8_t role;               // oblivious encoding role (0 or 1)
    uint8_t ot;                 // oblivious transfer index (0 to sigma)
    uint8_t ro;                 // kem index (0 to N)
} hid_t;

void kop_add_pk(
    kop_kem_pk_s *r,
    const kop_kem_pk_s *a,
    const kop_kem_pk_s *b);

void kop_sub_pk(
    kop_kem_pk_s *r,
    const kop_kem_pk_s *a,
    const kop_kem_pk_s *b);

void kop_random_pk(
    kop_kem_pk_s *r,
    const uint8_t rho[KYBER_SYMBYTES]);

void kop_hash_pks(
    kop_kem_pk_s *r,
    const uint8_t * const pks_serialized[KOP_OT_M - 1],
    const uint8_t rho[KYBER_SYMBYTES],
    hid_t hid);

#endif
