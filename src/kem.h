#ifndef KOP_KEM_H
#define KOP_KEM_H

#include <stdint.h>

#include "ec.h"
#include "pq.h"
#include "common.h"
#include "params.h"

typedef struct {
    kop_ec_sk_s ec;
    uint8_t pq[KOP_PQ_SK_BYTES];
} kop_kem_sk_s;

typedef struct {
    kop_ec_pk_s ec;
    kop_pq_pk_s pq;
} kop_kem_pk_s;

typedef struct {
    uint8_t bytes[KOP_KEM_SS_BYTES];
} kop_kem_ss_s;

void kop_kem_keygen(
    kop_kem_pk_s *pk,
    kop_kem_sk_s *sk);

void kop_kem_encaps(
    uint8_t ct[KOP_KEM_CT_BYTES],
    kop_kem_ss_s *ss,
    const kop_kem_pk_s *pk);

void kop_kem_decaps(
    kop_kem_ss_s *ss,
    const uint8_t ct[KOP_KEM_CT_BYTES],
    const kop_kem_sk_s *sk);

void kop_kem_pk_serialize(
    uint8_t out[KOP_KEM_PK_BYTES],
    const kop_kem_pk_s *pk);

// De-serialize the public key.
//
// PQ deserialization always succeeds (so that `pk->pq` always holds a valid value)
// If EC decoding succeeds:
//   - `pk->ec` holds the deserialized point
//   - return KOP_RESULT_OK
// Else:
//   - `pk->ec` holds an invalid value
//   - return KOP_RESULT_ERROR
kop_result_e kop_kem_pk_deserialize(
    kop_kem_pk_s *pk,
    const uint8_t in[KOP_KEM_PK_BYTES]);

#endif
