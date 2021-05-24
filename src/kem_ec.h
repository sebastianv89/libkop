#ifndef KOP_KEM_EC_H
#define KOP_KEM_EC_H

#include <stdint.h>
#include <decaf/point_448.h>

#include "types.h"
#include "params.h"

typedef struct {
    decaf_448_scalar_t sk;
    uint8_t s[DECAF_448_SER_BYTES];
} kop_ec_sk_s;

typedef struct {
    decaf_448_point_t pk;
} kop_ec_pk_s;

void kop_ec_keygen(
    kop_ec_pk_s *pk,
    kop_ec_sk_s *sk);

void kop_ec_encaps(
    uint8_t ct[KOP_EC_CT_BYTES],
    uint8_t ss[KOP_EC_SS_BYTES],
    const kop_ec_pk_s *pk);

void kop_ec_decaps(
    uint8_t ss[KOP_EC_SS_BYTES],
    const uint8_t ct[KOP_EC_CT_BYTES],
    const kop_ec_sk_s *sk);

void kop_ec_pk_serialize(
    uint8_t out[KOP_EC_PK_BYTES],
    const kop_ec_pk_s *pk);

// De-serialize the public key.
//
// If decoding succeeds:
//   - `pk` holds the deserialized point
//   - return KOP_RESULT_OK
// Else:
//   - `pk` holds an invalid value
//   - return KOP_RESULT_ERROR
kop_result_e kop_ec_pk_deserialize(
    kop_ec_pk_s *pk,
    const uint8_t in[KOP_EC_PK_BYTES]);

#endif
