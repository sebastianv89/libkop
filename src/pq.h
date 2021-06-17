#ifndef KOP_PQ_H
#define KOP_PQ_H

#include <stdint.h>

#include "params.h"

#ifndef KYBER_K
#define KYBER_K 4
#endif

#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_SYMBYTES 32

typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

typedef struct {
    poly vec[KYBER_K];
} polyvec;

typedef struct {
    polyvec t;
    uint8_t rho[KYBER_SYMBYTES];
} kop_pq_pk_s;

void kop_pq_add_pk(
    kop_pq_pk_s *r,
    const kop_pq_pk_s *a,
    const kop_pq_pk_s *b);

void kop_pq_sub_pk(
    kop_pq_pk_s *r,
    const kop_pq_pk_s *a,
    const kop_pq_pk_s *b);

void kop_pq_gen_pk(
    kop_pq_pk_s *r,
    const uint8_t seed[KYBER_SYMBYTES],
    const uint8_t rho[KYBER_SYMBYTES]);

void kop_pq_keygen(
    kop_pq_pk_s *pk,
    uint8_t sk[KOP_PQ_SK_BYTES]);

void kop_pq_encaps(
    uint8_t ct[KOP_PQ_CT_BYTES],
    uint8_t ss[KOP_PQ_SS_BYTES],
    const kop_pq_pk_s *pk);

void kop_pq_decaps(
    uint8_t ss[KOP_PQ_SS_BYTES],
    const uint8_t ct[KOP_PQ_CT_BYTES],
    const uint8_t sk[KOP_PQ_SS_BYTES]);

void kop_pq_pk_serialize(
    uint8_t out[KOP_PQ_PK_BYTES],
    const kop_pq_pk_s *pk);

void kop_pq_pk_deserialize(
    kop_pq_pk_s *pk,
    const uint8_t in[KOP_PQ_PK_BYTES]);

#endif
