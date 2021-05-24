#ifndef KOP_PQ_H
#define KOP_PQ_H

#include <stdint.h>

#include "params.h"

#define KYBER_SYMBYTES 32

void kop_pq_add_pk(
    uint8_t r[KOP_PQ_PK_BYTES],
    const uint8_t a[KOP_PQ_PK_BYTES],
    const uint8_t b[KOP_PQ_PK_BYTES]);

void kop_pq_sub_pk(
    uint8_t r[KOP_PQ_PK_BYTES],
    const uint8_t a[KOP_PQ_PK_BYTES],
    const uint8_t b[KOP_PQ_PK_BYTES]);

void kop_pq_gen_pk(
    uint8_t r[KOP_PQ_PK_BYTES],
    const uint8_t seed[KYBER_SYMBYTES],
    const uint8_t rho[KYBER_SYMBYTES]);

void kop_pq_keygen(
    uint8_t pk[KOP_PQ_PK_BYTES],
    uint8_t sk[KOP_PQ_SK_BYTES]);

void kop_pq_encaps(
    uint8_t ct[KOP_PQ_CT_BYTES],
    uint8_t ss[KOP_PQ_SS_BYTES],
    const uint8_t pk[KOP_PQ_PK_BYTES]);

void kop_pq_decaps(
    uint8_t ss[KOP_PQ_SS_BYTES],
    const uint8_t ct[KOP_PQ_CT_BYTES],
    const uint8_t sk[KOP_PQ_SS_BYTES]);

const uint8_t * kop_pq_pk_rho(
    const uint8_t pk[KOP_PQ_PK_BYTES]);

#endif
