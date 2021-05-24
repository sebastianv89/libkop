#ifndef KOP_KEM_PQ_H
#define KOP_KEM_PQ_H

#include <stdint.h>

#include "params.h"

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

#endif
