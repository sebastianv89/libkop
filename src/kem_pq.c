#include <stddef.h>
#include <stdint.h>

#include <oqs/oqs.h>

#include "kem_pq.h"
#include "common.h"
#include "params.h"

void kop_pq_keygen(
    uint8_t pk[KOP_PQ_PK_BYTES],
    uint8_t sk[KOP_PQ_SK_BYTES])
{
    OQS_UNWRAP(KOP_PQ_KEYGEN(pk, sk));
}

void kop_pq_encaps(
    uint8_t ct[KOP_PQ_CT_BYTES],
    uint8_t ss[KOP_PQ_SS_BYTES],
    const uint8_t pk[KOP_PQ_PK_BYTES])
{
    OQS_UNWRAP(KOP_PQ_ENCAPS(ct, ss, pk));
}

void kop_pq_decaps(
    uint8_t ss[KOP_PQ_SS_BYTES],
    const uint8_t ct[KOP_PQ_CT_BYTES],
    const uint8_t sk[KOP_PQ_SS_BYTES])
{
    OQS_UNWRAP(KOP_PQ_DECAPS(ss, ct, sk));
}

