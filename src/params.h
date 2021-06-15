#ifndef PARAMS_H
#define PARAMS_H

#include <oqs/kem.h>
#include <decaf/point_448.h>

#ifndef KOP_PQ_ALG
#define KOP_PQ_ALG kyber_768
#endif

#ifndef KOP_SID_BYTES
#define KOP_SID_BYTES 8
#endif

#ifndef KOP_INPUT_BYTES
#define KOP_INPUT_BYTES 10
#endif

#ifndef KOP_OT_LOGN
#define KOP_OT_LOGN 2
#endif

/* Don't edit below this line */

#define KOP_OQS_XNS(a, b) OQS_KEM_##a##_##b
#define KOP_OQS_NS(a, b) KOP_OQS_XNS(a, b)
#define KOP_PQ_namespace(s) KOP_OQS_NS(KOP_PQ_ALG, s)

#define KOP_PQ_KEYGEN KOP_PQ_namespace(keypair)
#define KOP_PQ_ENCAPS KOP_PQ_namespace(encaps)
#define KOP_PQ_DECAPS KOP_PQ_namespace(decaps)

#define KOP_PQ_PK_BYTES KOP_PQ_namespace(length_public_key)
#define KOP_PQ_SK_BYTES KOP_PQ_namespace(length_secret_key)
#define KOP_PQ_CT_BYTES KOP_PQ_namespace(length_ciphertext)
#define KOP_PQ_SS_BYTES KOP_PQ_namespace(length_shared_secret)

#define KOP_EC_PK_BYTES DECAF_448_SER_BYTES
#define KOP_EC_SK_BYTES DECAF_448_SCALAR_BYTES
#define KOP_EC_CT_BYTES DECAF_448_SER_BYTES
#define KOP_EC_SS_BYTES 32

#define KOP_KEM_PK_BYTES (KOP_EC_PK_BYTES + KOP_PQ_PK_BYTES)
#define KOP_KEM_CT_BYTES (KOP_EC_CT_BYTES + KOP_PQ_CT_BYTES)
#define KOP_KEM_SS_BYTES 32

#define KOP_OT_N (1 << KOP_OT_LOGN)
#define KOP_SIGMA ((KOP_INPUT_BYTES * 8 + KOP_OT_LOGN - 1) / KOP_OT_LOGN)

#define KOP_KYBER_SYMBYTES 32
#define KOP_PET_PRF_BYTES 32

#define KOP_OT_MSG0_BYTES (KOP_OT_N * KOP_KEM_PK_BYTES)
#define KOP_OT_MSG1_BYTES (KOP_OT_N * KOP_KEM_CT_BYTES)

#define KOP_PET_MSG0_BYTES (KOP_SIGMA * KOP_OT_MSG0_BYTES)
#define KOP_PET_MSG1_BYTES (KOP_SIGMA * (KOP_OT_MSG0_BYTES + KOP_OT_MSG1_BYTES))
#define KOP_PET_MSG2_BYTES (KOP_PET_PRF_BYTES + KOP_SIGMA * KOP_OT_MSG1_BYTES)
#define KOP_PET_MSG3_BYTES (KOP_PET_PRF_BYTES)

#endif
