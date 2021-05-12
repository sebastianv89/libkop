#ifndef PARAMS_H
#define PARAMS_H

#include <oqs/kem.h>

#define KOP_KEM_ALG kyber_768
#define KOP_SID_BYTES 8
#define KOP_INPUT_BYTES 10

/* Don't edit below this line */

#if KOP_KEM_ALG == kyber_768
#define KOP_KEM_namespace(s) OQS_KEM_kyber_768_##s
#else
#error KEM algorithm not supported
#endif

#define KOP_KEM_keygen KOP_KEM_namespace(keygen)
#define KOP_KEM_encaps KOP_KEM_namespace(encaps)
#define KOP_KEM_decaps KOP_KEM_namespace(decaps)

#define KOP_PK_BYTES KOP_KEM_namespace(length_public_key)
#define KOP_SK_BYTES KOP_KEM_namespace(length_secret_key)
#define KOP_CT_BYTES KOP_KEM_namespace(length_ciphertext)
#define KOP_SS_BYTES KOP_KEM_namespace(length_shared_secret)

// TODO: This should be a changeable parameter
#define KOP_OT_LOGN 2

#define KOP_OT_N (1 << KOP_OT_LOGN)
#define KOP_INPUT_WORDS ((KOP_INPUT_BYTES * 8 + KOP_OT_LOGN - 1) / KOP_OT_LOGN)

// TODO: This should be derived from whatever PRF we use
#define KOP_PRF_BYTES 32

#define KOP_OT_MSG0_BYTES (KOP_OT_N * KOP_PK_BYTES)
#define KOP_OT_MSG1_BYTES (KOP_OT_N * KOP_CT_BYTES)

#define KOP_PET_MSG0_BYTES (KOP_INPUT_WORDS * KOP_OT_MSG0_BYTES)
#define KOP_PET_MSG1_BYTES (KOP_INPUT_WORDS * (KOP_OT_MSG0_BYTES + KOP_OT_MSG1_BYTES))
#define KOP_PET_MSG2_BYTES (KOP_PRF_BYTES + KOP_INPUT_WORDS * KOP_OT_MSG1_BYTES)
#define KOP_PET_MSG3_BYTES (KOP_PRF_BYTES)

#endif
