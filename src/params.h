#ifndef PARAMS_H
#define PARAMS_H

#include <oqs/kem.h>
#include <oqs/rand.h>

#define KOP_KEM_ALG kyber_768
#define KOP_SID_BYTES 8
#define KOP_INPUT_BYTES 10

/* Don't edit below this line */

#define KOP_OQS_NS_I(a, b) OQS_KEM_##a##_##b
#define KOP_OQS_NS(a, b) KOP_OQS_NS_I(a, b)
#define KOP_KEM_namespace(s) KOP_OQS_NS(KOP_KEM_ALG, s)

#define KOP_KEM_KEYGEN KOP_KEM_namespace(keypair)
#define KOP_KEM_ENCAPS KOP_KEM_namespace(encaps)
#define KOP_KEM_DECAPS KOP_KEM_namespace(decaps)

#define KOP_PK_BYTES KOP_KEM_namespace(length_public_key)
#define KOP_SK_BYTES KOP_KEM_namespace(length_secret_key)
#define KOP_CT_BYTES KOP_KEM_namespace(length_ciphertext)
#define KOP_SS_BYTES KOP_KEM_namespace(length_shared_secret)

#define randombytes OQS_randombytes

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
