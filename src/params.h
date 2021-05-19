#ifndef PARAMS_H
#define PARAMS_H

#include <oqs/kem.h>
#include <oqs/rand.h>

#ifndef KOP_KEM_ALG
#define KOP_KEM_ALG kyber_768
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

#define KOP_OT_N (1 << KOP_OT_LOGN)
#if KOP_OT_LOGN > 8
#error large N not (yet?) supported
#endif
typedef uint8_t kop_pet_index_t;
#define KOP_SIGMA ((KOP_INPUT_BYTES * 8 + KOP_OT_LOGN - 1) / KOP_OT_LOGN)

#define KOP_PRF_BYTES 32

#define KOP_OT_MSG0_BYTES (KOP_OT_N * KOP_PK_BYTES)
#define KOP_OT_MSG1_BYTES (KOP_OT_N * KOP_CT_BYTES)

#define KOP_PET_MSG0_BYTES (KOP_SIGMA * KOP_OT_MSG0_BYTES)
#define KOP_PET_MSG1_BYTES (KOP_SIGMA * (KOP_OT_MSG0_BYTES + KOP_OT_MSG1_BYTES))
#define KOP_PET_MSG2_BYTES (KOP_PRF_BYTES + KOP_SIGMA * KOP_OT_MSG1_BYTES)
#define KOP_PET_MSG3_BYTES (KOP_PRF_BYTES)

#endif
