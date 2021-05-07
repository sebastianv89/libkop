#ifndef PARAMS_H
#define PARAMS_H

#include <oqs/kem.h>

#define PK_BYTES OQS_KEM_kyber_768_length_public_key
#define SK_BYTES OQS_KEM_kyber_768_length_secret_key
#define CT_BYTES OQS_KEM_kyber_768_length_ciphertext
#define SS_BYTES OQS_KEM_kyber_768_length_shared_secret

// TODO is this going to be sufficient?
#define SID_BYTES 2
#define HID_BYTES (SID_BYTES + 1)

#define SEED_BYTES 32
#define SYMMETRIC_BYTES 32

#define OTKEM_LOG_N 2
#define OTKEM_N (1 << OTKEM_LOG_N)

// Required: PET_INPUT_BITS is a multiple of 8 and a multiple of OTKEM_LOG_N
#define PET_INPUT_BITS 80
#define PET_INPUT_BYTES (PET_INPUT_BITS / 8)
#define PET_SIGMA (PET_INPUT_BITS / OTKEM_LOG_N)

// NOTE: these are in bytes
#define PET_KAPPA 32
#define PET_LAMBDA 32 // misnomer (the statistical security is determined by PET_INPUT_BYTES)

#endif
