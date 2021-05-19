#ifndef KOP_KEM_H
#define KOP_KEM_H

#include <stdint.h>

#include "types.h"
#include "params.h"

typedef struct {
    uint8_t bytes[KOP_PK_BYTES];
} kop_kem_pk_s;

typedef struct {
    uint8_t bytes[KOP_SK_BYTES];
} kop_kem_sk_s;

typedef struct {
    uint8_t bytes[KOP_CT_BYTES];
} kop_kem_ct_s;

typedef struct {
    uint8_t bytes[KOP_SS_BYTES];
} kop_kem_ss_s;

kop_result kop_kem_keygen(kop_kem_pk_s *pk, kop_kem_sk_s *sk);
kop_result kop_kem_encaps(kop_kem_ct_s *ct, kop_kem_ss_s *ss, const kop_kem_pk_s *pk);
kop_result kop_kem_decaps(kop_kem_ss_s *ss, const kop_kem_ct_s *ct, const kop_kem_sk_s *sk);

#endif
