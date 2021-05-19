#include <oqs/kem.h>

#include "kem.h"
#include "types.h"

kop_result kop_kem_keygen(kop_kem_pk_s *pk, kop_kem_sk_s *sk) {
    OQS_STATUS os;

    os = KOP_KEM_KEYGEN(pk->bytes, sk->bytes);
    if (os != OQS_SUCCESS) {
        return KOP_RESULT_ERROR;
    }
    return KOP_RESULT_OK;
}

kop_result kop_kem_encaps(kop_kem_ct_s *ct, kop_kem_ss_s *ss, const kop_kem_pk_s *pk) {
    OQS_STATUS os;

    os = KOP_KEM_ENCAPS(ct->bytes, ss->bytes, pk->bytes);
    if (os != OQS_SUCCESS) {
        return KOP_RESULT_ERROR;
    }
    return KOP_RESULT_OK;
}

kop_result kop_kem_decaps(kop_kem_ss_s *ss, const kop_kem_ct_s *ct, const kop_kem_sk_s *sk) {
    OQS_STATUS os;

    os = KOP_KEM_DECAPS(ss->bytes, ct->bytes, sk->bytes);
    if (os != OQS_SUCCESS) {
        return KOP_RESULT_ERROR;
    }
    return KOP_RESULT_OK;
}
