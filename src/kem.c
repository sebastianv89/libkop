#include <stddef.h>
#include <stdint.h>

#include "KeccakHash.h"

#include "kem.h"
#include "ec.h"
#include "pq.h"
#include "common.h"
#include "types.h"
#include "randombytes.h"

// Use the simplest KEM combiner of https://eprint.iacr.org/2018/024 (secure in the ROM):
// hash the concatenation of both keys and both ciphertexts
static void kop_kdf(
    kop_kem_ss_s *ss,
    const uint8_t ec_ss[KOP_EC_SS_BYTES],
    const uint8_t pq_ss[KOP_PQ_SS_BYTES],
    const uint8_t ct[KOP_KEM_CT_BYTES])
{
    const uint8_t prefix[7] = {0x4b, 0x4f, 0x50, 0x2d, 0x4b, 0x44, 0x46}; // "KOP-KDF"
    Keccak_HashInstance hi;

    KECCAK_UNWRAP(Keccak_HashInitialize_SHAKE256(&hi));
    // domain separation
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, prefix, 8 * sizeof(prefix)));
    // hash keys and ciphertext
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, ec_ss, 8 * KOP_EC_SS_BYTES));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, pq_ss, 8 * KOP_PQ_SS_BYTES));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, ct, 8 * KOP_KEM_CT_BYTES));
    // output
    KECCAK_UNWRAP(Keccak_HashFinal(&hi, NULL));
    KECCAK_UNWRAP(Keccak_HashSqueeze(&hi, ss->bytes, 8 * KOP_KEM_SS_BYTES));
}

void kop_kem_keygen(kop_kem_pk_s *pk, kop_kem_sk_s *sk)
{
    kop_ec_keygen(&pk->ec, &sk->ec);
    kop_pq_keygen(pk->pq, sk->pq);
}

void kop_kem_encaps(
    uint8_t ct[KOP_KEM_CT_BYTES],
    kop_kem_ss_s *ss,
    const kop_kem_pk_s *pk)
{
    uint8_t ec_ss[KOP_EC_SS_BYTES], pq_ss[KOP_PQ_SS_BYTES];
    
    kop_ec_encaps(ct, ec_ss, &pk->ec);
    kop_pq_encaps(&ct[KOP_EC_CT_BYTES], pq_ss, pk->pq);
    kop_kdf(ss, pq_ss, ec_ss, ct);
}

void kop_kem_decaps(
    kop_kem_ss_s *ss,
    const uint8_t ct[KOP_KEM_CT_BYTES],
    const kop_kem_sk_s *sk)
{
    uint8_t ec_ss[KOP_EC_SS_BYTES], pq_ss[KOP_PQ_SS_BYTES];

    kop_ec_decaps(ec_ss, ct, &sk->ec);
    kop_pq_decaps(pq_ss, &ct[KOP_EC_CT_BYTES], sk->pq);
    kop_kdf(ss, pq_ss, ec_ss, ct);
}

void kop_kem_pk_serialize(
    uint8_t out[KOP_KEM_PK_BYTES],
    const kop_kem_pk_s *pk) 
{
    kop_ec_pk_serialize(out, &pk->ec);
    memcpy(&out[KOP_EC_PK_BYTES], pk->pq, KOP_PQ_PK_BYTES);
}

kop_result_e kop_kem_pk_deserialize(kop_kem_pk_s *pk, const uint8_t in[KOP_KEM_PK_BYTES])
{
    kop_result_e res;

    res = kop_ec_pk_deserialize(&pk->ec, in);
    memcpy(pk->pq, &in[KOP_EC_PK_BYTES], KOP_PQ_PK_BYTES);
    return res;
}

