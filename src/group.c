#include <stddef.h>
#include <stdint.h>

#include "KeccakHash.h"

#include "group.h"
#include "ec.h"
#include "pq.h"
#include "common.h"
#include "params.h"
#include "kem.h"
#include "randombytes.h"

void kop_add_pk(
    kop_kem_pk_s *r,
    const kop_kem_pk_s *a,
    const kop_kem_pk_s *b)
{
    kop_ec_add_pk(&r->ec, &a->ec, &b->ec);
    kop_pq_add_pk(&r->pq, &a->pq, &b->pq);
}

void kop_sub_pk(
    kop_kem_pk_s *r,
    const kop_kem_pk_s *a,
    const kop_kem_pk_s *b)
{
    kop_ec_sub_pk(&r->ec, &a->ec, &b->ec);
    kop_pq_sub_pk(&r->pq, &a->pq, &b->pq);
}

void kop_random_pk(
    kop_kem_pk_s *r,
    const uint8_t rho[KOP_KYBER_SYMBYTES])
{
    uint8_t seed[2 * DECAF_448_HASH_BYTES + KOP_KYBER_SYMBYTES];
    
    randombytes(seed, sizeof(seed));
    kop_ec_gen_pk(&r->ec, seed);
    kop_pq_gen_pk(&r->pq, &seed[2 * DECAF_448_HASH_BYTES], rho);
}

void kop_hash_pks(
    kop_kem_pk_s *r,
    const uint8_t * const pks[KOP_OT_N - 1],
    const uint8_t rho[KOP_KYBER_SYMBYTES],
    hid_t hid)
{
    uint8_t prefix[6] = {0x4b, 0x4f, 0x50, 0x2d, 0x52, 0x4f}; // "KOP-RO"
    uint8_t seed[2 * DECAF_448_HASH_BYTES + KOP_KYBER_SYMBYTES];
    Keccak_HashInstance hi;
    size_t i;

    KECCAK_UNWRAP(Keccak_HashInitialize_SHAKE256(&hi));
    // domain separation
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, prefix, 8 * sizeof(prefix)));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, hid.sid, 8 * KOP_SID_BYTES));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, &hid.oenc, 8));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, &hid.ot, 8));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, &hid.kem, 8));
    // input data
    for (i = 0; i < KOP_OT_N - 1; i++) {
        KECCAK_UNWRAP(Keccak_HashUpdate(&hi, pks[i], 8 * KOP_KEM_PK_BYTES));
    }
    // get output
    KECCAK_UNWRAP(Keccak_HashFinal(&hi, NULL));
    KECCAK_UNWRAP(Keccak_HashSqueeze(&hi, seed, 8 * sizeof(seed)));
    kop_ec_gen_pk(&r->ec, seed);
    kop_pq_gen_pk(&r->pq, &seed[2 * DECAF_448_HASH_BYTES], rho);
}

