#include <stddef.h>
#include <stdint.h>

#include <decaf/common.h>
#include <decaf/point_448.h>

#include "KeccakHash.h"

#include "ec.h"
#include "common.h"
#include "types.h"
#include "randombytes.h"

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

// map success to ok and failure to error
// decaf: success = -1, failure = 0;
// kop: ok = 0, error = -1, abort = -2;
static kop_result_e kop_result_from_decaf_error(decaf_error_t err)
{
    return -1 - err;
}

static void kop_ec_kdf(
    uint8_t ss[KOP_EC_SS_BYTES],
    const uint8_t m_serialized[DECAF_448_SER_BYTES],
    const uint8_t ct[KOP_EC_CT_BYTES])
{
    const uint8_t prefix[10] = {0x4b, 0x4f, 0x50, 0x2d, 0x45, 0x43, 0x2d, 0x4b, 0x44, 0x46}; // "KOP-EC-KDF"
    Keccak_HashInstance hi;

    KECCAK_UNWRAP(Keccak_HashInitialize_SHAKE256(&hi));
    // domain separation
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, prefix, 8 * sizeof(prefix)));
    // hash message and ciphertext
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, m_serialized, 8 * DECAF_448_SER_BYTES));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, ct, 8 * KOP_EC_CT_BYTES));
    // output
    KECCAK_UNWRAP(Keccak_HashFinal(&hi, NULL));
    KECCAK_UNWRAP(Keccak_HashSqueeze(&hi, ss, 8 * KOP_EC_SS_BYTES));
}

void kop_ec_add_pk(
    kop_ec_pk_s *r,
    const kop_ec_pk_s *a,
    const kop_ec_pk_s *b)
{
    decaf_448_point_add(r->pk, a->pk, b->pk);
}

void kop_ec_sub_pk(
    kop_ec_pk_s *r,
    const kop_ec_pk_s *a,
    const kop_ec_pk_s *b)
{
    decaf_448_point_sub(r->pk, a->pk, b->pk);
}

void kop_ec_gen_pk(
    kop_ec_pk_s *r,
    const uint8_t seed[2 * DECAF_448_HASH_BYTES])
{
    decaf_448_point_from_hash_uniform(r->pk, seed);
}

void kop_ec_keygen(
    kop_ec_pk_s *pk,
    kop_ec_sk_s *sk)
{
    uint8_t buf[DECAF_448_SCALAR_BYTES + DECAF_448_SER_BYTES];

    randombytes(buf, sizeof(buf));
    decaf_448_scalar_decode_long(sk->sk, buf, DECAF_448_SCALAR_BYTES);
    decaf_448_precomputed_scalarmul(pk->pk, decaf_448_precomputed_base, sk->sk);
    memcpy(sk->s, &buf[DECAF_448_SCALAR_BYTES], DECAF_448_SER_BYTES);
    // technically (according to https://eprint.iacr.org/2017/604) `s` should
    // come from the message space (a random serialized point) however since it
    // is only ever used as input to a kdf, a random bytesequence is pretty
    // much the same.
}

void kop_ec_encaps(
    uint8_t ct[KOP_EC_CT_BYTES],
    uint8_t ss[KOP_EC_SS_BYTES],
    const kop_ec_pk_s *pk)
{
    uint8_t buf[MAX(DECAF_448_SCALAR_BYTES + 2 * DECAF_448_HASH_BYTES, DECAF_448_SER_BYTES)];
    decaf_448_scalar_t scalar;
    decaf_448_point_t m, c0, c1;

    randombytes(buf, DECAF_448_SCALAR_BYTES + 2 * DECAF_448_HASH_BYTES);
    decaf_448_scalar_decode_long(scalar, buf, DECAF_448_SCALAR_BYTES);
    decaf_448_point_from_hash_uniform(m, &buf[DECAF_448_SCALAR_BYTES]);
    decaf_448_precomputed_scalarmul(c0, decaf_448_precomputed_base, scalar);
    decaf_448_point_scalarmul(c1, pk->pk, scalar);
    decaf_448_point_add(c1, c1, m);
    decaf_448_point_encode(ct, c0);
    decaf_448_point_encode(buf, m);
    decaf_448_point_encode(&ct[DECAF_448_SER_BYTES], c1);
    kop_ec_kdf(ss, buf, ct);
}

void kop_ec_decaps(
    uint8_t ss[KOP_EC_SS_BYTES],
    const uint8_t ct[KOP_EC_CT_BYTES],
    const kop_ec_sk_s *sk)
{
    decaf_error_t err;
    decaf_448_point_t c0, c1;
    uint8_t m_serialized[DECAF_448_SER_BYTES];
    
    // we cannot stop after the first error to output kdf(sk->s, ct), but we
    // continue the calculation with dummy values in order not to leak any
    // timing info

    err = decaf_448_point_decode(c0, ct, DECAF_FALSE);
    // c0 = (err == DECAF_SUCCESS ? c0 : base)
    decaf_448_point_cond_sel(c0, decaf_448_point_base, c0, err);
    err &= decaf_448_point_decode(c1, &ct[DECAF_448_SER_BYTES], DECAF_TRUE);
    // c1 = (err == DECAF_SUCCESS ? c1 : base)
    decaf_448_point_cond_sel(c1, decaf_448_point_base, c1, err);
    decaf_448_point_scalarmul(c0, c0, sk->sk);
    decaf_448_point_sub(c1, c1, c0);
    decaf_448_point_encode(m_serialized, c1);
    cmov(m_serialized, sk->s, DECAF_448_SER_BYTES, 1+err);
    kop_ec_kdf(ss, m_serialized, ct);
}

void kop_ec_pk_serialize(
    uint8_t out[KOP_EC_PK_BYTES],
    const kop_ec_pk_s *pk)
{
    decaf_448_point_encode(out, pk->pk);
}

kop_result_e kop_ec_pk_deserialize(
    kop_ec_pk_s *pk,
    const uint8_t in[KOP_EC_PK_BYTES])
{
    return kop_result_from_decaf_error(
        decaf_448_point_decode(pk->pk, in, DECAF_FALSE)
    );
}
