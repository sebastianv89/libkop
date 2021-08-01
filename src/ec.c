#include <stddef.h>
#include <stdint.h>

#include <decaf/common.h>
#include <decaf/point_448.h>

#include "KeccakHash.h"

#include "ec.h"
#include "common.h"
#include "randombytes.h"

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

// map success to ok and failure to error
// decaf: success = -1, failure = 0;
// kop: ok = 0, error = -1, abort = -2;
static kop_result_e kop_result_from_decaf_error(decaf_error_t err)
{
    return -1 - err;
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
    uint8_t buf[DECAF_448_SCALAR_BYTES];

    randombytes(buf, sizeof(buf));
    decaf_448_scalar_decode_long(sk->sk, buf, DECAF_448_SCALAR_BYTES);
    decaf_448_precomputed_scalarmul(pk->pk, decaf_448_precomputed_base, sk->sk);
}

void kop_ec_encaps(
    uint8_t ct[KOP_EC_CT_BYTES],
    uint8_t ss[KOP_EC_SS_BYTES],
    const kop_ec_pk_s *pk)
{
    uint8_t buf[DECAF_448_SCALAR_BYTES];
    decaf_448_scalar_t scalar;
    decaf_448_point_t g, h;

    randombytes(buf, DECAF_448_SCALAR_BYTES);
    decaf_448_scalar_decode_long(scalar, buf, DECAF_448_SCALAR_BYTES);
    decaf_448_precomputed_scalarmul(g, decaf_448_precomputed_base, scalar);
    decaf_448_point_scalarmul(h, pk->pk, scalar);
    decaf_448_point_encode(ct, g);
    decaf_448_point_encode(ss, h);
}

void kop_ec_decaps(
    uint8_t ss[KOP_EC_SS_BYTES],
    const uint8_t ct[KOP_EC_CT_BYTES],
    const kop_ec_sk_s *sk)
{
    decaf_error_t err;
    decaf_448_point_t g;

    err = decaf_448_point_decode(g, ct, DECAF_FALSE);
    // g := (err == DECAF_SUCCESS ? g : base)
    decaf_448_point_cond_sel(g, decaf_448_point_base, g, err);
    decaf_448_point_scalarmul(g, g, sk->sk);
    decaf_448_point_encode(ss, g);
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
