#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <decaf/point_448.h>

#include "KeccakHash.h"
#include "SimpleFIPS202.h"

#include "group.h"
#include "common.h"
#include "params.h"
#include "kem.h"
#include "randombytes.h"

///////
/// The following is mostly duplicated from Crystals/Kyber768 code.
/// [0]: github.com/pq-crystals/kyber/tree/master/ref
///////

#ifndef KYBER_K
#define KYBER_K 3
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES      32
#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

typedef struct {
    poly vec[KYBER_K];
} polyvec;

// Serialization of a polynomial
static void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a)
{
    size_t i;
    uint16_t t0, t1;

    for (i = 0; i < KYBER_N / 2; i++) {
        // map to positive standard representatives
        t0  = a->coeffs[2 * i];
        t0 += ((int16_t)t0 >> 15) & KYBER_Q;
        t1 = a->coeffs[2 * i + 1];
        t1 += ((int16_t)t1 >> 15) & KYBER_Q;
        r[3 * i + 0] = (t0 >> 0);
        r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
        r[3 * i + 2] = (t1 >> 4);
    }
}

// De-serialization of a polynomial
static void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES])
{
    size_t i;

    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2 * i]     = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}

// Barrett reduction: computes centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
static int16_t barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;

    t  = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= KYBER_Q;
    return a - t;
}

// Applies Barrett reduction to all coefficients of a polynomial
static void poly_reduce(poly *r)
{
    size_t i;

    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

// Add polynomials
static void poly_add(poly *r, const poly *a, const poly *b)
{
    size_t i;

    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

// Subtract polynomials
static void poly_sub(poly *r, const poly *a, const poly *b)
{
    size_t i;

    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

// Serialize a vector of polynomials
static void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], polyvec *a)
{
    size_t i;

    for (i = 0; i < KYBER_K; i++) {
        poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
    }
}

// De-serialize a vector of polynomials
static void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES])
{
    size_t i;

    for (i = 0; i < KYBER_K; i++) {
        poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
    }
}

// Applies Barrett reduction to all coefficients of a the vector of polynomials
static void polyvec_reduce(polyvec *r)
{
    size_t i;

    for (i = 0; i < KYBER_K; i++) {
        poly_reduce(&r->vec[i]);
    }
}

// Add vectors of polynomials.
static void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
    size_t i;

    for (i = 0; i < KYBER_K; i++) {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

// Serialize vector of polynomials and seed into bytes.
static void pack_pk(
    uint8_t r[KOP_PQ_PK_BYTES],
    polyvec *pk,
    const uint8_t seed[KYBER_SYMBYTES])
{
    size_t i;

    polyvec_tobytes(r, pk);
    for (i = 0; i < KYBER_SYMBYTES; i++) {
        r[i + KYBER_POLYVECBYTES] = seed[i];
    }
}

// De-serialize vector of polynomials and seed from bytes.
static void unpack_pk(
    polyvec *pk,
    uint8_t seed[KYBER_SYMBYTES],
    const uint8_t packedpk[KOP_PQ_PK_BYTES])
{
    size_t i;

    polyvec_frombytes(pk, packedpk);
    for (i = 0; i < KYBER_SYMBYTES; i++) {
        seed[i] = packedpk[i + KYBER_POLYVECBYTES];
    }
}

// rejection sampling (three bytes to two coordinates mod q)
static size_t rej_uniform(
    int16_t *r,
    size_t len,
    const uint8_t *buf,
    size_t buflen)
{
    size_t ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q) {
            r[ctr++] = val0;
        }
        if (ctr < len && val1 < KYBER_Q) {
            r[ctr++] = val1;
        }
    }

    return ctr;
}

///////
/// End of duplicated code
///////

// Subtract vectors of polynomials.
static void polyvec_sub(polyvec *r, const polyvec *a, const polyvec *b)
{
    size_t i;

    for (i = 0; i < KYBER_K; i++) {
        poly_sub(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

// Generate a random polyvec from a seed.
//
// Adapted from the Crystals/Kyber subroutine `gen_matrix`.
// Does not generate more than one polyvec.
#define SHAKE128_BYTERATE 168
#define REJ_SAMPLE_BLOCKS ((12*KYBER_N/8*(1 << 12) / KYBER_Q + SHAKE128_BYTERATE)/SHAKE128_BYTERATE)
#define REJ_SAMPLE_BYTES (REJ_SAMPLE_BLOCKS * SHAKE128_BYTERATE)
static void gen_polyvec(polyvec *a, const uint8_t seed[KYBER_SYMBYTES])
{
    const uint8_t prefix[13] = { 0x4b, 0x4f, 0x50, 0x2d, 0x4b, 0x79, 0x62, 0x65, 0x72, 0x2d, 0x58, 0x4f, 0x46 }; // "KOP-Kyber-XOF";

    size_t ctr, i;
    uint8_t buf[REJ_SAMPLE_BYTES];
    Keccak_HashInstance hi;

    for (i = 0; i < KYBER_K; i++) {
        KECCAK_UNWRAP(Keccak_HashInitialize_SHAKE128(&hi));
        KECCAK_UNWRAP(Keccak_HashUpdate(&hi, prefix, 8 * sizeof(prefix)));
        KECCAK_UNWRAP(Keccak_HashUpdate(&hi, seed, 8 * KYBER_SYMBYTES));
        KECCAK_UNWRAP(Keccak_HashUpdate(&hi, seed, 8 * KYBER_SYMBYTES));
        KECCAK_UNWRAP(Keccak_HashUpdate(&hi, (uint8_t *)(&i), 8));
        KECCAK_UNWRAP(Keccak_HashFinal(&hi, NULL));
        KECCAK_UNWRAP(Keccak_HashSqueeze(&hi, buf, 8 * REJ_SAMPLE_BYTES));
        ctr = rej_uniform(a->vec[i].coeffs, KYBER_N, buf, REJ_SAMPLE_BYTES);
        while (ctr < KYBER_N) {
            KECCAK_UNWRAP(Keccak_HashSqueeze(&hi, buf, 8 * SHAKE128_BYTERATE));
            ctr += rej_uniform(a->vec[i].coeffs + ctr, KYBER_N - ctr, buf, SHAKE128_BYTERATE);
        }
    }
}

void add_pk(kop_kem_pk_s *r, const kop_kem_pk_s *a, const kop_kem_pk_s *b)
{
    size_t i;
    polyvec ta, tb;
    uint8_t rhoa[KYBER_SYMBYTES], rhob[KYBER_SYMBYTES];

    // PQ KEM
    unpack_pk(&ta, rhoa, a->pq);
    unpack_pk(&tb, rhob, b->pq);
    polyvec_add(&ta, &ta, &tb);
    polyvec_reduce(&ta);
    for (i = 0; i < KYBER_SYMBYTES; i++) {
        rhoa[i] ^= rhob[i];
    }
    pack_pk(r->pq, &ta, rhoa);

    // ECDH
    decaf_448_point_add(r->ec.pk, a->ec.pk, b->ec.pk);
}

void sub_pk(kop_kem_pk_s *r, const kop_kem_pk_s *a, const kop_kem_pk_s *b)
{
    size_t i;
    polyvec ta, tb;
    uint8_t rhoa[KYBER_SYMBYTES], rhob[KYBER_SYMBYTES];

    // PQ KEM
    unpack_pk(&ta, rhoa, a->pq);
    unpack_pk(&tb, rhob, b->pq);
    polyvec_sub(&ta, &ta, &tb);
    polyvec_reduce(&ta);
    for (i = 0; i < KYBER_SYMBYTES; i++) {
        rhoa[i] ^= rhob[i];
    }
    pack_pk(r->pq, &ta, rhoa);

    // ECDH
    decaf_448_point_sub(r->ec.pk, a->ec.pk, b->ec.pk);
}

// Expand a seed into a public key: generate polynomial
static void gen_pk(kop_kem_pk_s *r, const uint8_t seed[2 * (KYBER_SYMBYTES + DECAF_448_HASH_BYTES)])
{
    polyvec a;

    // PQ KEM
    gen_polyvec(&a, seed);
    pack_pk(r->pq, &a, &seed[KYBER_SYMBYTES]);

    // ECDH
    decaf_448_point_from_hash_uniform(r->ec.pk, &seed[64]);
}

void random_pk(kop_kem_pk_s *r)
{
    uint8_t seed[64 + 2 * DECAF_448_HASH_BYTES];
    
    randombytes(seed, 32);
    // hash the randomness to prevent leaking the system random state
    FIPS202_UNWRAP(SHAKE256(seed, 2 * (KYBER_SYMBYTES + DECAF_448_HASH_BYTES), seed, 32));
    gen_pk(r, seed);
}

void hash_pks(kop_kem_pk_s *r, const uint8_t * const pks[KOP_OT_N - 1], hid_t hid)
{
    uint8_t prefix[6] = {0x4b, 0x4f, 0x50, 0x2d, 0x52, 0x4f}; // "KOP-RO"
    uint8_t seed[64 + 2 * DECAF_448_HASH_BYTES];
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
    KECCAK_UNWRAP(Keccak_HashSqueeze(&hi, seed, 8 * (64 + 2 * DECAF_448_HASH_BYTES)));
    gen_pk(r, seed);
}

