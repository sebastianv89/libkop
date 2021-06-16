#include <stddef.h>
#include <stdint.h>

#include <oqs/oqs.h>

#include "KeccakHash.h"

#include "pq.h"
#include "common.h"
#include "params.h"

#ifdef KOP_DEBUG
#include <assert.h>
#endif

///////
/// The following is mostly duplicated from Crystals/Kyber code.
/// [0]: github.com/pq-crystals/kyber/tree/master/ref
///////

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

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

    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
    }
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
static void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a)
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

void kop_pq_add_pk(
    kop_pq_pk_s *r,
    const kop_pq_pk_s *a,
    const kop_pq_pk_s *b)
{
#ifdef KOP_DEBUG
    // required: a and b have the same rho for expanding matrix A
    assert(verify(a->rho, b->rho, KYBER_SYMBYTES) == 0);
#endif

    // PQ KEM
    polyvec_add(&r->t, &a->t, &b->t);
    polyvec_reduce(&r->t);
    memmove(r->rho, a->rho, KYBER_SYMBYTES);
}

void kop_pq_sub_pk(
    kop_pq_pk_s *r,
    const kop_pq_pk_s *a,
    const kop_pq_pk_s *b)
{
#ifdef KOP_DEBUG
    // required: a and b have the same rho for expanding matrix A
    assert(verify(a->rho, b->rho, KYBER_SYMBYTES) == 0);
#endif

    // PQ KEM
    polyvec_sub(&r->t, &a->t, &b->t);
    polyvec_reduce(&r->t);
    memmove(r->rho, a->rho, KYBER_SYMBYTES);
}

void kop_pq_gen_pk(
    kop_pq_pk_s *r,
    const uint8_t seed[KYBER_SYMBYTES],
    const uint8_t rho[KYBER_SYMBYTES])
{
    gen_polyvec(&r->t, seed);
    memmove(r->rho, rho, KYBER_SYMBYTES);
}

void kop_pq_keygen(
    kop_pq_pk_s *pk,
    uint8_t sk[KOP_PQ_SK_BYTES])
{
    uint8_t pk_ser[KOP_PQ_PK_BYTES];

    OQS_UNWRAP(KOP_PQ_KEYGEN(pk_ser, sk));
    kop_pq_pk_deserialize(pk, pk_ser);
}

void kop_pq_encaps(
    uint8_t ct[KOP_PQ_CT_BYTES],
    uint8_t ss[KOP_PQ_SS_BYTES],
    const kop_pq_pk_s *pk)
{
    uint8_t pk_ser[KOP_PQ_PK_BYTES];

    kop_pq_pk_serialize(pk_ser, pk);
    OQS_UNWRAP(KOP_PQ_ENCAPS(ct, ss, pk_ser));
}

void kop_pq_decaps(
    uint8_t ss[KOP_PQ_SS_BYTES],
    const uint8_t ct[KOP_PQ_CT_BYTES],
    const uint8_t sk[KOP_PQ_SS_BYTES])
{
    OQS_UNWRAP(KOP_PQ_DECAPS(ss, ct, sk));
}

void kop_pq_pk_serialize(
    uint8_t out[KOP_PQ_PK_BYTES],
    const kop_pq_pk_s *pk)
{
    polyvec_tobytes(out, &pk->t);
    memcpy(&out[KYBER_POLYVECBYTES], pk->rho, KYBER_SYMBYTES);
}

void kop_pq_pk_deserialize(
    kop_pq_pk_s *pk,
    const uint8_t in[KOP_PQ_PK_BYTES])
{
    polyvec_frombytes(&pk->t, in);
    memcpy(pk->rho, &in[KYBER_POLYVECBYTES], KYBER_SYMBYTES);

}

