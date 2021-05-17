#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>

#include "group.h"
#include "params.h"

///////
/// The following is mostly duplicated from Crystals/Kyber768 code.
/// [0]: github.com/pq-crystals/kyber/tree/master/ref
///////

#define KYBER_N 256
#define KYBER_K 3
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

    for(i = 0; i < KYBER_N / 2; i++) {
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

    for(i = 0; i < KYBER_N / 2; i++) {
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

    for(i = 0; i < KYBER_N; i++)
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

// Add polynomials
static void poly_add(poly *r, const poly *a, const poly *b)
{
    size_t i;

    for(i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

// Subtract polynomials
static void poly_sub(poly *r, const poly *a, const poly *b)
{
    size_t i;

    for(i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

// Serialize a vector of polynomials
static void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], polyvec *a)
{
    size_t i;

    for(i = 0; i < KYBER_K; i++) {
        poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
    }
}

// De-serialize a vector of polynomials
static void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES])
{
    size_t i;

    for(i = 0; i < KYBER_K; i++) {
        poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
    }
}

// Applies Barrett reduction to all coefficients of a the vector of polynomials
static void polyvec_reduce(polyvec *r)
{
    size_t i;

    for(i = 0; i < KYBER_K; i++) {
        poly_reduce(&r->vec[i]);
    }
}

// Add vectors of polynomials.
static void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
    size_t i;

    for(i = 0; i < KYBER_K; i++) {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

// Serialize vector of polynomials and seed into bytes.
static void pack_pk(uint8_t r[KOP_PK_BYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
    size_t i;

    polyvec_tobytes(r, pk);
    for(i = 0; i < KYBER_SYMBYTES; i++) {
        r[i + KYBER_POLYVECBYTES] = seed[i];
    }
}

// De-serialize vector of polynomials and seed from bytes.
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KOP_PK_BYTES])
{
    size_t i;

    polyvec_frombytes(pk, packedpk);
    for(i = 0; i < KYBER_SYMBYTES; i++) {
        seed[i] = packedpk[i + KYBER_POLYVECBYTES];
    }
}

// rejection sampling (three bytes to two coordinates mod q)
static size_t rej_uniform(int16_t *r,
                          size_t len,
                          const uint8_t *buf,
                          size_t buflen)
{
    size_t ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while(ctr < len && pos + 3 <= buflen) {
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if(val0 < KYBER_Q) {
            r[ctr++] = val0;
        }
        if(ctr < len && val1 < KYBER_Q) {
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

    for(i = 0; i < KYBER_K; i++) {
        poly_sub(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

// Generate a random polyvec from a seed.
//
// Adapted from the Crystals/Kyber subroutine `gen_matrix`.
// Does not generate more than one polyvec.
// 
// OpenSSL can't squeeze a XOF, so we apply a hack like liboqs does, cloning contexts
// and dynamically allocating memory. (The overhead here could be worse than the gain
// of using OpenSSL's optimized shake implementation)
#define XOF_BLOCKBYTES 168
#define GEN_POLYVEC_NBLOCKS ((12*KYBER_N/8*(1 << 12) / KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
static void gen_polyvec(polyvec *a, const uint8_t seed[KYBER_SYMBYTES])
{
    size_t ctr, i, squeeze_len;
    size_t buflen;
    uint8_t extseed[KYBER_SYMBYTES + 1];
    uint8_t *buf;
    EVP_MD_CTX *ctx, *ctx_clone;

    ctx = EVP_MD_CTX_new();
    ctx_clone = EVP_MD_CTX_new();
    buflen = GEN_POLYVEC_NBLOCKS * XOF_BLOCKBYTES;
    buf = malloc(buflen);
    assert(buf != NULL);

    for (i = 0; i < KYBER_SYMBYTES; i++) {
        extseed[i] = seed[i];
    }

    for (i = 0; i < KYBER_K; i++) {
        extseed[KYBER_SYMBYTES] = (uint8_t)i;
        EVP_DigestInit_ex(ctx, EVP_shake128(), NULL);
        EVP_DigestUpdate(ctx, extseed, sizeof(extseed));
        EVP_DigestInit_ex(ctx_clone, EVP_shake128(), NULL);
        EVP_MD_CTX_copy_ex(ctx_clone, ctx);
        EVP_DigestFinalXOF(ctx_clone, buf, GEN_POLYVEC_NBLOCKS * XOF_BLOCKBYTES);
        ctr = rej_uniform(a->vec[i].coeffs, KYBER_N, buf, buflen);
        squeeze_len = (buflen / 3) * 3;

        while(ctr < KYBER_N) {
            free(buf);
            buflen += XOF_BLOCKBYTES;
            buf = malloc(buflen);
            assert(buf != NULL);
            EVP_DigestInit_ex(ctx_clone, EVP_shake128(), NULL);
            EVP_MD_CTX_copy_ex(ctx_clone, ctx);
            EVP_DigestFinalXOF(ctx_clone, buf, buflen);
            ctr += rej_uniform(a->vec[i].coeffs + ctr, KYBER_N - ctr, buf + squeeze_len, buflen - squeeze_len);
            squeeze_len = (buflen / 3) * 3;
        }
    }
    free(buf);
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctx_clone);
}

/// r = a + b
///
/// Group addition of public keys
///
/// @param[out] r  resulting sum (of length KOP_PK_BYTES)
/// @param[in]  a  first sum input (of length KOP_PK_BYTES)
/// @param[in]  b  second sum input (of length KOP_PK_BYTES)
void add_pk(uint8_t r[KOP_PK_BYTES], const uint8_t a[KOP_PK_BYTES], const uint8_t b[KOP_PK_BYTES])
{
    size_t i;
    polyvec ta, tb;
    uint8_t rhoa[KYBER_SYMBYTES], rhob[KYBER_SYMBYTES];

    unpack_pk(&ta, rhoa, a);
    unpack_pk(&tb, rhob, b);
    polyvec_add(&ta, &ta, &tb);
    polyvec_reduce(&ta);
    for (i = 0; i < KYBER_SYMBYTES; i++) {
        rhoa[i] ^= rhob[i];
    }
    pack_pk(r, &ta, rhoa);
}

/// r = a - b
///
/// Group subtraction of public keys
///
/// @param[out] r  resulting difference (of length KOP_PK_BYTES)
/// @param[in]  a  minuend (of length KOP_PK_BYTES)
/// @param[in]  b  subtrahend (of length KOP_PK_BYTES)
void sub_pk(uint8_t r[KOP_PK_BYTES], const uint8_t a[KOP_PK_BYTES], const uint8_t b[KOP_PK_BYTES])
{
    size_t i;
    polyvec ta, tb;
    uint8_t rhoa[KYBER_SYMBYTES], rhob[KYBER_SYMBYTES];

    unpack_pk(&ta, rhoa, a);
    unpack_pk(&tb, rhob, b);
    polyvec_sub(&ta, &ta, &tb);
    polyvec_reduce(&ta);
    for (i = 0; i < KYBER_SYMBYTES; i++) {
        rhoa[i] ^= rhob[i];
    }
    pack_pk(r, &ta, rhoa);
}

// Expand a seed into a public key: generate polynomial
static void gen_pk(uint8_t pk[KOP_PK_BYTES], const uint8_t seed[2 * KYBER_SYMBYTES])
{
    polyvec a;

    gen_polyvec(&a, seed);
    pack_pk(pk, &a, &seed[KYBER_SYMBYTES]);
}

/// Generate a random public key
///
/// Generates a random seed, then expands that into a public key.
///
/// @param[out] pk resulting public key (of length KOP_PK_BYTES)
void random_pk(uint8_t pk[KOP_PK_BYTES])
{
    uint8_t seed[2 * KYBER_SYMBYTES];

    randombytes(seed, 2 * KYBER_SYMBYTES);
    gen_pk(pk, seed);
}

/// Hash public keys into a new public key
///
/// Hashes input public keys to a seed, then generates a new public key from that seed.
///
/// @param[out] pk   resulting public key (of length KOP_PK_BYTES)
/// @param[in]  pks  (KOP_OT_N - 1) public keys (each of length KOP_PK_BYTES)
/// @param[in]  hid  unique identifier, ensures domain separation
void hash_pks(uint8_t pk[KOP_PK_BYTES], const uint8_t * const pks[KOP_OT_N - 1], const hid_t *hid)
{
    EVP_MD_CTX *ctx;
    uint8_t seed[2 * KYBER_SYMBYTES];
    uint8_t hid_buf[KOP_SID_BYTES + 3];
    size_t i;

    memcpy(hid_buf, hid->sid, KOP_SID_BYTES);
    hid_buf[KOP_SID_BYTES    ] = hid->oenc;
    hid_buf[KOP_SID_BYTES + 1] = hid->ot;
    hid_buf[KOP_SID_BYTES + 2] = hid->kem;
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, hid_buf, KOP_SID_BYTES + 3);
    for (i = 0; i < KOP_OT_N - 1; i++) {
        EVP_DigestUpdate(ctx, pks[i], KOP_PK_BYTES);
    }
    EVP_DigestFinal_ex(ctx, seed, NULL);
    gen_pk(pk, seed);
    EVP_MD_CTX_free(ctx);
}

