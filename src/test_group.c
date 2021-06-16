#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <decaf/common.h>

#include "group.h"
#include "kem.h"
#include "ec.h"
#include "pq.h"
#include "params.h"
#include "common.h"
#include "randombytes.h"

#define XSTR(s) STR(s)
#define STR(s) #s

// Comparison of pq public keys, for testing purposes only
static int kop_pq_pk_eq(
    kop_pq_pk_s *a,
    kop_pq_pk_s *b)
{
    uint8_t a_ser[KOP_PQ_PK_BYTES], b_ser[KOP_PQ_PK_BYTES];

    kop_pq_pk_serialize(a_ser, a);
    kop_pq_pk_serialize(b_ser, b);

    return verify(a_ser, b_ser, KOP_PQ_PK_BYTES) == 0;
}

static void test_ec()
{
    uint8_t seed[2 * DECAF_448_HASH_BYTES];
    kop_ec_pk_s a, b, c;

    randombytes(seed, sizeof(seed));
    kop_ec_gen_pk(&a, seed);
    randombytes(seed, sizeof(seed));
    kop_ec_gen_pk(&b, seed);
    kop_ec_add_pk(&c, &a, &b);
    kop_ec_sub_pk(&c, &c, &b);
    assert(decaf_448_point_eq(a.pk, c.pk) == DECAF_TRUE);
}

static void test_pq()
{
    uint8_t seed[KOP_KYBER_SYMBYTES], rho[KOP_KYBER_SYMBYTES];
    kop_pq_pk_s a, b, c;

    randombytes(rho, sizeof(rho));
    randombytes(seed, sizeof(seed));
    kop_pq_gen_pk(&a, seed, rho);
    randombytes(seed, sizeof(seed));
    kop_pq_gen_pk(&b, seed, rho);
    // (a + b) - b == a
    kop_pq_add_pk(&c, &a, &b);
    kop_pq_sub_pk(&c, &c, &b);
    assert(kop_pq_pk_eq(&a, &c));
}

static void test_group()
{
    kop_kem_pk_s a, b, c, pk;
    uint8_t rho[KOP_KYBER_SYMBYTES];
    uint8_t pk_serialized[(KOP_OT_N - 1) * KOP_KEM_PK_BYTES];
    const uint8_t * pk_pointers[KOP_OT_N - 1];
    size_t j;
    hid_t hid = {0};

    randombytes(rho, sizeof(rho));
    kop_random_pk(&a, rho);
    kop_random_pk(&b, rho);
    kop_add_pk(&c, &a, &b);
    kop_sub_pk(&c, &c, &b);
    assert(decaf_448_point_eq(a.ec.pk, c.ec.pk) == DECAF_TRUE);
    assert(kop_pq_pk_eq(&a.pq, &c.pq));

    for (j = 0; j < KOP_OT_N - 1; j++) {
        kop_random_pk(&pk, rho);
        kop_kem_pk_serialize(&pk_serialized[j * KOP_KEM_PK_BYTES], &pk);
        pk_pointers[j] = &pk_serialized[j * KOP_KEM_PK_BYTES];
    }
    kop_hash_pks(&a, pk_pointers, rho, hid);
    kop_hash_pks(&b, pk_pointers, rho, hid);
    assert(decaf_448_point_eq(a.ec.pk, b.ec.pk) == DECAF_TRUE);
    assert(kop_pq_pk_eq(&a.pq, &b.pq));
}

int main(int argc, char *argv[])
{
    size_t i, nr_of_tests = 16;

    if (argc >= 2) {
        nr_of_tests = atoi(argv[1]);
        if (nr_of_tests == 0) {
            fprintf(stderr, "Usage: %s [nr_of_tests]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    for (i = 0; i < nr_of_tests; i++) {
        test_ec();
        test_pq();
        test_group();
    }

    return EXIT_SUCCESS;
}

