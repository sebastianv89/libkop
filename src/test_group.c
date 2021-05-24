#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <decaf/common.h>

#include "group.h"
#include "kem.h"
#include "params.h"
#include "common.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static void test_group()
{
    kop_kem_pk_s a, b, c, pk;
    uint8_t pk_serialized[(KOP_OT_N - 1) * KOP_KEM_PK_BYTES];
    const uint8_t * pk_pointers[KOP_OT_N - 1];
    size_t j;
    hid_t hid = {0};

    random_pk(&a);
    random_pk(&b);
    add_pk(&c, &a, &b);
    sub_pk(&c, &c, &b);
    assert(decaf_448_point_eq(a.ec.pk, c.ec.pk) == DECAF_TRUE);
    assert(verify(a.pq, c.pq, KOP_PQ_PK_BYTES) == 0);

    for (j = 0; j < KOP_OT_N - 1; j++) {
        random_pk(&pk);
        kop_kem_pk_serialize(&pk_serialized[j * KOP_KEM_PK_BYTES], &pk);
        pk_pointers[j] = &pk_serialized[j * KOP_KEM_PK_BYTES];
    }
    hash_pks(&a, pk_pointers, hid);
    hash_pks(&b, pk_pointers, hid);
    assert(decaf_448_point_eq(a.ec.pk, b.ec.pk) == DECAF_TRUE);
    assert(verify(a.pq, b.pq, KOP_PQ_PK_BYTES) == 0);
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
        test_group();
    }

    return EXIT_SUCCESS;
}

