#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "group.h"
#include "common.h"
#include "params.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static void test_group()
{
    kop_kem_pk_s a, b, c, pks[KOP_OT_N - 1];
    const kop_kem_pk_s * pk_pointers[KOP_OT_N - 1];
    size_t j;
    hid_t hid = {0};

    random_pk(&a);
    random_pk(&b);
    add_pk(&c, &a, &b);
    sub_pk(&c, &c, &b);

    for (j = 0; j < KOP_OT_N - 1; j++) {
        random_pk(&pks[j]);
        pk_pointers[j] = &pks[j];
    }
    assert(verify(a.bytes, c.bytes, KOP_PK_BYTES) == 0);
    hash_pks(&a, pk_pointers, hid);
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

