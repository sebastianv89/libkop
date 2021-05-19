#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "kem.h"
#include "common.h"
#include "params.h"
#include "types.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static void test_kem()
{
    kop_kem_pk_s pk;
    kop_kem_sk_s sk;
    kop_kem_ct_s ct;
    kop_kem_ss_s ss0, ss1;
    kop_result_e res;

    res = kop_kem_keygen(&pk, &sk);
    assert(res == KOP_RESULT_OK);
    res = kop_kem_encaps(&ct, &ss0, &pk);
    assert(res == KOP_RESULT_OK);
    res = kop_kem_decaps(&ss1, &ct, &sk);
    assert(res == KOP_RESULT_OK);

    assert(verify(ss0.bytes, ss1.bytes, KOP_SS_BYTES) == 0);
}

static void print_sizes()
{
    printf("%s\n", XSTR(KOP_KEM_ALG));
    printf("M0, R -> S: %8u bytes (a public key)\n", KOP_PK_BYTES);
    printf("M1, S -> R: %8u bytes (a ciphertext)\n", KOP_CT_BYTES);
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

    printf("OQS %s\n", OQS_VERSION_TEXT);
    print_sizes();
    for (i = 0; i < nr_of_tests; i++) {
        test_kem();
    }

    return EXIT_SUCCESS;
}

