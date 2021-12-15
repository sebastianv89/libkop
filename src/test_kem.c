#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "poison.h"

#include "kem.h"
#include "ec.h"
#include "pq.h"
#include "common.h"
#include "params.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static void test_kem_ec()
{
    uint8_t ct[KOP_EC_CT_BYTES], ss0[KOP_EC_SS_BYTES], ss1[KOP_EC_SS_BYTES];
    kop_ec_pk_s pk;
    kop_ec_sk_s sk;

    kop_ec_keygen(&pk, &sk);
    kop_ec_encaps(ct, ss0, &pk);
    kop_ec_decaps(ss1, ct, &sk);

    assert(verify(ss0, ss1, KOP_PQ_SS_BYTES) == 0);
}

static void test_kem_pq()
{
    uint8_t sk[KOP_PQ_SK_BYTES],
        ct[KOP_PQ_CT_BYTES],
        ss0[KOP_PQ_SS_BYTES],
        ss1[KOP_PQ_SS_BYTES];
    kop_pq_pk_s pk;

    kop_pq_keygen(&pk, sk);
    kop_pq_encaps(ct, ss0, &pk);
    kop_pq_decaps(ss1, ct, sk);

    assert(verify(ss0, ss1, KOP_PQ_SS_BYTES) == 0);
}

static void test_kem()
{
    kop_kem_pk_s pk;
    kop_kem_sk_s sk;
    uint8_t ct[KOP_KEM_CT_BYTES];
    kop_kem_ss_s ss0, ss1;

    kop_kem_keygen(&pk, &sk);
    kop_kem_encaps(ct, &ss0, &pk);
    kop_kem_decaps(&ss1, ct, &sk);

    assert(verify(ss0.bytes, ss1.bytes, KOP_KEM_SS_BYTES) == 0);
}

static void test_sidechannels()
{
    kop_kem_pk_s pk;
    kop_kem_sk_s sk;
    uint8_t ct[KOP_KEM_CT_BYTES];
    kop_kem_ss_s ss0, ss1;

    poison(&sk, sizeof(kop_kem_sk_s));
    poison(&ss0, sizeof(kop_kem_ss_s));
    poison(&ss1, sizeof(kop_kem_ss_s));

    kop_kem_keygen(&pk, &sk);
    poison(&sk, sizeof(kop_kem_sk_s));
    unpoison(&pk, sizeof(kop_kem_pk_s));
    kop_kem_encaps(ct, &ss0, &pk);
    poison(&ss0, sizeof(kop_kem_ss_s));
    unpoison(ct, KOP_KEM_CT_BYTES);
    kop_kem_decaps(&ss1, ct, &sk);
    poison(&ss1, sizeof(kop_kem_ss_s));
}

static void print_sizes()
{
    printf("%s\n", XSTR(KOP_PQ_ALG));
    printf("M0, R -> S: %8u bytes (public key); EC + PQ == %8u + %8u\n", KOP_KEM_PK_BYTES, KOP_EC_PK_BYTES, KOP_PQ_PK_BYTES);
    printf("M1, S -> R: %8u bytes (ciphertext); EC + PQ == %8u + %8u\n", KOP_KEM_CT_BYTES, KOP_EC_CT_BYTES, KOP_PQ_CT_BYTES);
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
        test_kem_ec();
        test_kem_pq();
        test_kem();
    }

    test_sidechannels();

    return EXIT_SUCCESS;
}

