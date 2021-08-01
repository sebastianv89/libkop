#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "pec.h"
#include "common.h"
#include "params.h"
#include "randombytes.h"

#define XSTR(s) STR(s)
#define STR(s) #s
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

static void test_with_input(
    const uint8_t x[KOP_INPUT_BYTES],
    const uint8_t y[KOP_INPUT_BYTES],
    const uint8_t sid[KOP_SID_BYTES])
{
    kop_result_e res;
    kop_pec_state_s alice, bob;
    uint8_t msg0[KOP_PEC_MSG0_BYTES];
    uint8_t msg1[KOP_PEC_MSG1_BYTES];
    uint8_t msg2[KOP_PEC_MSG2_BYTES];
    uint8_t msg3[KOP_PEC_MSG3_BYTES];
    int accept, expected = 1 - verify(x, y, KOP_INPUT_BYTES);

    kop_pec_init(&alice, x, sid);
    kop_pec_init(&bob, y, sid);

    kop_pec_alice_m0(&alice, msg0);
    res = kop_pec_bob_m1(&bob, msg1, msg0);
    assert(res == KOP_RESULT_OK);
    res = kop_pec_alice_m2(&alice, msg2, msg1);
    assert(res == KOP_RESULT_OK);
    kop_pec_bob_m3(&accept, &bob, msg3, msg2);
    assert(accept == expected);
    res = kop_pec_alice_accept(&accept, &alice, msg3);
    assert(accept == expected);
    assert(res == KOP_RESULT_OK);
}

static void test_overlap(
    const uint8_t x[KOP_INPUT_BYTES],
    const uint8_t y[KOP_INPUT_BYTES],
    const uint8_t sid[KOP_SID_BYTES])
{
    kop_result_e res;
    kop_pec_state_s alice, bob;
    uint8_t msg[MAX(MAX(KOP_PEC_MSG0_BYTES, KOP_PEC_MSG1_BYTES), MAX(KOP_PEC_MSG2_BYTES, KOP_PEC_MSG3_BYTES))];
    int accept, expected = 1 - verify(x, y, KOP_INPUT_BYTES);

    kop_pec_init(&alice, x, sid);
    kop_pec_init(&bob, y, sid);

    kop_pec_alice_m0(&alice, msg);
    res = kop_pec_bob_m1(&bob, msg, msg);
    assert(res == KOP_RESULT_OK);
    res = kop_pec_alice_m2(&alice, msg, msg);
    assert(res == KOP_RESULT_OK);
    kop_pec_bob_m3(&accept, &bob, msg, msg);
    assert(accept == expected);
    res = kop_pec_alice_accept(&accept, &alice, msg);
    assert(accept == expected);
    assert(res == KOP_RESULT_OK);
}

static void test_pec()
{
    uint8_t x[KOP_INPUT_BYTES], y[KOP_INPUT_BYTES], sid[KOP_SID_BYTES];

    randombytes(x, KOP_INPUT_BYTES);
    randombytes(y, KOP_INPUT_BYTES);
    randombytes(sid, KOP_SID_BYTES);

    test_with_input(x, x, sid);
    test_with_input(x, y, sid);
    test_overlap(x, x, sid);
}

static void print_sizes()
{
    printf("%s, M=%u, N=%u\n", XSTR(KOP_PQ_ALG), KOP_OT_M, KOP_PEC_N);
    printf("M0, A -> B: %8u bytes (MN public keys)\n", KOP_PEC_MSG0_BYTES);
    printf("M1, B -> A: %8u bytes (MN (ciphertexts + public keys))\n", KOP_PEC_MSG1_BYTES);
    printf("M2, A -> B: %8u bytes (encoding + MN ciphertexts))\n", KOP_PEC_MSG2_BYTES);
    printf("M3, B -> A: %8u bytes (encoding)\n", KOP_PEC_MSG3_BYTES);
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
        test_pec();
    }

    return EXIT_SUCCESS;
}

