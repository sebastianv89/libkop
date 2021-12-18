#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "poison.h"

#include "pec.h"
#include "common.h"
#include "params.h"
#include "randombytes.h"

#define XSTR(s) STR(s)
#define STR(s) #s

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
    int expected = 1 - verify(x, y, KOP_INPUT_BYTES);

    memset(&alice, 0, sizeof(kop_pec_state_s));
    memset(&bob, 0, sizeof(kop_pec_state_s));
    kop_pec_set_input(&alice, x);
    kop_pec_set_input(&bob, y);
    kop_pec_set_sid(&alice, sid);
    kop_pec_set_sid(&bob, sid);

    kop_pec_alice_m0(&alice, msg0);
    res = kop_pec_bob_m1(&bob, msg1, msg0);
    assert(res == KOP_RESULT_OK);
    res = kop_pec_alice_m2(&alice, msg2, msg1);
    assert(res == KOP_RESULT_OK);
    kop_pec_bob_m3(&bob, msg3, msg2);
    assert(bob.accept == expected);
    res = kop_pec_alice_accept(&alice, msg3);
    assert(alice.accept == expected);
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
    // test_overlap(x, x, sid);
}

static void test_sidechannels()
{
    uint8_t x[KOP_INPUT_BYTES], y[KOP_INPUT_BYTES], sid[KOP_SID_BYTES];
    kop_pec_state_s alice, bob;
    uint8_t msg0[KOP_PEC_MSG0_BYTES];
    uint8_t msg1[KOP_PEC_MSG1_BYTES];
    uint8_t msg2[KOP_PEC_MSG2_BYTES];
    uint8_t msg3[KOP_PEC_MSG3_BYTES];

    randombytes(x, KOP_INPUT_BYTES);
    randombytes(y, KOP_INPUT_BYTES);
    randombytes(sid, KOP_SID_BYTES);

    poison(x, KOP_INPUT_BYTES);
    poison(y, KOP_INPUT_BYTES);

    kop_pec_set_input(&alice, x);
    kop_pec_set_sid(&alice, sid);
    kop_pec_set_input(&bob, y);
    kop_pec_set_sid(&bob, sid);
    kop_pec_alice_m0(&alice, msg0);
    unpoison(msg0, KOP_PEC_MSG0_BYTES);
    kop_pec_bob_m1(&bob, msg1, msg0);
    unpoison(msg1, KOP_PEC_MSG1_BYTES);
    kop_pec_alice_m2(&alice, msg2, msg1);
    unpoison(msg2, KOP_PEC_MSG2_BYTES);
    kop_pec_bob_m3(&bob, msg3, msg2);
    unpoison(msg3, KOP_PEC_MSG3_BYTES);
    kop_pec_alice_accept(&alice, msg3);
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

    test_sidechannels();

    return EXIT_SUCCESS;
}

