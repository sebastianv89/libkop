#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "pet.h"
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
    kop_pet_state_s alice, bob;
    kop_pet_msg0_s msg0;
    kop_pet_msg1_s msg1;
    kop_pet_msg2_s msg2;
    kop_pet_msg3_s msg3;
    int expected = 1 - verify(x, y, KOP_INPUT_BYTES);

    kop_pet_init(&alice, x, sid);
    kop_pet_init(&bob, y, sid);

    res = kop_pet_alice_m0(&alice, &msg0);
    assert(res == KOP_RESULT_OK);
    res = kop_pet_bob_m1(&bob, &msg1, &msg0);
    assert(res == KOP_RESULT_OK);
    res = kop_pet_alice_m2(&alice, &msg2, &msg1);
    assert(res == KOP_RESULT_OK);
    res = kop_pet_bob_m3(&bob, &msg3, &msg2);
    if (expected == 1) {
        assert(res == KOP_RESULT_OK);
    } else {
        assert(res == KOP_RESULT_ABORT);
    }
    // This last message should only be sent if Bob accepted.
    // If he does not, Alice should still reject his message.
    res = kop_pet_alice_accept(&alice, &msg3);
    if (expected == 1) {
        assert(res == KOP_RESULT_OK);
    } else {
        assert(res == KOP_RESULT_ABORT);
    }
}

static void test_pet()
{
    uint8_t x[KOP_INPUT_BYTES], y[KOP_INPUT_BYTES], sid[KOP_SID_BYTES];

    randombytes(x, KOP_INPUT_BYTES);
    randombytes(y, KOP_INPUT_BYTES);
    randombytes(sid, KOP_SID_BYTES);

    test_with_input(x, x, sid);
    test_with_input(x, y, sid);
}

static void print_sizes()
{
    printf("%s, N=%u, σ=%u\n", XSTR(KOP_KEM_ALG), KOP_OT_N, KOP_SIGMA);
    printf("M0, A -> B: %8u bytes (σN public keys)\n", KOP_PET_MSG0_BYTES);
    printf("M1, B -> A: %8u bytes (σN (ciphertexts + public keys))\n", KOP_PET_MSG1_BYTES);
    printf("M2, A -> B: %8u bytes (encoding + σN ciphertexts))\n", KOP_PET_MSG2_BYTES);
    printf("M3, B -> A: %8u bytes (encoding)\n", KOP_PET_MSG3_BYTES);
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
        test_pet();
    }

    return EXIT_SUCCESS;
}

