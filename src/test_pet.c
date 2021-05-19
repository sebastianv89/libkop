#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "pet.h"
#include "params.h"
#include "randombytes.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static void test_pet()
{
    kop_pet_state_s alice, bob;
    kop_pet_msg0_s msg0;
    kop_pet_msg1_s msg1;
    kop_pet_msg2_s msg2;
    kop_pet_msg3_s msg3;
    uint8_t x[KOP_INPUT_BYTES], y[KOP_INPUT_BYTES], sid[KOP_SID_BYTES];
    int alice_accept, bob_accept;

    randombytes(x, KOP_INPUT_BYTES);
    randombytes(sid, KOP_SID_BYTES);
    randombytes(y, KOP_INPUT_BYTES);

    // different input
    kop_pet_init(&alice, x, sid);
    kop_pet_init(&bob, y, sid);

    kop_pet_alice_m0(&alice, &msg0);
    kop_pet_bob_m1(&bob, &msg1, &msg0);
    kop_pet_alice_m2(&alice, &msg2, &msg1);
    bob_accept = kop_pet_bob_m3(&bob, &msg3, &msg2);
    assert(bob_accept == 0); // Bob should abort, but sending msg3 won't break security
    alice_accept = kop_pet_alice_accept(&alice, &msg3);
    assert(alice_accept == 0);

    // same input
    kop_pet_init(&alice, x, sid);
    kop_pet_init(&bob, x, sid);

    kop_pet_alice_m0(&alice, &msg0);
    kop_pet_bob_m1(&bob, &msg1, &msg0);
    kop_pet_alice_m2(&alice, &msg2, &msg1);
    bob_accept = kop_pet_bob_m3(&bob, &msg3, &msg2);
    assert(bob_accept == 1);
    alice_accept = kop_pet_alice_accept(&alice, &msg3);
    assert(alice_accept == 1);
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

