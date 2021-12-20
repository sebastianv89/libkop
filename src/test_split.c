#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <oqs/oqs.h>

#include "poison.h"

#include "split.h"
#include "common.h"
#include "params.h"
#include "randombytes.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static void test_split()
{
    kop_result_e res;
    kop_split_state_s alice, bob;
    uint8_t x[KOP_INPUT_BYTES], y[KOP_INPUT_BYTES];
    uint8_t msg0[KOP_SPLIT_MSG0_BYTES];
    uint8_t msg1[KOP_SPLIT_MSG1_BYTES];
    uint8_t msg2[KOP_SPLIT_MSG2_BYTES];
    uint8_t msg3[KOP_SPLIT_MSG3_BYTES];
    uint8_t msg4[KOP_SPLIT_MSG4_BYTES];
    uint8_t msg5[KOP_SPLIT_MSG5_BYTES];

    randombytes(x, KOP_INPUT_BYTES);
    memcpy(y, x, KOP_INPUT_BYTES);

    // honest run with equal input
    kop_split_init(&alice, x);
    kop_split_init(&bob, y);
    kop_split_alice0(&alice, msg0);
    kop_split_bob1(&bob, msg1, msg0);
    res = kop_split_alice2(&alice, msg2, msg1);
    assert(res == KOP_RESULT_OK);
    res = kop_split_bob3(&bob, msg3, msg2);
    assert(res == KOP_RESULT_OK);
    res = kop_split_alice4(&alice, msg4, msg3);
    assert(res == KOP_RESULT_OK);
    res = kop_split_bob5(&bob, msg5, msg4);
    assert(res == KOP_RESULT_OK);
    assert(kop_split_accepted(&bob));
    res = kop_split_alice6(&alice, msg5);
    assert(res == KOP_RESULT_OK);
    assert(kop_split_accepted(&alice));
    
    // detect tampering in msg/signature
    kop_split_init(&alice, x);
    kop_split_init(&bob, y);
    kop_split_alice0(&alice, msg0);
    kop_split_bob1(&bob, msg1, msg0);
    res = kop_split_alice2(&alice, msg2, msg1);
    assert(res == KOP_RESULT_OK);
    msg2[1] ^= 1;
    res = kop_split_bob3(&bob, msg3, msg2);
    assert(res == KOP_RESULT_ERROR);
}    

static void test_sidechannels()
{
    uint8_t x[KOP_INPUT_BYTES], y[KOP_INPUT_BYTES];
    kop_split_state_s alice, bob;
    uint8_t msg0[KOP_SPLIT_MSG0_BYTES];
    uint8_t msg1[KOP_SPLIT_MSG1_BYTES];
    uint8_t msg2[KOP_SPLIT_MSG2_BYTES];
    uint8_t msg3[KOP_SPLIT_MSG3_BYTES];
    uint8_t msg4[KOP_SPLIT_MSG4_BYTES];
    uint8_t msg5[KOP_SPLIT_MSG5_BYTES];

    randombytes(x, KOP_INPUT_BYTES);
    randombytes(y, KOP_INPUT_BYTES);

    poison(x, KOP_INPUT_BYTES);
    poison(y, KOP_INPUT_BYTES);

    kop_split_init(&alice, x);
    kop_split_init(&bob, y);
    poison(alice.sk, KOP_SPLIT_SK_BYTES);
    poison(bob.sk, KOP_SPLIT_SK_BYTES);

    kop_split_alice0(&alice, msg0);
    unpoison(msg0, KOP_SPLIT_MSG0_BYTES);
    kop_split_bob1(&bob, msg1, msg0);
    unpoison(msg1, KOP_SPLIT_MSG1_BYTES);
    kop_split_alice2(&alice, msg2, msg1);
    unpoison(msg2, KOP_SPLIT_MSG2_BYTES);
    kop_split_bob3(&bob, msg3, msg2);
    unpoison(msg3, KOP_SPLIT_MSG3_BYTES);
    kop_split_alice4(&alice, msg4, msg3);
    unpoison(msg4, KOP_SPLIT_MSG4_BYTES);
    kop_split_bob5(&bob, msg5, msg4);
    unpoison(msg5, KOP_SPLIT_MSG5_BYTES);
    kop_split_alice6(&alice, msg5);
}

static void print_sizes()
{
    printf("%s, M=%u, N=%u\n", XSTR(KOP_PQ_ALG), KOP_OT_M, KOP_PEC_N);
    printf("M0: %8u bytes (local overhead)\n", KOP_SPLIT_MSG0_BYTES);
    printf("M1: %8u bytes (local overhead)\n", KOP_SPLIT_MSG1_BYTES);
    printf("M2: %8u bytes (local overhead)\n", KOP_SPLIT_MSG2_BYTES);
    printf("M3: %8u bytes (local overhead)\n", KOP_SPLIT_MSG3_BYTES);
    printf("M4: %8u bytes (local overhead)\n", KOP_SPLIT_MSG4_BYTES);
    printf("M5: %8u bytes (local overhead)\n", KOP_SPLIT_MSG5_BYTES);
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
        test_split();
    }

    test_sidechannels();

    return EXIT_SUCCESS;
}

