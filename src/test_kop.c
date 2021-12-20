#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <oqs/oqs.h>

#include "poison.h"

#include "kop.h"
#include "common.h"
#include "params.h"
#include "randombytes.h"

#define XSTR(s) STR(s)
#define STR(s) #s
#define MAX(a,b) ((a) > (b) ? (a) : (b))

static void test_kop()
{
    kop_result_e res;
    kop_state_s alice, bob;
    uint8_t x[KOP_INPUT_BYTES], y[KOP_INPUT_BYTES];
    uint8_t msg[MAX(MAX(MAX(
        KOP_SPLIT_MSG0_BYTES,
        KOP_SPLIT_MSG1_BYTES), MAX(
        KOP_SPLIT_MSG2_BYTES,
        KOP_SPLIT_MSG3_BYTES)), MAX(
        KOP_SPLIT_MSG4_BYTES,
        KOP_SPLIT_MSG5_BYTES))];
    size_t msg_bytes;

    randombytes(x, KOP_INPUT_BYTES);
    memcpy(y, x, KOP_INPUT_BYTES);

    // honest run with equal input
    kop_init(&alice, x);
    kop_init(&bob, y);
    res = kop_msg0(&alice, msg);
    assert(res == KOP_RESULT_OK);
    res = kop_process_msg(&bob, msg, &msg_bytes, msg, KOP_MSG0_BYTES);
    assert(res == KOP_RESULT_OK);
    assert(msg_bytes == KOP_MSG1_BYTES);
    res = kop_process_msg(&alice, msg, &msg_bytes, msg, KOP_MSG1_BYTES);
    assert(res == KOP_RESULT_OK);
    assert(msg_bytes == KOP_MSG2_BYTES);
    res = kop_process_msg(&bob, msg, &msg_bytes, msg, KOP_MSG2_BYTES);
    assert(res == KOP_RESULT_OK);
    assert(msg_bytes == KOP_MSG3_BYTES);
    res = kop_process_msg(&alice, msg, &msg_bytes, msg, KOP_MSG3_BYTES);
    assert(res == KOP_RESULT_OK);
    assert(msg_bytes == KOP_MSG4_BYTES);
    res = kop_process_msg(&bob, msg, &msg_bytes, msg, KOP_MSG4_BYTES);
    assert(res == KOP_RESULT_OK); // Bob accepts
    assert(msg_bytes == KOP_MSG5_BYTES);
    res = kop_process_msg(&alice, NULL, &msg_bytes, msg, KOP_MSG5_BYTES);
    assert(res == KOP_RESULT_OK); // Alice accepts
    assert(msg_bytes == 0);

    // honest run with unequal input
    randombytes(y, KOP_INPUT_BYTES);
    kop_init(&alice, x);
    kop_init(&bob, y);
    res = kop_msg0(&alice, msg);
    assert(res == KOP_RESULT_OK);
    res = kop_process_msg(&bob, msg, &msg_bytes, msg, KOP_MSG0_BYTES);
    assert(res == KOP_RESULT_OK);
    assert(msg_bytes == KOP_MSG1_BYTES);
    res = kop_process_msg(&alice, msg, &msg_bytes, msg, KOP_MSG1_BYTES);
    assert(res == KOP_RESULT_OK);
    assert(msg_bytes == KOP_MSG2_BYTES);
    res = kop_process_msg(&bob, msg, &msg_bytes, msg, KOP_MSG2_BYTES);
    assert(res == KOP_RESULT_OK);
    assert(msg_bytes == KOP_MSG3_BYTES);
    res = kop_process_msg(&alice, msg, &msg_bytes, msg, KOP_MSG3_BYTES);
    assert(res == KOP_RESULT_OK);
    assert(msg_bytes == KOP_MSG4_BYTES);
    res = kop_process_msg(&bob, msg, &msg_bytes, msg, KOP_MSG4_BYTES);
    assert(res == KOP_RESULT_ERROR); // Bob rejects 
    assert(!kop_has_aborted(&bob));
    assert(msg_bytes == KOP_MSG5_BYTES);
    res = kop_process_msg(&alice, NULL, &msg_bytes, msg, KOP_MSG5_BYTES);
    assert(res == KOP_RESULT_ERROR); // Alice rejects
    assert(!kop_has_aborted(&alice));
    assert(msg_bytes == 0);
}

static void test_sidechannels()
{
    kop_state_s alice, bob;
    uint8_t x[KOP_INPUT_BYTES], y[KOP_INPUT_BYTES];
    uint8_t msg[MAX(MAX(MAX(
        KOP_SPLIT_MSG0_BYTES,
        KOP_SPLIT_MSG1_BYTES), MAX(
        KOP_SPLIT_MSG2_BYTES,
        KOP_SPLIT_MSG3_BYTES)), MAX(
        KOP_SPLIT_MSG4_BYTES,
        KOP_SPLIT_MSG5_BYTES))];
    size_t msg_bytes;

    randombytes(x, KOP_INPUT_BYTES);
    randombytes(y, KOP_INPUT_BYTES);

    poison(x, KOP_INPUT_BYTES);
    poison(y, KOP_INPUT_BYTES);

    kop_init(&alice, x);
    kop_init(&bob, y);
    poison(alice.split.sk, KOP_SPLIT_SK_BYTES);
    poison(bob.split.sk, KOP_SPLIT_SK_BYTES);

    kop_init(&alice, x);
    kop_init(&bob, y);
    kop_msg0(&alice, msg);
    unpoison(msg, KOP_SPLIT_MSG0_BYTES);
    kop_process_msg(&bob, msg, &msg_bytes, msg, KOP_MSG0_BYTES);
    unpoison(msg, KOP_SPLIT_MSG1_BYTES);
    kop_process_msg(&alice, msg, &msg_bytes, msg, KOP_MSG1_BYTES);
    unpoison(msg, KOP_SPLIT_MSG2_BYTES);
    kop_process_msg(&bob, msg, &msg_bytes, msg, KOP_MSG2_BYTES);
    unpoison(msg, KOP_SPLIT_MSG3_BYTES);
    kop_process_msg(&alice, msg, &msg_bytes, msg, KOP_MSG3_BYTES);
    unpoison(msg, KOP_SPLIT_MSG4_BYTES);
    kop_process_msg(&bob, msg, &msg_bytes, msg, KOP_MSG4_BYTES);
    unpoison(msg, KOP_SPLIT_MSG5_BYTES);
    kop_process_msg(&alice, NULL, &msg_bytes, msg, KOP_MSG5_BYTES);
}

static void print_sizes()
{
    printf("%s, %s, M=%u, N=%u\n", XSTR(KOP_PQ_ALG), XSTR(KOP_SPLIT_ALG), KOP_OT_M, KOP_PEC_N);
    printf("M0, A -> B: %8u bytes (tag + public verification key)\n", KOP_MSG0_BYTES);
    printf("M1, B -> A: %8u bytes (tag + signature + public verification key)\n", KOP_MSG1_BYTES);
    printf("M2, A -> B: %8u bytes (tag + PEC msg0 + signature)\n", KOP_MSG2_BYTES);
    printf("M3, B -> A: %8u bytes (tag + PEC msg1 + signature)\n", KOP_MSG3_BYTES);
    printf("M4, A -> B: %8u bytes (tag + PEC msg2 + signature)\n", KOP_MSG4_BYTES);
    printf("M5, B -> A: %8u bytes (tag + PEC msg3 + signature)\n", KOP_MSG5_BYTES);
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
        test_kop();
    }

    test_sidechannels();

    return EXIT_SUCCESS;
}

