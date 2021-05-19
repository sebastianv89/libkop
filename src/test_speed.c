#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "group.h"
#include "ot.h"
#include "pet.h"
#include "params.h"
#include "randombytes.h"

#include "ds_benchmark.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static void measure_group(int iterations) {
    kop_kem_pk_s a, b, pks[KOP_OT_N - 1];
    const kop_kem_pk_s * pk_pointers[KOP_OT_N - 1];
    size_t j;
    hid_t hid;

    for (j = 0; j < KOP_OT_N - 1; j++) {
        random_pk(&pks[j]);
        pk_pointers[j] = &pks[j];
    }
    random_pk(&a);
    random_pk(&b);
    randombytes(hid.sid, KOP_SID_BYTES);
    hid.oenc = 0;
    hid.ot = 0;
    hid.kem = 0;

    printf("  group: %s, N=%u\n", XSTR(KOP_KEM_ALG), KOP_OT_N);

    TIME_OPERATION_ITERATIONS(add_pk(&a, &a, &b), "add", iterations)
    TIME_OPERATION_ITERATIONS(sub_pk(&a, &a, &b), "sub", iterations)
    TIME_OPERATION_ITERATIONS(random_pk(&a), "random", iterations)
    TIME_OPERATION_ITERATIONS(hash_pks(&a, pk_pointers, hid), "hash", iterations)
}

static void measure_kem(int iterations)
{
    kop_kem_pk_s pk;
    kop_kem_sk_s sk;
    kop_kem_ct_s ct;
    kop_kem_ss_s s0, s1;

    printf("  KEM: %s\n", XSTR(KOP_KEM_ALG));

    TIME_OPERATION_ITERATIONS(kop_kem_keygen(&pk, &sk), "keygen", iterations)
    TIME_OPERATION_ITERATIONS(kop_kem_encaps(&ct, &s0, &pk), "encaps", iterations)
    TIME_OPERATION_ITERATIONS(kop_kem_decaps(&s1, &ct, &sk), "decaps", iterations)
}


static void measure_ot(int iterations)
{
    kop_kem_ss_s secret;
    kop_ot_recv_s recv;
    kop_ot_send_s send;
    kop_ot_recv_msg_s recv_msg;
    kop_ot_send_msg_s send_msg;
    kop_ot_index_t index;
    hid_t hid;

    randombytes(hid.sid, KOP_SID_BYTES);
    hid.oenc = 0;
    hid.ot = 0;
    index = 0;

    printf("  OT: %s, N=%u\n", XSTR(KOP_KEM_ALG), KOP_OT_N);

    TIME_OPERATION_ITERATIONS(kop_ot_recv_init(&recv, &recv_msg, index, hid), "recv init", iterations)
    TIME_OPERATION_ITERATIONS(kop_ot_send(&send, &send_msg, &recv_msg, hid), "send", iterations)
    TIME_OPERATION_ITERATIONS(kop_ot_recv_out(&secret, &send_msg, &recv), "recv out", iterations)
}

static void measure_pet(int iterations)
{
    uint8_t sid[KOP_SID_BYTES], input[KOP_INPUT_BYTES];
    kop_pet_state_s alice, bob;
    kop_pet_msg0_s msg0;
    kop_pet_msg1_s msg1;
    kop_pet_msg2_s msg2;
    kop_pet_msg3_s msg3;

    randombytes(sid, KOP_SID_BYTES);
    randombytes(input, KOP_INPUT_BYTES);
    kop_pet_init(&bob, input, sid);

    printf("  PET: %s, N=%u, σ=%u\n", XSTR(KOP_KEM_ALG), KOP_OT_N, KOP_SIGMA);

    TIME_OPERATION_ITERATIONS(kop_pet_init(&alice, input, sid), "init", iterations)
    TIME_OPERATION_ITERATIONS(kop_pet_alice_m0(&alice, &msg0), "alice m0", iterations)
    TIME_OPERATION_ITERATIONS(kop_pet_bob_m1(&bob, &msg1, &msg0), "bob m1", iterations)
    TIME_OPERATION_ITERATIONS(kop_pet_alice_m2(&alice, &msg2, &msg1), "alice m2", iterations)
    TIME_OPERATION_ITERATIONS(kop_pet_bob_m3(&bob, &msg3, &msg2), "bob m3", iterations)
    TIME_OPERATION_ITERATIONS(kop_pet_alice_accept(&alice, &msg3), "alice accept", iterations)
}


int main(int argc, char *argv[])
{
    int iterations = 1000;

    if (argc >= 2) {
        iterations = atoi(argv[1]);
        if (iterations == 0) {
            fprintf(stderr, "Usage: %s [nr_of_tests]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    PRINT_TIMER_HEADER
    measure_group(iterations);
    measure_kem(iterations);
    measure_ot(iterations);
    measure_pet(iterations);
    PRINT_TIMER_FOOTER

    return EXIT_SUCCESS;
}

