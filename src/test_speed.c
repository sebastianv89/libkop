#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "group.h"
#include "ec.h"
#include "pq.h"
#include "kem.h"
#include "ot.h"
#include "pet.h"
#include "params.h"
#include "randombytes.h"

#include "ds_benchmark.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static void measure_ec_validation(float seconds) {
    uint8_t buf[DECAF_448_SER_BYTES];
    decaf_448_point_t p;
    decaf_error_t err;

    printf("  Decaf decoding (validating)\n");
    randombytes(buf, sizeof(buf));

    TIME_OPERATION_SECONDS(err = decaf_448_point_decode(p, buf, DECAF_FALSE), "decode", seconds)
    (void)err; // hide "err unused" warning
}

static void measure_group_ec(float seconds) {
    uint8_t seed[2 * DECAF_448_HASH_BYTES];
    kop_ec_pk_s a, b;

    randombytes(seed, sizeof(seed));
    kop_ec_gen_pk(&a, seed);
    kop_ec_gen_pk(&b, seed);

    printf("  group EC\n");

    TIME_OPERATION_SECONDS(kop_ec_add_pk(&a, &a, &b), "add", seconds)
    TIME_OPERATION_SECONDS(kop_ec_sub_pk(&a, &a, &b), "sub", seconds)
    TIME_OPERATION_SECONDS(kop_ec_gen_pk(&a, seed), "gen", seconds)
}

static void measure_group_pq(float seconds) {
    uint8_t seed[KOP_KYBER_SYMBYTES], rho[KOP_KYBER_SYMBYTES];
    uint8_t a[KOP_PQ_PK_BYTES], b[KOP_PQ_PK_BYTES];

    randombytes(seed, sizeof(seed));
    randombytes(rho, sizeof(rho));
    kop_pq_gen_pk(a, seed, rho);
    kop_pq_gen_pk(b, seed, rho);

    printf("  group PQ\n");

    TIME_OPERATION_SECONDS(kop_pq_add_pk(a, a, b), "add", seconds)
    TIME_OPERATION_SECONDS(kop_pq_sub_pk(a, a, b), "sub", seconds)
    TIME_OPERATION_SECONDS(kop_pq_gen_pk(a, seed, rho), "gen", seconds)
}

static void measure_group(float seconds) {
    kop_kem_pk_s a, b, pk;
    uint8_t rho[KOP_KYBER_SYMBYTES];
    uint8_t pks_serialized[(KOP_OT_N - 1) * KOP_KEM_PK_BYTES];
    const uint8_t * pk_pointers[KOP_OT_N - 1];
    size_t j;
    hid_t hid;

    randombytes(rho, sizeof(rho));
    for (j = 0; j < KOP_OT_N - 1; j++) {
        kop_random_pk(&pk, rho);
        kop_kem_pk_serialize(&pks_serialized[j * KOP_KEM_PK_BYTES], &pk);
        pk_pointers[j] = &pks_serialized[j * KOP_KEM_PK_BYTES];
    }
    kop_random_pk(&a, rho);
    kop_random_pk(&b, rho);
    randombytes(hid.sid, KOP_SID_BYTES);
    hid.oenc = 0;
    hid.ot = 0;
    hid.kem = 0;

    printf("  group\n");

    TIME_OPERATION_SECONDS(kop_add_pk(&a, &a, &b), "add", seconds)
    TIME_OPERATION_SECONDS(kop_sub_pk(&a, &a, &b), "sub", seconds)
    TIME_OPERATION_SECONDS(kop_random_pk(&a, rho), "random", seconds)
    TIME_OPERATION_SECONDS(kop_hash_pks(&a, pk_pointers, rho, hid), "hash", seconds)
}

static void measure_kem_ec(float seconds)
{
    kop_ec_pk_s pk;
    kop_ec_sk_s sk;
    uint8_t ct[KOP_EC_CT_BYTES], ss[KOP_EC_SS_BYTES];

    printf("  KEM EC: ECIES Decaf448\n");

    TIME_OPERATION_SECONDS(kop_ec_keygen(&pk, &sk), "keygen", seconds)
    TIME_OPERATION_SECONDS(kop_ec_encaps(ct, ss, &pk), "encaps", seconds)
    TIME_OPERATION_SECONDS(kop_ec_decaps(ss, ct, &sk), "decaps", seconds)
}

static void measure_kem_pq(float seconds)
{
    uint8_t pk[KOP_PQ_PK_BYTES];
    uint8_t sk[KOP_PQ_SK_BYTES];
    uint8_t ct[KOP_PQ_CT_BYTES];
    uint8_t ss[KOP_PQ_SS_BYTES];

    printf("  KEM PQ: %s\n", XSTR(KOP_KEM_ALG));

    TIME_OPERATION_SECONDS(kop_pq_keygen(pk, sk), "keygen", seconds)
    TIME_OPERATION_SECONDS(kop_pq_encaps(ct, ss, pk), "encaps", seconds)
    TIME_OPERATION_SECONDS(kop_pq_decaps(ss, ct, sk), "decaps", seconds)
}

static void measure_kem(float seconds)
{
    kop_kem_pk_s pk;
    kop_kem_sk_s sk;
    uint8_t ct[KOP_KEM_CT_BYTES];
    kop_kem_ss_s ss;

    printf("  KEM\n");

    TIME_OPERATION_SECONDS(kop_kem_keygen(&pk, &sk), "keygen", seconds)
    TIME_OPERATION_SECONDS(kop_kem_encaps(ct, &ss, &pk), "encaps", seconds)
    TIME_OPERATION_SECONDS(kop_kem_decaps(&ss, ct, &sk), "decaps", seconds)
}


static void measure_ot(float seconds)
{
    kop_kem_ss_s secret, secrets[KOP_OT_N];
    kop_ot_recv_s recv;
    uint8_t recv_msg[KOP_OT_MSG0_BYTES];
    uint8_t send_msg[KOP_OT_MSG1_BYTES];
    kop_ot_index_t index;
    hid_t hid;

    randombytes(hid.sid, KOP_SID_BYTES);
    hid.oenc = 0;
    hid.ot = 0;
    index = 0;

    printf("  OT: %s, N=%u\n", XSTR(KOP_KEM_ALG), KOP_OT_N);

    TIME_OPERATION_SECONDS(kop_ot_recv_init(&recv, recv_msg, index, hid), "recv init", seconds)
    TIME_OPERATION_SECONDS(kop_ot_send(secrets, send_msg, recv_msg, hid), "send", seconds)
    TIME_OPERATION_SECONDS(kop_ot_recv_out(&secret, send_msg, &recv), "recv out", seconds)
}

static void measure_pet(float seconds)
{
    uint8_t sid[KOP_SID_BYTES], input[KOP_INPUT_BYTES];
    kop_pet_state_s alice, bob;
    uint8_t msg0[KOP_PET_MSG0_BYTES];
    uint8_t msg1[KOP_PET_MSG1_BYTES];
    uint8_t msg2[KOP_PET_MSG2_BYTES];
    uint8_t msg3[KOP_PET_MSG3_BYTES];

    randombytes(sid, KOP_SID_BYTES);
    randombytes(input, KOP_INPUT_BYTES);
    kop_pet_init(&bob, input, sid);

    printf("  PET: %s, N=%u, σ=%u\n", XSTR(KOP_KEM_ALG), KOP_OT_N, KOP_SIGMA);

    TIME_OPERATION_SECONDS(kop_pet_init(&alice, input, sid), "init", seconds)
    TIME_OPERATION_SECONDS(kop_pet_alice_m0(&alice, msg0), "alice m0", seconds)
    TIME_OPERATION_SECONDS(kop_pet_bob_m1(&bob, msg1, msg0), "bob m1", seconds)
    TIME_OPERATION_SECONDS(kop_pet_alice_m2(&alice, msg2, msg1), "alice m2", seconds)
    TIME_OPERATION_SECONDS(kop_pet_bob_m3(&bob, msg3, msg2), "bob m3", seconds)
    TIME_OPERATION_SECONDS(kop_pet_alice_accept(&alice, msg3), "alice accept", seconds)
}


int main(int argc, char *argv[])
{
    float seconds = 1.5;

    if (argc >= 2) {
        seconds = atof(argv[1]);
        if (seconds == 0.0) {
            fprintf(stderr, "Usage: %s [nr_of_tests]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    PRINT_TIMER_HEADER
    measure_ec_validation(seconds);
    measure_group_ec(seconds);
    measure_group_pq(seconds);
    measure_group(seconds);
    measure_kem_ec(seconds);
    measure_kem_pq(seconds);
    measure_kem(seconds);
    measure_ot(seconds);
    measure_pet(seconds);
    PRINT_TIMER_FOOTER

    return EXIT_SUCCESS;
}

