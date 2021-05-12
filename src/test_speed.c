#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "group.h"
#include "ot.h"
#include "pet.h"
#include "params.h"
#include "randombytes.h"

#include "ds_benchmark.h"

static void measure_timing()
{
    uint8_t a_x[PET_INPUT_BYTES];
    uint8_t a_sks[PET_SIGMA * SK_BYTES];
    uint8_t a_x_a[PET_LAMBDA];

    uint8_t b_y[PET_INPUT_BYTES];
    uint8_t b_sks[PET_SIGMA * SK_BYTES];
    uint8_t b_y_b[PET_SIGMA * SK_BYTES];

    uint8_t m0[PET_SIGMA * OTKEM_N * PK_BYTES];
    uint8_t m1[PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES)];
    uint8_t m2[PET_LAMBDA + PET_SIGMA * OTKEM_N * CT_BYTES];
    uint8_t m3[PET_LAMBDA];

    uint8_t ot_sk[SK_BYTES];
    uint8_t ot_ss[SS_BYTES];
    uint8_t ot_pks[OTKEM_N * PK_BYTES];
    uint8_t ot_sss[OTKEM_N * SS_BYTES];
    uint8_t ot_cts[OTKEM_N * CT_BYTES];
    uint8_t ot_sid[SID_BYTES] = {0};
    uint8_t ot_index = 0;

    uint8_t a[PK_BYTES];
    uint8_t b[PK_BYTES];
    uint8_t pks[(OTKEM_N-1) * PK_BYTES];
    const uint8_t *pks_pointers[OTKEM_N - 1];
    uint8_t hid[HID_BYTES] = {0};

    uint8_t prf_out[PET_LAMBDA];
    uint8_t prf_in[SS_BYTES + PET_INPUT_BYTES];

    size_t j;

    randombytes(a_x, PET_INPUT_BYTES);
    for (j = 0; j < PET_INPUT_BYTES; j++) {
        b_y[j] = a_x[j];
    }
    random_pk(a);
    random_pk(b);
    for (j = 0; j < OTKEM_N - 1; j++) {
        random_pk(&pks[j * PK_BYTES]);
        pks_pointers[j] = &pks[j * PK_BYTES];
    }
    randombytes(prf_in, SS_BYTES + PET_INPUT_BYTES);

    PRINT_TIMER_HEADER
    TIME_OPERATION_ITERATIONS(pet_alice_m0(a_sks, m0, a_x), "pet_alice_m0", 1000)
    TIME_OPERATION_ITERATIONS(pet_bob_m1(b_y_b, b_sks, m1, m0, b_y), "pet_bob_m1", 1000)
    TIME_OPERATION_ITERATIONS(pet_alice_m2(a_x_a, m2, m1, a_sks, a_x), "pet_alice_m2", 1000)
    TIME_OPERATION_ITERATIONS(pet_bob_m3(m3, m2, b_sks, b_y, b_y_b), "pet_bob_m3", 1000)
    TIME_OPERATION_ITERATIONS(pet_alice_accept(m3, a_x_a), "pet_alice_accept", 1000)

    TIME_OPERATION_ITERATIONS(kemot_receiver_init(ot_sk, ot_pks, ot_index, ot_sid), "ot_recv_init", 1000)
    TIME_OPERATION_ITERATIONS(kemot_sender(ot_sss, ot_cts, ot_pks, ot_sid), "ot_send", 1000)
    TIME_OPERATION_ITERATIONS(kemot_receiver_output(ot_ss, ot_cts, ot_sk, ot_index), "ot_recv_out", 1000)

    TIME_OPERATION_ITERATIONS(add_pk(a, a, b), "add_pk", 1000)
    TIME_OPERATION_ITERATIONS(sub_pk(a, a, b), "sub_pk", 1000)
    TIME_OPERATION_ITERATIONS(random_pk(a), "random_pk", 1000)
    TIME_OPERATION_ITERATIONS(hash_pks(a, pks_pointers, hid), "hash_pks", 1000)

    TIME_OPERATION_ITERATIONS(pet_prf(prf_out, prf_in), "pet_prf", 1000)
    PRINT_TIMER_FOOTER
}


int main()
{
    measure_timing();
}

