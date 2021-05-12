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

static void measure_timing()
{
    uint8_t sid[KOP_SID_BYTES];

    uint8_t a_x[KOP_INPUT_BYTES];
    uint8_t a_sks[KOP_INPUT_WORDS * KOP_SK_BYTES];
    uint8_t a_x_a[KOP_PRF_BYTES];

    uint8_t b_y[KOP_INPUT_BYTES];
    uint8_t b_sks[KOP_INPUT_WORDS * KOP_SK_BYTES];
    uint8_t b_y_b[KOP_INPUT_WORDS * KOP_SK_BYTES];

    uint8_t m0[KOP_PET_MSG0_BYTES];
    uint8_t m1[KOP_PET_MSG1_BYTES];
    uint8_t m2[KOP_PET_MSG2_BYTES];
    uint8_t m3[KOP_PET_MSG3_BYTES];

    hid_t hid;

    uint8_t ot_sk[KOP_SK_BYTES];
    uint8_t ot_ss[KOP_SS_BYTES];
    uint8_t ot_pks[KOP_OT_N * KOP_PK_BYTES];
    uint8_t ot_sss[KOP_OT_N * KOP_SS_BYTES];
    uint8_t ot_cts[KOP_OT_N * KOP_CT_BYTES];
    uint8_t ot_index = 0;

    uint8_t a[KOP_PK_BYTES];
    uint8_t b[KOP_PK_BYTES];
    uint8_t pks[(KOP_OT_N-1) * KOP_PK_BYTES];
    const uint8_t *pks_pointers[KOP_OT_N - 1];

    uint8_t prf_out[KOP_PRF_BYTES];
    uint8_t prf_in[KOP_SS_BYTES + KOP_INPUT_BYTES];

    size_t j;

    randombytes(sid, KOP_SID_BYTES);
    memcpy(&(hid.sid), sid, KOP_SID_BYTES);
    randombytes(a_x, KOP_INPUT_BYTES);
    for (j = 0; j < KOP_INPUT_BYTES; j++) {
        b_y[j] = a_x[j];
    }
    random_pk(a);
    random_pk(b);
    for (j = 0; j < KOP_OT_N - 1; j++) {
        random_pk(&pks[j * KOP_PK_BYTES]);
        pks_pointers[j] = &pks[j * KOP_PK_BYTES];
    }
    randombytes(prf_in, KOP_SS_BYTES + KOP_INPUT_BYTES);

    PRINT_TIMER_HEADER
    TIME_OPERATION_ITERATIONS(pet_alice_m0(a_sks, m0, a_x, sid), "pet_alice_m0", 1000)
    TIME_OPERATION_ITERATIONS(pet_bob_m1(b_y_b, b_sks, m1, m0, b_y, sid), "pet_bob_m1", 300)
    TIME_OPERATION_ITERATIONS(pet_alice_m2(a_x_a, m2, m1, a_sks, a_x, sid), "pet_alice_m2", 300)
    TIME_OPERATION_ITERATIONS(pet_bob_m3(m3, m2, b_sks, b_y, b_y_b), "pet_bob_m3", 1000)
    TIME_OPERATION_ITERATIONS(pet_alice_accept(m3, a_x_a), "pet_alice_accept", 1000)

    TIME_OPERATION_ITERATIONS(kemot_receiver_init(ot_sk, ot_pks, ot_index, &hid), "ot_recv_init", 1000)
    TIME_OPERATION_ITERATIONS(kemot_sender(ot_sss, ot_cts, ot_pks, &hid), "ot_send", 1000)
    TIME_OPERATION_ITERATIONS(kemot_receiver_output(ot_ss, ot_cts, ot_sk, ot_index), "ot_recv_out", 1000)

    TIME_OPERATION_ITERATIONS(add_pk(a, a, b), "add_pk", 1000)
    TIME_OPERATION_ITERATIONS(sub_pk(a, a, b), "sub_pk", 1000)
    TIME_OPERATION_ITERATIONS(random_pk(a), "random_pk", 1000)
    TIME_OPERATION_ITERATIONS(hash_pks(a, pks_pointers, &hid), "hash_pks", 1000)

    TIME_OPERATION_ITERATIONS(pet_prf(prf_out, prf_in), "pet_prf", 1000)
    PRINT_TIMER_FOOTER
}


int main()
{
    measure_timing();
}

