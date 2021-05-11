#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

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

    size_t j;

    randombytes(a_x, PET_INPUT_BYTES);
    for (j = 0; j < PET_INPUT_BYTES; j++) {
        b_y[j] = a_x[j];
    }

    PRINT_TIMER_HEADER
    TIME_OPERATION_ITERATIONS(pet_alice_m0(a_sks, m0, a_x), "pet_alice_m0", 1000)
    TIME_OPERATION_ITERATIONS(pet_bob_m1(b_y_b, b_sks, m1, m0, b_y), "pet_bob_m1", 1000)
    TIME_OPERATION_ITERATIONS(pet_alice_m2(a_x_a, m2, m1, a_sks, a_x), "pet_alice_m2", 1000)
    TIME_OPERATION_ITERATIONS(pet_bob_m3(m3, m2, b_sks, b_y, b_y_b), "pet_bob_m3", 1000)
    TIME_OPERATION_ITERATIONS(pet_alice_accept(m3, a_x_a), "pet_alice_accept", 1000)
    PRINT_TIMER_FOOTER
}


int main()
{
    measure_timing();
}

