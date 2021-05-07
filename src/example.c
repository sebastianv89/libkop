#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "pet.h"
#include "params.h"
#include "randombytes.h"

#include "ds_benchmark.h"

static void example_same_input()
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

    size_t i;
    int alice, bob;

    // generate same input
    randombytes(a_x, PET_INPUT_BYTES);
    for (i = 0; i < PET_INPUT_BYTES; i++) {
        b_y[i] = a_x[i];
    }

    // execute PET
    pet_alice_m0(a_sks, m0, a_x);
    pet_bob_m1(b_y_b, b_sks, m1, m0, b_y);
    pet_alice_m2(a_x_a, m2, m1, a_sks, a_x);
    bob = pet_bob_m3(m3, m2, b_sks, b_y, b_y_b);
    if (!bob) {
        fprintf(stderr, "Bob did not accept\n");
        exit(EXIT_FAILURE);
    }
    alice = pet_alice_accept(m3, a_x_a);
    if (!alice) {
        fprintf(stderr, "Alice did not accept\n");
        exit(EXIT_FAILURE);
    }
}

static void example_different_input()
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

    int bob;

    // generate different input
    randombytes(a_x, PET_INPUT_BYTES);
    randombytes(b_y, PET_INPUT_BYTES);

    // execute PET
    pet_alice_m0(a_sks, m0, a_x);
    pet_bob_m1(b_y_b, b_sks, m1, m0, b_y);
    pet_alice_m2(a_x_a, m2, m1, a_sks, a_x);
    bob = pet_bob_m3(m3, m2, b_sks, b_y, b_y_b);
    if (bob) {
        fprintf(stderr, "Bob accepted (but shouldn't have)\n");
        exit(EXIT_FAILURE);
    }
    // Bob should NOT send a message to Alice
}

// Kyber768:
//   (pk, sk, ct) = (1184, 2400, 1088)
// For 80-bit secrets, n=256 (so sigma=10):
//   (m0, m1, m2, m3) = (3_031_040, 5_816_320, 2_785_280, 32)
// For 80-bit secrets, n=16 (so sigma=20):
//   (m0, m1, m2, m3) = (378_880, 727_040, 348_160, 32)
// For 80-bit secrets, n=2 (so sigma=80):
//   (m0, m1, m2, m3) = (189_440, 363_520, 174_080, 32)
// For 80-bit secrets, n=4 (so sigma=40):
//   (m0, m1, m2, m3) = (189_440, 363_520, 174_080, 32)
static void print_sizes()
{
    printf("M0, A -> B: %8d bytes (σN public keys)\n", PET_SIGMA * OTKEM_N * PK_BYTES);
    printf("M1, B -> A: %8d bytes (σN (ciphertext + public key))\n", PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES));
    printf("M2, A -> B: %8d bytes (encoding + σN ciphertexts))\n", 32 + PET_SIGMA * OTKEM_N * CT_BYTES);
    printf("M3, B -> A: %8d bytes (encoding)\n", 32);
}


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
    print_sizes();
    for (size_t i = 0; i < 100; i++) {
        example_same_input();
        example_different_input();
    }
    measure_timing();
}

// M0, A -> B:   189440 bytes (185 KiB) (σN public keys)
// M1, B -> A:   363520 bytes (355 KiB) (σN (ciphertext + public key))
// M2, A -> B:   174112 bytes (170 KiB) (encoding + σN ciphertexts))
// M3, B -> A:       32 bytes           (encoding)
// Started at 2021-05-07 14:11:36
// Operation                      | Iterations | Total time (s) | Time (us): mean | pop. stdev | CPU cycles: mean          | pop. stdev
// ------------------------------ | ----------:| --------------:| ---------------:| ----------:| -------------------------:| ----------:
// pet_alice_m0                   |       1000 |         12.844 |       12843.857 |    760.072 |                  23118696 |    1368104
// pet_bob_m1                     |       1000 |         46.401 |       46401.005 |   1101.628 |                  83521427 |    1982916
// pet_alice_m2                   |       1000 |         36.123 |       36122.741 |     40.635 |                  65020699 |      73092
// pet_bob_m3                     |       1000 |          2.383 |        2383.034 |     15.363 |                   4289077 |      27635
// pet_alice_accept               |       1000 |          0.000 |           0.123 |      0.328 |                        60 |          7
// Ended at 2021-05-07 14:13:14
//
