#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "pet.h"
#include "params.h"
#include "randombytes.h"

static int test_with_inputs(const uint8_t a_x[PET_INPUT_BYTES], const uint8_t b_y[PET_INPUT_BYTES])
{
    uint8_t a_sks[PET_SIGMA * SK_BYTES];
    uint8_t a_x_a[PET_LAMBDA];

    uint8_t b_sks[PET_SIGMA * SK_BYTES];
    uint8_t b_y_b[PET_SIGMA * SK_BYTES];

    uint8_t m0[PET_SIGMA * OTKEM_N * PK_BYTES];
    uint8_t m1[PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES)];
    uint8_t m2[PET_LAMBDA + PET_SIGMA * OTKEM_N * CT_BYTES];
    uint8_t m3[PET_LAMBDA];

    int alice, bob;

    // execute PET
    pet_alice_m0(a_sks, m0, a_x);
    pet_bob_m1(b_y_b, b_sks, m1, m0, b_y);
    pet_alice_m2(a_x_a, m2, m1, a_sks, a_x);
    bob = pet_bob_m3(m3, m2, b_sks, b_y, b_y_b);
    if (!bob) {
        return 0;
    }
    alice = pet_alice_accept(m3, a_x_a);
    if (!alice) {
        fprintf(stderr, "Alice did not accept while Bob did\n");
        return 0;
    }
    return 1;
}

static void example_same_input()
{
    uint8_t x[PET_INPUT_BYTES];
    randombytes(x, PET_INPUT_BYTES);
    assert(test_with_inputs(x, x));
}

static void example_different_input()
{
    uint8_t x[PET_INPUT_BYTES];
    uint8_t y[PET_INPUT_BYTES];
    randombytes(x, PET_INPUT_BYTES);
    randombytes(y, PET_INPUT_BYTES);
    assert(!test_with_inputs(x, y));
}

// Kyber768, σ=40, N=4
// M0, A -> B:   189440 bytes (185 KiB) (σN public keys)
// M1, B -> A:   363520 bytes (355 KiB) (σN (ciphertext + public key))
// M2, A -> B:   174112 bytes (170 KiB) (encoding + σN ciphertexts))
// M3, B -> A:       32 bytes           (encoding)
static void print_sizes()
{
    printf("Kyber768, σ=%u, N=%u\n", PET_SIGMA, OTKEM_N);
    printf("M0, A -> B: %8u bytes (σN public keys)\n", PET_SIGMA * OTKEM_N * PK_BYTES);
    printf("M1, B -> A: %8u bytes (σN (ciphertext + public key))\n", PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES));
    printf("M2, A -> B: %8u bytes (encoding + σN ciphertexts))\n", PET_LAMBDA + PET_SIGMA * OTKEM_N * CT_BYTES);
    printf("M3, B -> A: %8u bytes (encoding)\n", PET_LAMBDA);
}

int main()
{
    print_sizes();
    for (size_t i = 0; i < 100; i++) {
        example_same_input();
        example_different_input();
    }
}

