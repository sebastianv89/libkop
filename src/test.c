#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "pet.h"
#include "params.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static int test_with_inputs(const uint8_t a_x[KOP_INPUT_BYTES],
                            const uint8_t b_y[KOP_INPUT_BYTES],
                            const uint8_t sid[KOP_SID_BYTES])
{
    uint8_t a_sks[KOP_INPUT_WORDS * KOP_SK_BYTES];
    uint8_t a_x_a[KOP_PRF_BYTES];

    uint8_t b_sks[KOP_INPUT_WORDS * KOP_SK_BYTES];
    uint8_t b_y_b[KOP_INPUT_WORDS * KOP_SK_BYTES];

    uint8_t m0[KOP_PET_MSG0_BYTES];
    uint8_t m1[KOP_PET_MSG1_BYTES];
    uint8_t m2[KOP_PET_MSG2_BYTES];
    uint8_t m3[KOP_PET_MSG3_BYTES];

    int alice, bob;

    // execute PET
    pet_alice_m0(a_sks, m0, a_x, sid);
    pet_bob_m1(b_y_b, b_sks, m1, m0, b_y, sid);
    pet_alice_m2(a_x_a, m2, m1, a_sks, a_x, sid);
    bob = pet_bob_m3(m3, m2, b_y_b, b_sks, b_y);
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

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

static int test_buffer_overlap(const uint8_t a_x[KOP_INPUT_BYTES],
                               const uint8_t b_y[KOP_INPUT_BYTES],
                               const uint8_t sid[KOP_SID_BYTES]) {
    uint8_t alice[MAX(KOP_INPUT_WORDS * KOP_SK_BYTES, KOP_PRF_BYTES)];
    uint8_t bob[KOP_PRF_BYTES + KOP_INPUT_WORDS * KOP_SK_BYTES];
    uint8_t msg[MAX(MAX(KOP_PET_MSG0_BYTES, KOP_PET_MSG1_BYTES), MAX(KOP_PET_MSG2_BYTES, KOP_PET_MSG3_BYTES))];
    uint8_t *bob_y_b = bob;
    uint8_t *bob_sks = &bob[KOP_PRF_BYTES];
    int a_out, b_out;

    pet_alice_m0(alice, msg, a_x, sid);
    pet_bob_m1(bob_y_b, bob_sks, msg, msg, b_y, sid);
    pet_alice_m2(alice, msg, msg, alice, a_x, sid);
    b_out = pet_bob_m3(msg, msg, bob_y_b, bob_sks, b_y);
    if (!b_out) {
        return 0;
    }
    a_out = pet_alice_accept(msg, alice);
    if (!a_out) {
        fprintf(stderr, "Alice did not accept while Bob did\n");
        return 0;
    }
    return 1;
}

static void example_same_input()
{
    uint8_t x[KOP_INPUT_BYTES];
    uint8_t sid[KOP_SID_BYTES];
    randombytes(x, KOP_INPUT_BYTES);
    randombytes(sid, KOP_SID_BYTES);
    assert(test_with_inputs(x, x, sid));
    assert(test_buffer_overlap(x, x, sid));
}

static void example_different_input()
{
    uint8_t x[KOP_INPUT_BYTES];
    uint8_t y[KOP_INPUT_BYTES];
    uint8_t sid[KOP_SID_BYTES];
    randombytes(x, KOP_INPUT_BYTES);
    randombytes(y, KOP_INPUT_BYTES);
    randombytes(sid, KOP_SID_BYTES);
    assert(!test_with_inputs(x, y, sid));
    assert(!test_buffer_overlap(x, y, sid));
}

// kyber_768, σ=40, N=4
// M0, A -> B:   189440 bytes (185 KiB) (σN public keys)
// M1, B -> A:   363520 bytes (355 KiB) (σN (ciphertext + public key))
// M2, A -> B:   174112 bytes (170 KiB) (encoding + σN ciphertexts))
// M3, B -> A:       32 bytes           (encoding)
static void print_sizes()
{
    printf("%s, σ=%u, N=%u\n", XSTR(KOP_KEM_ALG), KOP_INPUT_WORDS, KOP_OT_N);
    printf("M0, A -> B: %8u bytes (σN public keys)\n", KOP_PET_MSG0_BYTES);
    printf("M1, B -> A: %8u bytes (σN (ciphertext + public key))\n", KOP_PET_MSG1_BYTES);
    printf("M2, A -> B: %8u bytes (encoding + σN ciphertexts))\n", KOP_PET_MSG2_BYTES);
    printf("M3, B -> A: %8u bytes (encoding)\n", KOP_PET_MSG3_BYTES);
}

int main()
{
    print_sizes();
    for (size_t i = 0; i < 20; i++) {
        example_same_input();
        example_different_input();
    }
}

