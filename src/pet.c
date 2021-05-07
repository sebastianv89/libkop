#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// #include <stdio.h> // FIXME remove

#include "pet.h"
#include "params.h"
#include "common.h"
#include "ot.h"
#include "fips202.h"

/*
static void print_bytes(const uint8_t *a, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", a[i]);
    }
}
static void print_input(const uint8_t input[PET_INPUT_BYTES])
{
    print_bytes(input, PET_INPUT_BYTES);
}

static void print_words(const uint8_t words[PET_SIGMA])
{
    size_t i;
    for (i = 0; i < PET_SIGMA; i++) {
        printf("%d", words[i]);
    }
}

static void print_pk(const uint8_t pk[PK_BYTES])
{
    size_t i;
    for (i = 0; i < 4; ++i) {
        printf("%02x", pk[i]);
    }
    printf("...");
    for (i = 4; i > 0; i--) {
        printf("%02x", pk[PK_BYTES-i]);
    }
}

static void print_ss(const uint8_t ss[SS_BYTES])
{
    print_bytes(ss, SS_BYTES);
}
// */

// Convert bytes to words of OTKEM_LOG_N bits
static void bytes_to_words(uint8_t words[PET_SIGMA], const uint8_t bytes[PET_INPUT_BYTES])
{
#if OTKEM_N != 4
    // TODO write general implementation
    exit(EXIT_FAILURE);
#else
    size_t i, j;

    for (i = 0, j = 0; i < PET_SIGMA; i += 4, j++) {
        words[i    ] =  bytes[j]       & 0x03;
        words[i + 1] = (bytes[j] >> 2) & 0x03;
        words[i + 2] = (bytes[j] >> 4) & 0x03;
        words[i + 3] = (bytes[j] >> 6) & 0x03;
    }
#endif
}

/// Initialize Alice in the private equality test
///
/// Alice initializes the oblivious encoding Receiver with her secret `x`.
/// She gets her secret keys and the public keys to send to Bob.
///
/// @param[out] sks  PET_SIGMA secret keys, of length SK_BYTES each.
/// @param[out] pks  (PET_SIGMA * OTKEM_N) public keys, of length PK_BYTES each.
///                  Outgoing message to Bob.
/// @param[in]  x    Alice's secret input.
// FIXME: consider buffer overlap
void pet_alice_m0(uint8_t sks[PET_SIGMA * SK_BYTES],
                  uint8_t pks[PET_SIGMA * OTKEM_N * PK_BYTES],
                  const uint8_t x[PET_INPUT_BYTES])
{
    uint8_t indices[PET_SIGMA];
    uint8_t sid[SID_BYTES] = {0};
    size_t i;

    // printf("=== Alice ===\n");

    bytes_to_words(indices, x);
    // printf("x="); print_input(x); printf(" => x="); print_words(indices); printf("\n");
    for (i = 0; i < PET_SIGMA; i++) {
        sid[SID_BYTES-1] = i;
        // printf("OT %zu, %02x%02x: (i=%d)\n", i, sid[0], sid[1], indices[i]);
        kemot_receiver_init(&sks[i * SK_BYTES], &pks[i * OTKEM_N * PK_BYTES], indices[i], sid);
    }
}

/// Bob processes m0 in the private equality test
///
/// Bob takes Alice's message and runs the oblivious encoding Sender: from his
/// shared secrets he computes `y_b`: his secret input `y` in his encoding.
/// Bob also initializes an oblivious encoding Receiver with his secret `y`.
/// He gets her secret keys and public keys to send to Alice.  The outgoing
/// message is a concatenation of his Sender ciphertext and Receiver public
/// keys.
///
/// @param[out] y_b      secret encoding of `y` in Bob's encoding.
/// @param[out] sks      PET_SIGMA secret keys, of length SK_BYTES each.
/// @param[out] msg_out  (PET_SIGMA * OTKEM_N) ciphertexts, of length CT_BYTES each.
///                      Concatenated with (PET_SIGMA * OTKEM_N) public keys, of length PK_BYTES each.
///                      Outgoing message to Alice.
/// @param[in]  pks_in   Incoming message from Alice, output of `pet_alice_m0`.
/// @param[in]  y        Bob's secret input, of length PET_INPUT_BYTES
// FIXME: consider buffer overlap
void pet_bob_m1(uint8_t y_b[PET_LAMBDA],
                uint8_t sks[PET_SIGMA * SK_BYTES],
                uint8_t msg_out[PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES)],
                const uint8_t pks_in[PET_SIGMA * OTKEM_N * PK_BYTES],
                const uint8_t y[PET_INPUT_BYTES])
{
    size_t i, j;
    uint8_t indices[PET_SIGMA];
    uint8_t digest[PET_LAMBDA];
    uint8_t prf_input[SS_BYTES + PET_INPUT_BYTES];
    uint8_t sss[OTKEM_N * SS_BYTES];
    uint8_t *cts_out = msg_out;
    uint8_t *pks_out = &msg_out[PET_SIGMA * OTKEM_N * CT_BYTES];
    uint8_t sid[SID_BYTES] = {0};
    uint8_t b;

    // printf("=== Bob ===\n");

    for (j = 0; j < PET_LAMBDA; j++) {
        y_b[j] = 0;
    }
    for (j = 0; j < PET_INPUT_BYTES; j++) {
        prf_input[j + SS_BYTES] = y[j];
    }
    bytes_to_words(indices, y);
    // printf("y="); print_input(y); printf(" => y="); print_words(indices); printf("\n");
    for (i = 0; i < PET_SIGMA; i++) {
        sid[SID_BYTES - 1] = i;
        // printf("OT %zu, %02x%02x: (i=%d)\n", i, sid[0], sid[1], indices[i]);
        kemot_sender(sss, &cts_out[i * OTKEM_N * CT_BYTES], &pks_in[i * OTKEM_N * PK_BYTES], sid);
        // for (j = 0; j < OTKEM_N; j++) {
        //     printf("  s%zu: ", j); print_ss(&sss[j * SS_BYTES]); printf("\n");
        // }
        for (j = 0; j < OTKEM_N; j++) {
            b = 1 - ((-(uint64_t)(j ^ indices[i])) >> 63);
            cmov(prf_input, &sss[j * SS_BYTES], SS_BYTES, b);
        }
        // printf("  hashing "); print_bytes(prf_input, sizeof(prf_input)); printf("\n");
        sha3_256(digest, prf_input, SS_BYTES + PET_INPUT_BYTES);
        // printf("    res:  "); print_bytes(digest, sizeof(digest)); printf("\n");
        for (j = 0; j < PET_LAMBDA; j++) {
            y_b[j] ^= digest[j];
        }
    }
    // printf("y_b = "); print_bytes(y_b, PET_LAMBDA); printf("\n");

    sid[SID_BYTES - 2] = 1;
    for (i = 0; i < PET_SIGMA; i++) {
        sid[SID_BYTES - 1] = i;
        // printf("OT %zu, %02x%02x: (i=%d)\n", i, sid[0], sid[1], indices[i]);
        kemot_receiver_init(&sks[i * SK_BYTES], &pks_out[i * OTKEM_N * PK_BYTES], indices[i], sid);
    }
}

/// Alice processes m1 in the private equality test.
///
/// Alice takes Bob's message. As oblivious encoding Receiver, she learns
/// `x_b`: her secret input `x` in his encoding.  As oblivious encoding Sender:
/// from her shared secrets she computes `x_a`: her secret input `x` in her
/// encoding.  The outgoing message consists of the common encoding and the
/// oblivious encoding ciphertexts.
///
/// @param[out] x_a      Secret encoding of `x` in Alice's encoding.
/// @param[out] msg_out  Common encoding `x_a ^ x_b`, of length PET_LAMBDA.
///                      Concatenated with (PET_SIGMA * OTKEM_N) ciphertexts, of length CT_BYTES each.
///                      Outgoing message to Bob.
/// @param[in]  msg_in   Incoming message from Bob, output of `pet_bob_m1`.
/// @param[in]  sks      Alice's secret keys, output of `pet_alice_m0`.
/// @param[in]  x        Alice's secret input, of length PET_INPUT_BYTES.
// FIXME consider buffer overlap
void pet_alice_m2(uint8_t x_a[PET_LAMBDA],
                  uint8_t msg_out[PET_LAMBDA + PET_SIGMA * OTKEM_N * CT_BYTES],
                  const uint8_t msg_in[PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES)],
                  const uint8_t sks[PET_SIGMA * SK_BYTES],
                  const uint8_t x[PET_INPUT_BYTES])
{
    uint8_t indices[PET_SIGMA];
    uint8_t digest[PET_LAMBDA];
    uint8_t prf_input[SS_BYTES + PET_INPUT_BYTES];
    uint8_t sid[SID_BYTES] = {0};
    uint8_t sss[OTKEM_N * SS_BYTES];
    uint8_t x_b[PET_LAMBDA] = {0};
    uint8_t *x_ab = msg_out;
    uint8_t *cts_out = &msg_out[PET_LAMBDA];
    const uint8_t *cts_in = msg_in;
    const uint8_t *pks_in = &msg_in[PET_SIGMA * OTKEM_N * CT_BYTES];
    uint8_t b;
    size_t i, j;

    // printf("=== Alice ===\n");

    for (i = 0; i < PET_INPUT_BYTES; i++) {
        prf_input[i + SS_BYTES] = x[i];
    }
    bytes_to_words(indices, x);
    for (i = 0; i < PET_SIGMA; i++) {
        // printf("OT %zu, x: (i=%d)\n", i, indices[i]);
        kemot_receiver_output(prf_input, &cts_in[i * OTKEM_N * CT_BYTES], &sks[i * SK_BYTES], indices[i]);
        // printf("  s%u: ", indices[i]); print_bytes(prf_input, SS_BYTES); printf("\n");
        // printf("  hashing "); print_bytes(prf_input, sizeof(prf_input)); printf("\n");
        sha3_256(digest, prf_input, SS_BYTES + PET_INPUT_BYTES);
        // printf("    res:  "); print_bytes(digest, sizeof(digest)); printf("\n");
        for (j = 0; j < PET_LAMBDA; j++) {
            x_b[j] ^= digest[j];
        }
    }
    // printf("x_b: "); print_bytes(x_b, PET_LAMBDA); printf("\n");
    for (i = 0; i < PET_LAMBDA; i++) {
        x_ab[i] = x_b[i];
    }
    sid[SID_BYTES - 2] = 1;
    for (i = 0; i < PET_SIGMA; i++) {
        sid[SID_BYTES - 1] = i;
        // printf("OT %zu, %02x%02x: (i=%d)\n", i, sid[0], sid[1], indices[i]);
        kemot_sender(sss, &cts_out[i * OTKEM_N * CT_BYTES], &pks_in[i * OTKEM_N * PK_BYTES], sid);
        // for (j = 0; j < OTKEM_N; j++) {
        //     printf("  s%zu: ", j); print_ss(&sss[j * SS_BYTES]); printf("\n");
        // }
        for (j = 0; j < OTKEM_N; j++) {
            b = 1 - ((-(uint64_t)(j ^ indices[i])) >> 63);
            cmov(prf_input, &sss[j * SS_BYTES], SS_BYTES, b);
        }
        // printf("  hashing "); print_bytes(prf_input, sizeof(prf_input)); printf("\n");
        sha3_256(digest, prf_input, SS_BYTES + PET_INPUT_BYTES);
        // printf("    res:  "); print_bytes(digest, sizeof(digest)); printf("\n");
        for (j = 0; j < PET_LAMBDA; j++) {
            x_ab[j] ^= digest[j];
        }
    }
    // printf("x_ab: "); print_bytes(x_ab, PET_LAMBDA); printf("\n");
    for (i = 0; i < PET_LAMBDA; i++) {
        x_a[i] = x_ab[i] ^ x_b[i];
    }
    // printf("x_a:  "); print_bytes(x_a, PET_LAMBDA); printf("\n");
}

/// Bob processes m2 in the private equality test. Returns boolean value (0 or
/// 1) indicating if x==y.
///
/// Bob takes Alice's message. He computes `y_a`: his secret input `y`
/// in her encoding, from which he can compute the shared encoding `y_a ^ y_b`.
/// He compares this to the encoding she sent. If they are unequal, he aborts.
/// (Optional: send a message to Alice to let her know `x != y`.)
/// Otherwise (x equals y) he sends `y_a` to Alice.
///
/// @param[out] y_a      Secret encoding of `y` in Bob's encoding.
///                      If the function returns 1, this is the outgoing message to Alice.
/// @param[in]  msg_in   Incoming message from Alice, output of `pet_alice_m2`.
/// @param[in]  sks      Bob's secret keys, output of `pet_bob_m1`.
/// @param[in]  y        Bob's secret input `y`, of length PET_INPUT_BYTES.
/// @param[in]  y_b      Secret encoding of `y` in Bob's encoding, output of `pet_bob_m1`.
///
/// @return     if `x == y` then return 1, otherwise return 0.
// FIXME consider buffer overlap
int pet_bob_m3(uint8_t y_a[PET_LAMBDA],
               const uint8_t msg_in[PET_LAMBDA + PET_SIGMA * CT_BYTES],
               const uint8_t sks[PET_SIGMA * SK_BYTES],
               const uint8_t y[PET_INPUT_BYTES],
               const uint8_t y_b[PET_LAMBDA])
{
    uint8_t prf_input[SS_BYTES + PET_INPUT_BYTES];
    uint8_t digest[PET_LAMBDA];
    uint8_t y_ab[PET_LAMBDA];
    uint8_t indices[PET_SIGMA];
    const uint8_t *x_ab = msg_in;
    const uint8_t *cts_in = &msg_in[PET_LAMBDA];
    size_t i, j;

    // printf("=== Bob ===\n");

    for (j = 0; j < PET_LAMBDA; j++) {
        y_ab[j] = y_b[j];
    }
    for (j = 0; j < PET_INPUT_BYTES; j++) {
        prf_input[j + SS_BYTES] = y[j];
    }
    bytes_to_words(indices, y);
    for (i = 0; i < PET_SIGMA; i++) {
        // printf("OT %zu: (i=%d)\n", i, indices[i]);
        kemot_receiver_output(prf_input, &cts_in[i * OTKEM_N * CT_BYTES], &sks[i * SK_BYTES], indices[i]);
        // printf("  s%u: ", indices[i]); print_bytes(prf_input, SS_BYTES); printf("\n");
        // printf("  hashing "); print_bytes(prf_input, sizeof(prf_input)); printf("\n");
        sha3_256(digest, prf_input, SS_BYTES + PET_INPUT_BYTES);
        // printf("    res:  "); print_bytes(digest, sizeof(digest)); printf("\n");
        for (j = 0; j < PET_LAMBDA; j++) {
            y_ab[j] ^= digest[j];
        }
    }
    // printf("y_ab: "); print_bytes(y_ab, PET_LAMBDA); printf("\n");
    if (verify(x_ab, y_ab, PET_LAMBDA) != 0) {
        return 0;
    }
    for (j = 0; j < PET_LAMBDA; j++) {
        y_a[j] = y_ab[j] ^ y_b[j];
    }
    // printf("y_a: "); print_bytes(y_a, PET_LAMBDA); printf("\n");
    return 1;
}

/// Alice completes the private equality test. Returns boolean value (0 or
/// 1) indicating if x==y.
///
/// Alice takes Bob's message `y_a` and compares his encoding with her stored
/// encoding.
///
/// @param[in]  y_a  Bob's message, output of `pet_bob_m3`.
/// @param[in]  x_a  Secret encoding of `x` in Alice's encoding, output of `pet_alice_m2`.
/// @return     if `x == y` then return 1, otherwise return 0.
int pet_alice_accept(const uint8_t y_a[PET_LAMBDA],
                     const uint8_t x_a[PET_LAMBDA])
{
    return 1 - verify(x_a, y_a, 32);
}

#if TEST_PET == 1

#include <stdio.h>
#include <assert.h>
#include "randombytes.h"

#define NTESTS 100

static int test_inputs(const uint8_t a_x[PET_INPUT_BYTES], const uint8_t b_y[PET_INPUT_BYTES])
{
    uint8_t a_sks[PET_SIGMA * SK_BYTES];
    uint8_t a_x_a[PET_LAMBDA];

    uint8_t b_sks[PET_SIGMA * SK_BYTES];
    uint8_t b_y_b[PET_SIGMA * SK_BYTES];

    uint8_t m0[PET_SIGMA * OTKEM_N * PK_BYTES];
    uint8_t m1[PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES)];
    uint8_t m2[PET_LAMBDA + PET_SIGMA * OTKEM_N * CT_BYTES];
    uint8_t m3[PET_LAMBDA];

    size_t i;
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

static void test_same_input()
{
    uint8_t x[PET_INPUT_BYTES];
    randombytes(x, PET_INPUT_BYTES);
    printf("\nSame input\n\n");
    assert(test_inputs(x, x));
}

static void test_different_input()
{
    uint8_t x[PET_INPUT_BYTES];
    uint8_t y[PET_INPUT_BYTES];
    randombytes(x, PET_INPUT_BYTES);
    randombytes(y, PET_INPUT_BYTES);
    printf("\nDifferent input\n\n");
    assert(!test_inputs(x, y));
}

int main()
{
    size_t i;
    for (i = 0; i < NTESTS; i++) {
        test_same_input();
        test_different_input();
    }
    printf("it works\n");
}

#endif
