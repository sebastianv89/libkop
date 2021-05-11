#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "pet.h"
#include "params.h"
#include "common.h"
#include "ot.h"

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

// The PRF used in the PET.
// buffer *in must contain (key||msg)
void pet_prf(uint8_t out[PET_LAMBDA],
             const uint8_t in[SS_BYTES + PET_INPUT_BYTES])
{
    EVP_Digest(in, SS_BYTES + PET_INPUT_BYTES, out, NULL, EVP_sha3_256(), NULL);
}

// Initialize the receiver of oblivious encoding
static void oenc_recv_init(uint8_t sks[PET_SIGMA * SK_BYTES],
                           uint8_t pks[PET_SIGMA * OTKEM_N * PK_BYTES],
                           uint8_t indices[PET_SIGMA],
                           uint8_t sid[SID_BYTES])
{
    size_t i;

    for (i = 0; i < PET_SIGMA; i++) {
        sid[SID_BYTES-1] = i;
        kemot_receiver_init(&sks[i * SK_BYTES], &pks[i * OTKEM_N * PK_BYTES], indices[i], sid);
    }
}

// Run the sender of oblivious encoding.
//
// The sender could get arbitrary encodings, but for the PET we only require
// the encoding of the input.
static void oenc_send(uint8_t encoding[PET_LAMBDA],
                      uint8_t cts[PET_SIGMA * OTKEM_N * CT_BYTES],
                      const uint8_t pks[PET_SIGMA * OTKEM_N * PK_BYTES],
                      const uint8_t indices[PET_SIGMA],
                      const uint8_t input[PET_INPUT_BYTES],
                      uint8_t sid[SID_BYTES])
{
    uint8_t secrets[OTKEM_N * SS_BYTES];
    uint8_t prf_input[SS_BYTES + PET_INPUT_BYTES];
    uint8_t digest[PET_LAMBDA];
    uint8_t b;
    size_t i, j;

    memset(encoding, 0, PET_LAMBDA);
    memcpy(&prf_input[SS_BYTES], input, PET_INPUT_BYTES);
    for (i = 0; i < PET_SIGMA; i++) {
        sid[SID_BYTES-1] = i;
        kemot_sender(secrets, &cts[i * OTKEM_N * CT_BYTES], &pks[i * OTKEM_N * PK_BYTES], sid);
        for (j = 0; j < OTKEM_N; j++) {
            b = 1 - ((-(uint64_t)(j ^ indices[i])) >> 63);
            cmov(prf_input, &secrets[j * SS_BYTES], SS_BYTES, b);
        }
        pet_prf(digest, prf_input);
        for (j = 0; j < PET_LAMBDA; j++) {
            encoding[j] ^= digest[j];
        }
    }
}

// Get receiver output of oblivious encoding.
static void oenc_recv_out(uint8_t encoding[PET_LAMBDA],
                          const uint8_t cts[PET_SIGMA * OTKEM_N * CT_BYTES],
                          const uint8_t sks[PET_SIGMA * SK_BYTES],
                          const uint8_t indices[PET_SIGMA],
                          const uint8_t input[PET_INPUT_BYTES])
{
    uint8_t prf_input[SS_BYTES + PET_INPUT_BYTES];
    uint8_t digest[PET_LAMBDA];
    size_t i, j;

    memset(encoding, 0, PET_LAMBDA);
    memcpy(&prf_input[SS_BYTES], input, PET_INPUT_BYTES); 
    for (i = 0; i < PET_SIGMA; i++) {
        kemot_receiver_output(prf_input, &cts[i * OTKEM_N * CT_BYTES], &sks[i * SK_BYTES], indices[i]);
        pet_prf(digest, prf_input);
        for (j = 0; j < PET_LAMBDA; j++) {
            encoding[j] ^= digest[j];
        }
    }
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
void pet_alice_m0(uint8_t sks[PET_SIGMA * SK_BYTES],
                  uint8_t pks[PET_SIGMA * OTKEM_N * PK_BYTES],
                  const uint8_t x[PET_INPUT_BYTES])
{
    uint8_t indices[PET_SIGMA];
    uint8_t sid[SID_BYTES] = {0};

    bytes_to_words(indices, x);
    oenc_recv_init(sks, pks, indices, sid);
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
void pet_bob_m1(uint8_t y_b[PET_LAMBDA],
                uint8_t sks[PET_SIGMA * SK_BYTES],
                uint8_t msg_out[PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES)],
                const uint8_t pks_in[PET_SIGMA * OTKEM_N * PK_BYTES],
                const uint8_t y[PET_INPUT_BYTES])
{
    uint8_t indices[PET_SIGMA];
    uint8_t y_local[PET_INPUT_BYTES];
    uint8_t y_b_local[PET_LAMBDA];
    uint8_t cts[PET_SIGMA * OTKEM_N * CT_BYTES];
    uint8_t *pks_out = &msg_out[PET_SIGMA * OTKEM_N * CT_BYTES];
    uint8_t sid[SID_BYTES] = {0};

    memcpy(y_local, y, PET_INPUT_BYTES);
    bytes_to_words(indices, y);
    oenc_send(y_b_local, cts, pks_in, indices, y, sid);
    sid[SID_BYTES - 2] = 1;
    oenc_recv_init(sks, pks_out, indices, sid);
    memcpy(y_b, y_b_local, PET_LAMBDA);
    memcpy(msg_out, cts, PET_SIGMA * OTKEM_N * CT_BYTES);
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
void pet_alice_m2(uint8_t x_a[PET_LAMBDA],
                  uint8_t msg_out[PET_LAMBDA + PET_SIGMA * OTKEM_N * CT_BYTES],
                  const uint8_t msg_in[PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES)],
                  const uint8_t sks[PET_SIGMA * SK_BYTES],
                  const uint8_t x[PET_INPUT_BYTES])
{
    uint8_t indices[PET_SIGMA];
    uint8_t sid[SID_BYTES] = {1, 0};
    uint8_t x_a_local[PET_LAMBDA];
    uint8_t x_b[PET_LAMBDA] = {0};
    uint8_t cts_out[PET_SIGMA * OTKEM_N * CT_BYTES];
    const uint8_t *cts_in = msg_in;
    const uint8_t *pks_in = &msg_in[PET_SIGMA * OTKEM_N * CT_BYTES];
    size_t i;

    bytes_to_words(indices, x);
    oenc_recv_out(x_b, cts_in, sks, indices, x);
    oenc_send(x_a_local, cts_out, pks_in, indices, x, sid);

    memcpy(x_a, x_a_local, PET_LAMBDA);
    for (i = 0; i < PET_LAMBDA; i++) {
        msg_out[i] = x_a_local[i] ^ x_b[i];
    }
    memcpy(&msg_out[PET_LAMBDA], cts_out, PET_SIGMA * OTKEM_N * CT_BYTES);
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
int pet_bob_m3(uint8_t y_a[PET_LAMBDA],
               const uint8_t msg_in[PET_LAMBDA + PET_SIGMA * CT_BYTES],
               const uint8_t y_b[PET_LAMBDA],
               const uint8_t sks[PET_SIGMA * SK_BYTES],
               const uint8_t y[PET_INPUT_BYTES])
{
    uint8_t y_a_local[PET_LAMBDA];
    uint8_t y_ab[PET_LAMBDA];
    uint8_t indices[PET_SIGMA];
    const uint8_t *x_ab = msg_in;
    const uint8_t *cts_in = &msg_in[PET_LAMBDA];
    size_t i;

    bytes_to_words(indices, y);
    oenc_recv_out(y_a_local, cts_in, sks, indices, y);
    for (i = 0; i < PET_LAMBDA; i++) {
        y_ab[i] = y_a_local[i] ^ y_b[i];
    }
    if (verify(x_ab, y_ab, PET_LAMBDA) != 0) {
        return 0;
    }
    memcpy(y_a, y_a_local, PET_LAMBDA);
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

