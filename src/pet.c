#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "SimpleFIPS202.h"

#include "pet.h"
#include "params.h"
#include "common.h"
#include "ot.h"

static void words_from_bytes(
        kop_pet_index_t words[KOP_SIGMA],
        const uint8_t bytes[KOP_INPUT_BYTES])
{
#if KOP_OT_LOGN == 1
    size_t i, j;

    for (i = 0, j = 0; i < KOP_SIGMA; i += 8, j++) {
        words[i    ] =  bytes[j]       & 0x01;
        words[i + 1] = (bytes[j] >> 1) & 0x01;
        words[i + 2] = (bytes[j] >> 2) & 0x01;
        words[i + 3] = (bytes[j] >> 3) & 0x01;
        words[i + 4] = (bytes[j] >> 4) & 0x01;
        words[i + 5] = (bytes[j] >> 5) & 0x01;
        words[i + 6] = (bytes[j] >> 6) & 0x01;
        words[i + 7] =  bytes[j] >> 7;
    }
#elif KOP_OT_LOGN == 2
    size_t i, j;

    for (i = 0, j = 0; i < KOP_SIGMA; i += 4, j++) {
        words[i    ] =  bytes[j]       & 0x03;
        words[i + 1] = (bytes[j] >> 2) & 0x03;
        words[i + 2] = (bytes[j] >> 4) & 0x03;
        words[i + 3] =  bytes[j] >> 6;
    }
#elif KOP_OT_LOGN == 3
    size_t i, j;

    for (i = 0, j = 0; i < KOP_SIGMA; i += 8, j += 3) {
        words[i    ]  =  bytes[j]           & 0x07;
        words[i + 1]  = (bytes[j]     >> 3) & 0x07;
        words[i + 2]  =  bytes[j]     >> 6;
        if (j + 1 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 2] |= (bytes[j + 1] << 2) & 0x04;
        words[i + 3]  = (bytes[j + 1] >> 1) & 0x07;
        words[i + 4]  = (bytes[j + 1] >> 4) & 0x07;
        words[i + 5]  =  bytes[j + 1] >> 7;
        if (j + 2 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 5] |= (bytes[j + 2] << 1) & 0x06;
        words[i + 6]  = (bytes[j + 2] >> 2) & 0x07;
        words[i + 7]  =  bytes[j + 2] >> 5;
    }
#elif KOP_OT_LOGN == 4
    size_t i, j;

    for (i = 0, j = 0; i < KOP_SIGMA; i += 2, j++) {
        words[i    ] = bytes[j] & 0x0f;
        words[i + 1] = bytes[j] >> 4;
    }
#elif KOP_OT_LOGN == 5
    size_t i, j;

    for (i = 0, j = 0; i < KOP_SIGMA; i += 8, j += 5) {
        words[i    ]  =  bytes[j]           & 0x1f;
        words[i + 1]  =  bytes[j]     >> 5;
        if (j + 1 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 1] |= (bytes[j + 1] << 3) & 0x14;
        words[i + 2]  = (bytes[j + 1] >> 2) & 0x1f;
        words[i + 3]  =  bytes[j + 1] >> 7;
        if (j + 2 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 3] |= (bytes[j + 2] << 1) & 0x1e;
        words[i + 4]  =  bytes[j + 2] >> 4;
        if (j + 3 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 4] |= (bytes[j + 3] << 4) & 0x10;
        words[i + 5]  = (bytes[j + 3] >> 1) & 0x1f;
        words[i + 6]  =  bytes[j + 3] >> 6;
        if (j + 4 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 6] |= (bytes[j + 4] << 2) & 0x18;
        words[i + 7]  =  bytes[j + 4] >> 3;
    }
#elif KOP_OT_LOGN == 6
    size_t i, j;

    for (i = 0, j = 0; i < KOP_SIGMA; i += 4, j += 3) {
        words[i    ]  =  bytes[j]           & 0x3f;
        words[i + 1]  =  bytes[j]     >> 6;
        if (j + 1 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 1] |= (bytes[j + 1] << 2) & 0x3c;
        words[i + 2]  =  bytes[j + 1] >> 4;
        if (j + 2 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 2] |= (bytes[j + 2] << 4) & 0x30;
        words[i + 3]  =  bytes[j + 2] >> 2;
    }
#elif KOP_OT_LOGN == 7
    size_t i, j;

    for (i = 0, j = 0; i < KOP_SIGMA; i += 8, j += 7) {
        words[i    ]  =  bytes[j]           & 0x7f;
        words[i + 1]  =  bytes[j]     >> 7;
        if (j + 1 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 1] |= (bytes[j + 1] << 1) & 0x7e;
        words[i + 2]  =  bytes[j + 1] >> 6;
        if (j + 2 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 2] |= (bytes[j + 2] << 2) & 0x7c;
        words[i + 3]  =  bytes[j + 2] >> 5;
        if (j + 3 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 3] |= (bytes[j + 3] << 3) & 0x78;
        words[i + 4]  =  bytes[j + 3] >> 4;
        if (j + 4 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 4] |= (bytes[j + 4] << 4) & 0x70;
        words[i + 5]  =  bytes[j + 4] >> 3;
        if (j + 5 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 5] |= (bytes[j + 5] << 5) & 0x60;
        words[i + 6]  =  bytes[j + 5] >> 2;
        if (j + 6 >= KOP_INPUT_BYTES) {
            break;
        }
        words[i + 6] |= (bytes[j + 6] << 6) & 0x40;
        words[i + 7]  =  bytes[j + 6] >> 1;
    }
#elif KOP_OT_LOGN == 8
    memcpy(words, bytes, KOP_INPUT_BYTES);
#else
#error KOP_OT_LOGN larger than eight is not (yet) supported
#endif
}


// The PRF used in the PET.
// buffer *in must contain (key||msg)
void pet_prf(uint8_t out[KOP_PRF_BYTES],
             const uint8_t in[KOP_SS_BYTES + KOP_INPUT_BYTES])
{
    SHA3_256(out, in, KOP_SS_BYTES + KOP_INPUT_BYTES);
}

// Initialize the receiver of oblivious encoding
static void oenc_recv_init(
        uint8_t sks[KOP_SIGMA * KOP_SK_BYTES],
        uint8_t pks[KOP_SIGMA * KOP_OT_N * KOP_PK_BYTES],
        uint8_t indices[KOP_SIGMA],
        hid_t *hid)
{
    size_t i;

    for (i = 0; i < KOP_SIGMA; i++) {
        hid->ot = i;
        kemot_receiver_init(&sks[i * KOP_SK_BYTES], &pks[i * KOP_OT_N * KOP_PK_BYTES], indices[i], hid);
    }
}

// Run the sender of oblivious encoding.
//
// The sender could get arbitrary encodings, but for the PET we only require
// the encoding of the input.
static void oenc_send(
        uint8_t encoding[KOP_PRF_BYTES],
        uint8_t cts[KOP_SIGMA * KOP_OT_N * KOP_CT_BYTES],
        const uint8_t pks[KOP_SIGMA * KOP_OT_N * KOP_PK_BYTES],
        const uint8_t indices[KOP_SIGMA],
        const uint8_t input[KOP_INPUT_BYTES],
        hid_t *hid)
{
    uint8_t secrets[KOP_OT_N * KOP_SS_BYTES];
    uint8_t prf_input[KOP_SS_BYTES + KOP_INPUT_BYTES];
    uint8_t digest[KOP_PRF_BYTES];
    uint8_t b;
    size_t i, j;

    memset(encoding, 0, KOP_PRF_BYTES);
    memcpy(&prf_input[KOP_SS_BYTES], input, KOP_INPUT_BYTES);
    for (i = 0; i < KOP_SIGMA; i++) {
        hid->ot = i;
        kemot_sender(secrets, &cts[i * KOP_OT_N * KOP_CT_BYTES], &pks[i * KOP_OT_N * KOP_PK_BYTES], hid);
        for (j = 0; j < KOP_OT_N; j++) {
            b = 1 - ((-(uint64_t)(j ^ indices[i])) >> 63);
            cmov(prf_input, &secrets[j * KOP_SS_BYTES], KOP_SS_BYTES, b);
        }
        pet_prf(digest, prf_input);
        for (j = 0; j < KOP_PRF_BYTES; j++) {
            encoding[j] ^= digest[j];
        }
    }
}

// Get receiver output of oblivious encoding.
static void oenc_recv_out(
        uint8_t encoding[KOP_PRF_BYTES],
        const uint8_t cts[KOP_SIGMA * KOP_OT_N * KOP_CT_BYTES],
        const uint8_t sks[KOP_SIGMA * KOP_SK_BYTES],
        const uint8_t indices[KOP_SIGMA],
        const uint8_t input[KOP_INPUT_BYTES])
{
    uint8_t prf_input[KOP_SS_BYTES + KOP_INPUT_BYTES];
    uint8_t digest[KOP_PRF_BYTES];
    size_t i, j;

    memset(encoding, 0, KOP_PRF_BYTES);
    memcpy(&prf_input[KOP_SS_BYTES], input, KOP_INPUT_BYTES); 
    for (i = 0; i < KOP_SIGMA; i++) {
        kemot_receiver_output(prf_input, &cts[i * KOP_OT_N * KOP_CT_BYTES], &sks[i * KOP_SK_BYTES], indices[i]);
        pet_prf(digest, prf_input);
        for (j = 0; j < KOP_PRF_BYTES; j++) {
            encoding[j] ^= digest[j];
        }
    }
}

/// Initialize Alice in the private equality test
///
/// Alice initializes the oblivious encoding Receiver with her secret `x`.
/// She gets her secret keys and the public keys to send to Bob.
///
/// @param[out] sks  KOP_SIGMA secret keys, of length KOP_SK_BYTES each.
/// @param[out] pks  (KOP_SIGMA * KOP_OT_N) public keys, of length KOP_PK_BYTES each.
///                  Outgoing message to Bob.
/// @param[in]  x    Alice's secret input.
void pet_alice_m0(
        uint8_t sks[KOP_SIGMA * KOP_SK_BYTES],
        uint8_t pks[KOP_PET_MSG0_BYTES],
        const uint8_t x[KOP_INPUT_BYTES],
        const uint8_t sid[KOP_SID_BYTES])
{
    uint8_t indices[KOP_SIGMA];
    hid_t hid;

    memcpy(&(hid.sid), sid, KOP_SID_BYTES);
    hid.oenc = 0;
    words_from_bytes(indices, x);
    oenc_recv_init(sks, pks, indices, &hid);
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
/// @param[out] sks      KOP_SIGMA secret keys, of length KOP_SK_BYTES each.
/// @param[out] msg_out  (KOP_SIGMA * KOP_OT_N) ciphertexts, of length KOP_CT_BYTES each.
///                      Concatenated with (KOP_SIGMA * KOP_OT_N) public keys, of length KOP_PK_BYTES each.
///                      Outgoing message to Alice.
/// @param[in]  pks_in   Incoming message from Alice, output of `pet_alice_m0`.
/// @param[in]  y        Bob's secret input, of length KOP_INPUT_BYTES
void pet_bob_m1(
        uint8_t y_b[KOP_PRF_BYTES],
        uint8_t sks[KOP_SIGMA * KOP_SK_BYTES],
        uint8_t msg_out[KOP_PET_MSG1_BYTES],
        const uint8_t pks_in[KOP_PET_MSG0_BYTES],
        const uint8_t y[KOP_INPUT_BYTES],
        const uint8_t sid[KOP_SID_BYTES])
{
    uint8_t indices[KOP_SIGMA];
    uint8_t y_local[KOP_INPUT_BYTES];
    uint8_t y_b_local[KOP_PRF_BYTES];
    uint8_t cts[KOP_SIGMA * KOP_OT_N * KOP_CT_BYTES];
    uint8_t *pks_out = &msg_out[KOP_SIGMA * KOP_OT_N * KOP_CT_BYTES];
    hid_t hid;

    memcpy(&(hid.sid), sid, KOP_SID_BYTES);
    memcpy(y_local, y, KOP_INPUT_BYTES);
    words_from_bytes(indices, y);
    hid.oenc = 0;
    oenc_send(y_b_local, cts, pks_in, indices, y, &hid);
    hid.oenc = 1;
    oenc_recv_init(sks, pks_out, indices, &hid);
    memcpy(y_b, y_b_local, KOP_PRF_BYTES);
    memcpy(msg_out, cts, KOP_SIGMA * KOP_OT_N * KOP_CT_BYTES);
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
/// @param[out] msg_out  Common encoding `x_a ^ x_b`, of length KOP_PRF_BYTES.
///                      Concatenated with (KOP_SIGMA * KOP_OT_N) ciphertexts, of length KOP_CT_BYTES each.
///                      Outgoing message to Bob.
/// @param[in]  msg_in   Incoming message from Bob, output of `pet_bob_m1`.
/// @param[in]  sks      Alice's secret keys, output of `pet_alice_m0`.
/// @param[in]  x        Alice's secret input, of length KOP_INPUT_BYTES.
void pet_alice_m2(
        uint8_t x_a[KOP_PRF_BYTES],
        uint8_t msg_out[KOP_PET_MSG2_BYTES],
        const uint8_t msg_in[KOP_PET_MSG1_BYTES],
        const uint8_t sks[KOP_SIGMA * KOP_SK_BYTES],
        const uint8_t x[KOP_INPUT_BYTES],
        const uint8_t sid[KOP_SID_BYTES])
{
    uint8_t indices[KOP_SIGMA];
    uint8_t x_a_local[KOP_PRF_BYTES];
    uint8_t x_b[KOP_PRF_BYTES] = {0};
    uint8_t cts_out[KOP_SIGMA * KOP_OT_N * KOP_CT_BYTES];
    const uint8_t *cts_in = msg_in;
    const uint8_t *pks_in = &msg_in[KOP_SIGMA * KOP_OT_N * KOP_CT_BYTES];
    hid_t hid;
    size_t i;

    memcpy(&(hid.sid), sid, KOP_SID_BYTES);
    words_from_bytes(indices, x);
    oenc_recv_out(x_b, cts_in, sks, indices, x);
    hid.oenc = 1;
    oenc_send(x_a_local, cts_out, pks_in, indices, x, &hid);

    memcpy(x_a, x_a_local, KOP_PRF_BYTES);
    for (i = 0; i < KOP_PRF_BYTES; i++) {
        msg_out[i] = x_a_local[i] ^ x_b[i];
    }
    memcpy(&msg_out[KOP_PRF_BYTES], cts_out, KOP_SIGMA * KOP_OT_N * KOP_CT_BYTES);
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
/// @param[in]  y        Bob's secret input `y`, of length KOP_INPUT_BYTES.
/// @param[in]  y_b      Secret encoding of `y` in Bob's encoding, output of `pet_bob_m1`.
///
/// @return     if `x == y` then return 1, otherwise return 0.
int pet_bob_m3(
        uint8_t y_a[KOP_PET_MSG3_BYTES],
        const uint8_t msg_in[KOP_PET_MSG2_BYTES],
        const uint8_t sks[KOP_SIGMA * KOP_SK_BYTES],
        const uint8_t y[KOP_INPUT_BYTES],
        const uint8_t y_b[KOP_PRF_BYTES])
{
    uint8_t y_a_local[KOP_PRF_BYTES];
    uint8_t y_ab[KOP_PRF_BYTES];
    uint8_t indices[KOP_SIGMA];
    const uint8_t *x_ab = msg_in;
    const uint8_t *cts_in = &msg_in[KOP_PRF_BYTES];
    size_t i;

    words_from_bytes(indices, y);
    oenc_recv_out(y_a_local, cts_in, sks, indices, y);
    for (i = 0; i < KOP_PRF_BYTES; i++) {
        y_ab[i] = y_a_local[i] ^ y_b[i];
    }
    if (verify(x_ab, y_ab, KOP_PRF_BYTES) != 0) {
        return 0;
    }
    memcpy(y_a, y_a_local, KOP_PRF_BYTES);
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
int pet_alice_accept(
        const uint8_t y_a[KOP_PET_MSG3_BYTES],
        const uint8_t x_a[KOP_PRF_BYTES])
{
    return 1 - verify(x_a, y_a, 32);
}

