#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "KeccakHash.h"

#include "pet.h"
#include "params.h"
#include "common.h"
#include "group.h"
#include "ot.h"

static void words_from_bytes(
    kop_ot_index_t words[KOP_SIGMA],
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
static void kop_pet_prf(
        uint8_t out[KOP_PRF_BYTES],
        const kop_kem_ss_s *key,
        const uint8_t input[KOP_INPUT_BYTES])
{
    Keccak_HashInstance hi;   
    Keccak_HashInitialize_SHA3_256(&hi);
    Keccak_HashUpdate(&hi, key->bytes, KOP_SS_BYTES);
    Keccak_HashUpdate(&hi, input, KOP_INPUT_BYTES);
    Keccak_HashFinal(&hi, out);
}

// Initialize the receiver of oblivious encoding
static void kop_oenc_recv_init(
    kop_ot_recv_s states[KOP_SIGMA],
    kop_ot_recv_msg_s msgs_out[KOP_SIGMA],
    const kop_ot_index_t indices[KOP_SIGMA],
    hid_t hid)
{
    size_t i;

    for (i = 0; i < KOP_SIGMA; i++) {
        hid.ot = i;
        kop_ot_recv_init(&states[i], &msgs_out[i], indices[i], hid);
    }
}

// Run the sender of oblivious encoding.
//
// The sender could get arbitrary encodings, but for the PET we only require
// the encoding of the input.
static void kop_oenc_send(
    uint8_t encoding[KOP_PRF_BYTES],
    kop_ot_send_msg_s msgs_out[KOP_SIGMA],
    const kop_ot_recv_msg_s msgs_in[KOP_SIGMA],
    const kop_ot_index_t indices[KOP_SIGMA],
    const uint8_t input[KOP_INPUT_BYTES],
    hid_t hid)
{
    kop_ot_send_s send;
    kop_kem_ss_s secret = {0}; // prevent warnings
    uint8_t digest[KOP_PRF_BYTES];
    uint8_t b;
    size_t i, j;

    memset(encoding, 0, KOP_PRF_BYTES);
    for (i = 0; i < KOP_SIGMA; i++) {
        hid.ot = i;
        kop_ot_send(&send, &msgs_out[i], &msgs_in[i], hid);
        for (j = 0; j < KOP_OT_N; j++) {
            b = 1 - byte_neq(j, indices[i]);
            cmov(secret.bytes, send.secrets[j].bytes, KOP_SS_BYTES, b);
        }
        kop_pet_prf(digest, &secret, input);
        for (j = 0; j < KOP_PRF_BYTES; j++) {
            encoding[j] ^= digest[j];
        }
    }
}

// Get receiver output of oblivious encoding.
static void kop_oenc_recv_out(
    uint8_t encoding[KOP_PRF_BYTES],
    const kop_ot_send_msg_s msgs_in[KOP_SIGMA],
    const kop_ot_recv_s states[KOP_SIGMA],
    const uint8_t input[KOP_INPUT_BYTES])
{
    kop_kem_ss_s secret;
    uint8_t digest[KOP_PRF_BYTES];
    size_t i, j;

    memset(encoding, 0, KOP_PRF_BYTES);
    for (i = 0; i < KOP_SIGMA; i++) {
        kop_ot_recv_out(&secret, &msgs_in[i], &states[i]);
        kop_pet_prf(digest, &secret, input);
        for (j = 0; j < KOP_PRF_BYTES; j++) {
            encoding[j] ^= digest[j];
        }
    }
}

// this leaves part of the state uninitialized...
void kop_pet_init(
    kop_pet_state_s *state,
    const uint8_t input[KOP_INPUT_BYTES],
    const uint8_t sid[KOP_SID_BYTES])
{
    memcpy(state->hid.sid, sid, KOP_SID_BYTES);
    memcpy(state->input, input, KOP_INPUT_BYTES);
}

void kop_pet_alice_m0(
    kop_pet_state_s *state,
    kop_pet_msg0_s *msg_out)
{
    kop_ot_index_t indices[KOP_SIGMA];

    words_from_bytes(indices, state->input);
    state->hid.oenc = 0;
    kop_oenc_recv_init(state->recv, msg_out->recv, indices, state->hid);
}

void kop_pet_bob_m1(
    kop_pet_state_s *state,
    kop_pet_msg1_s *msg_out,
    const kop_pet_msg0_s *msg_in)
{
    kop_ot_index_t indices[KOP_SIGMA];
    
    words_from_bytes(indices, state->input);
    state->hid.oenc = 0;
    kop_oenc_send(state->encoding, msg_out->send, msg_in->recv, indices, state->input, state->hid);
    // state->encoding == B[y]
    state->hid.oenc = 1;
    kop_oenc_recv_init(state->recv, msg_out->recv, indices, state->hid);
}

void kop_pet_alice_m2(
    kop_pet_state_s *state,
    kop_pet_msg2_s *msg_out,
    const kop_pet_msg1_s *msg_in)
{
    kop_ot_index_t indices[KOP_SIGMA];
    uint8_t encoding[KOP_PRF_BYTES];
    size_t i;

    state->hid.oenc = 0;
    kop_oenc_recv_out(encoding, msg_in->send, state->recv, state->input);
    // encoding == B[x]
    for (i = 0; i < KOP_SIGMA; i++) {
        indices[i] = state->recv[i].index;
    }
    state->hid.oenc = 1;
    kop_oenc_send(state->encoding, msg_out->send, msg_in->recv, indices, state->input, state->hid);
    // state->encoding == A[x]
    for (i = 0; i < KOP_PRF_BYTES; i++) {
        msg_out->encoding[i] = encoding[i] ^ state->encoding[i];
    }
    // msg_out->encoding == A[x] ^ B[x]
}

int kop_pet_bob_m3(
    kop_pet_state_s *state,
    kop_pet_msg3_s *msg_out,
    const kop_pet_msg2_s *msg_in)
{
    uint8_t encoding_out[KOP_PRF_BYTES];
    size_t i;

    // state->encoding == B[y]
    state->hid.oenc = 1;
    kop_oenc_recv_out(encoding_out, msg_in->send, state->recv, state->input);
    // encoding_out == A[y]
    for (i = 0; i < KOP_PRF_BYTES; i++) {
        state->encoding[i] ^= encoding_out[i];
    }
    // state->encoding == A[y] ^ B[y]
    // msg_in->encoding == A[x] ^ B[x]
    if (verify(state->encoding, msg_in->encoding, KOP_PRF_BYTES) != 0) {
        // memset(msg_out->encoding, 0, KOP_PRF_BYTES); // prevents outputting an uninitialized value
        return 0;
    }
    memcpy(msg_out->encoding, encoding_out, KOP_PRF_BYTES);
    // msg_out->encoding == A[y]
    return 1;
}

int kop_pet_alice_accept(
    kop_pet_state_s *state,
    const kop_pet_msg3_s *msg_in)
{
    return 1 - verify(state->encoding, msg_in->encoding, KOP_PRF_BYTES);
}

