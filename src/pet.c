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

static void kop_pet_prf(
    uint8_t out[KOP_PET_PRF_BYTES],
    const kop_kem_ss_s *key,
    const uint8_t input[KOP_INPUT_BYTES])
{
    const uint8_t prefix[11] = { 0x4b, 0x4f, 0x50, 0x2d, 0x50, 0x45, 0x54, 0x2d, 0x50, 0x52, 0x46 }; // "KOP-PET-PRF"
    Keccak_HashInstance hi;

    KECCAK_UNWRAP(Keccak_HashInitialize_SHA3_256(&hi));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, prefix, 8 * sizeof(prefix)));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, key->bytes, 8 * KOP_KEM_SS_BYTES));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, input, 8 * KOP_INPUT_BYTES));
    KECCAK_UNWRAP(Keccak_HashFinal(&hi, out));
}

// Initialize the receiver of oblivious encoding
static void kop_oenc_recv_init(
    kop_ot_recv_s states[KOP_SIGMA],
    uint8_t msgs_out[KOP_SIGMA * KOP_OT_MSG0_BYTES],
    const kop_ot_index_t indices[KOP_SIGMA],
    hid_t hid)
{
    size_t i;

    for (i = 0; i < KOP_SIGMA; i++) {
        hid.ot = i;
        kop_ot_recv_init(&states[i], &msgs_out[i * KOP_OT_MSG0_BYTES], indices[i], hid);
    }
}

// Run the sender of oblivious encoding.
//
// The sender can get arbitrary encodings, but for the PET we only require the
// encoding of the input.
static kop_result_e kop_oenc_send(
    uint8_t encoding[KOP_PET_PRF_BYTES],
    uint8_t msgs_out[KOP_SIGMA * KOP_OT_MSG1_BYTES],
    const uint8_t msgs_in[KOP_SIGMA * KOP_OT_MSG0_BYTES],
    const kop_ot_index_t indices[KOP_SIGMA],
    const uint8_t input[KOP_INPUT_BYTES],
    hid_t hid)
{
    kop_result_e res;
    kop_kem_ss_s secrets[KOP_OT_N];
    uint8_t prf_out[KOP_PET_PRF_BYTES];
    uint8_t b;
    size_t i, j;

    memset(encoding, 0, KOP_PET_PRF_BYTES);
    for (i = 0; i < KOP_SIGMA; i++) {
        hid.ot = i;
        KOP_TRY(kop_ot_send(secrets, &msgs_out[i* KOP_OT_MSG0_BYTES], &msgs_in[i], hid));
        // select required secret in constant time
        for (j = 1; j < KOP_OT_N; j++) {
            b = 1 - byte_neq(j, indices[i]);
            cmov(secrets[0].bytes, secrets[j].bytes, KOP_KEM_SS_BYTES, b);
        }
        kop_pet_prf(prf_out, &secrets[0], input);
        for (j = 0; j < KOP_PET_PRF_BYTES; j++) {
            encoding[j] ^= prf_out[j];
        }
    }
    return KOP_RESULT_OK;
}

// Get receiver output of oblivious encoding.
static void kop_oenc_recv_out(
    uint8_t encoding[KOP_PET_PRF_BYTES],
    const uint8_t msgs_in[KOP_SIGMA * KOP_OT_MSG1_BYTES],
    const kop_ot_recv_s states[KOP_SIGMA],
    const uint8_t input[KOP_INPUT_BYTES])
{
    kop_kem_ss_s secret;
    uint8_t prf_out[KOP_PET_PRF_BYTES];
    size_t i, j;

    memset(encoding, 0, KOP_PET_PRF_BYTES);
    for (i = 0; i < KOP_SIGMA; i++) {
        kop_ot_recv_out(&secret, &msgs_in[i * KOP_OT_MSG1_BYTES], &states[i]);
        kop_pet_prf(prf_out, &secret, input);
        for (j = 0; j < KOP_PET_PRF_BYTES; j++) {
            encoding[j] ^= prf_out[j];
        }
    }
}

void kop_pet_init(
    kop_pet_state_s *state,
    const uint8_t input[KOP_INPUT_BYTES],
    const uint8_t sid[KOP_SID_BYTES])
{
    // TODO: need to init the rest as well?
    memcpy(state->hid.sid, sid, KOP_SID_BYTES);
    memcpy(state->input, input, KOP_INPUT_BYTES);
}

void kop_pet_alice_m0(
    kop_pet_state_s *state,
    uint8_t msg_out[KOP_PET_MSG0_BYTES])
{
    kop_ot_index_t indices[KOP_SIGMA];

    words_from_bytes(indices, state->input);
    state->hid.oenc = 0;
    kop_oenc_recv_init(state->recv, msg_out, indices, state->hid);
}

kop_result_e kop_pet_bob_m1(
    kop_pet_state_s *state,
    uint8_t msg_out[KOP_PET_MSG1_BYTES],
    const uint8_t msg_in[KOP_PET_MSG0_BYTES])
{
    uint8_t local_msg_in[KOP_PET_MSG0_BYTES];
    kop_result_e res;
    kop_ot_index_t indices[KOP_SIGMA];
    
    // ensure no memory overlap between msg_in and msg_out
    memcpy(local_msg_in, msg_in, KOP_PET_MSG0_BYTES);
    words_from_bytes(indices, state->input);
    state->hid.oenc = 0;
    KOP_TRY(kop_oenc_send(state->encoding, msg_out, local_msg_in, indices, state->input, state->hid));
    // state->encoding == B[y]
    state->hid.oenc = 1;
    kop_oenc_recv_init(state->recv, &msg_out[KOP_SIGMA * KOP_OT_MSG1_BYTES], indices, state->hid);
    return KOP_RESULT_OK;
}

kop_result_e kop_pet_alice_m2(
    kop_pet_state_s *state,
    uint8_t msg_out[KOP_PET_MSG2_BYTES],
    const uint8_t msg_in[KOP_PET_MSG1_BYTES])
{
    uint8_t local_msg_out[KOP_PET_MSG2_BYTES];
    kop_ot_index_t indices[KOP_SIGMA];
    kop_result_e res;
    size_t i;

    state->hid.oenc = 0;
    kop_oenc_recv_out(local_msg_out, msg_in, state->recv, state->input);
    // local_msg_out == B[x]
    for (i = 0; i < KOP_SIGMA; i++) {
        indices[i] = state->recv[i].index;
    }
    state->hid.oenc = 1;
    KOP_TRY(kop_oenc_send(
        state->encoding,
        &local_msg_out[KOP_PET_PRF_BYTES],
        &msg_in[KOP_SIGMA * KOP_OT_MSG1_BYTES],
        indices,
        state->input,
        state->hid)
    );
    // state->encoding == A[x]
    for (i = 0; i < KOP_PET_PRF_BYTES; i++) {
        local_msg_out[i] ^= state->encoding[i];
    }
    // msg_out->encoding == A[x] ^ B[x]
    memcpy(msg_out, local_msg_out, KOP_PET_MSG2_BYTES);
    return KOP_RESULT_OK;
}

kop_result_e kop_pet_bob_m3(
    kop_pet_state_s *state,
    uint8_t msg_out[KOP_PET_MSG3_BYTES],
    const uint8_t msg_in[KOP_PET_MSG2_BYTES])
{
    uint8_t local_msg_out[KOP_PET_MSG3_BYTES];
    size_t i;

    // msg_in == A[x] ^ B[x]
    // state->encoding == B[y]
    state->hid.oenc = 1;
    kop_oenc_recv_out(local_msg_out, &msg_in[KOP_PET_PRF_BYTES], state->recv, state->input);
    // local_msg_out == A[y]
    for (i = 0; i < KOP_PET_PRF_BYTES; i++) {
        state->encoding[i] ^= local_msg_out[i];
    }
    // state->encoding == A[y] ^ B[y]
    if (verify(state->encoding, msg_in, KOP_PET_PRF_BYTES) != 0) {
        return KOP_RESULT_ABORT;
    }
    memcpy(msg_out, local_msg_out, KOP_PET_MSG3_BYTES);
    return KOP_RESULT_OK;
}

kop_result_e kop_pet_alice_accept(
    kop_pet_state_s *state,
    const uint8_t msg_in[KOP_PET_PRF_BYTES])
{
    if (verify(state->encoding, msg_in, KOP_PET_PRF_BYTES) != 0) {
        return KOP_RESULT_ABORT;
    }
    return KOP_RESULT_OK;
}

