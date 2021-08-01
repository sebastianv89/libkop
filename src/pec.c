#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "KeccakHash.h"

#include "pec.h"
#include "params.h"
#include "common.h"
#include "group.h"
#include "ot.h"

static void words_from_bytes(
    kop_ot_index_t words[KOP_PEC_N],
    const uint8_t bytes[KOP_INPUT_BYTES])
{
#if KOP_OT_LOGM == 1
    size_t i, j;

    for (i = 0, j = 0; i < KOP_PEC_N; i += 8, j++) {
        words[i    ] =  bytes[j]       & 0x01;
        words[i + 1] = (bytes[j] >> 1) & 0x01;
        words[i + 2] = (bytes[j] >> 2) & 0x01;
        words[i + 3] = (bytes[j] >> 3) & 0x01;
        words[i + 4] = (bytes[j] >> 4) & 0x01;
        words[i + 5] = (bytes[j] >> 5) & 0x01;
        words[i + 6] = (bytes[j] >> 6) & 0x01;
        words[i + 7] =  bytes[j] >> 7;
    }
#elif KOP_OT_LOGM == 2
    size_t i, j;

    for (i = 0, j = 0; i < KOP_PEC_N; i += 4, j++) {
        words[i    ] =  bytes[j]       & 0x03;
        words[i + 1] = (bytes[j] >> 2) & 0x03;
        words[i + 2] = (bytes[j] >> 4) & 0x03;
        words[i + 3] =  bytes[j] >> 6;
    }
#elif KOP_OT_LOGM == 3
    size_t i, j;

    for (i = 0, j = 0; i < KOP_PEC_N; i += 8, j += 3) {
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
#elif KOP_OT_LOGM == 4
    size_t i, j;

    for (i = 0, j = 0; i < KOP_PEC_N; i += 2, j++) {
        words[i    ] = bytes[j] & 0x0f;
        words[i + 1] = bytes[j] >> 4;
    }
#elif KOP_OT_LOGM == 5
    size_t i, j;

    for (i = 0, j = 0; i < KOP_PEC_N; i += 8, j += 5) {
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
#elif KOP_OT_LOGM == 6
    size_t i, j;

    for (i = 0, j = 0; i < KOP_PEC_N; i += 4, j += 3) {
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
#elif KOP_OT_LOGM == 7
    size_t i, j;

    for (i = 0, j = 0; i < KOP_PEC_N; i += 8, j += 7) {
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
#elif KOP_OT_LOGM == 8
    memcpy(words, bytes, KOP_INPUT_BYTES);
#else
#error KOP_OT_LOGM larger than eight is not (yet) supported
#endif
}

static void kop_pec_g(
    uint8_t out[KOP_PEC_LAMBDA_BYTES],
    const uint8_t in[KOP_PEC_LAMBDA_BYTES])
{
    const uint8_t prefix[11] = { 0x4b, 0x4f, 0x50, 0x2d, 0x50, 0x45, 0x43, 0x2d, 0x47 }; // "KOP-PEC-G"
    Keccak_HashInstance hi;

    KECCAK_UNWRAP(Keccak_HashInitialize_SHA3_256(&hi));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, prefix, 8 * sizeof(prefix)));
    KECCAK_UNWRAP(Keccak_HashUpdate(&hi, in, 8 * KOP_PEC_LAMBDA_BYTES));
    KECCAK_UNWRAP(Keccak_HashFinal(&hi, out));
}

// Initialize the oblivious transfer receivers
static void kop_ots_recv_init(
    kop_ot_recv_s states[KOP_PEC_N],
    uint8_t msgs_out[KOP_PEC_N * KOP_OT_MSG0_BYTES],
    const kop_ot_index_t indices[KOP_PEC_N],
    hid_t hid)
{
    size_t i;

    for (i = 0; i < KOP_PEC_N; i++) {
        hid.ot = i;
        kop_ot_recv_init(&states[i], &msgs_out[i * KOP_OT_MSG0_BYTES], indices[i], hid);
    }
}

// Get XOR-ed sender output of oblivious transfers
//
// The sender can get arbitrary combinations, but for the PEC we only require one
static kop_result_e kop_ots_send(
    uint8_t encoding[KOP_PEC_LAMBDA_BYTES],
    uint8_t msgs_out[KOP_PEC_N * KOP_OT_MSG1_BYTES],
    const uint8_t msgs_in[KOP_PEC_N * KOP_OT_MSG0_BYTES],
    const kop_ot_index_t indices[KOP_PEC_N],
    hid_t hid)
{
    kop_result_e res;
    kop_kem_ss_s secrets[KOP_OT_M];
    uint8_t b;
    size_t i, j;

    memset(encoding, 0, KOP_PEC_LAMBDA_BYTES);
    for (i = 0; i < KOP_PEC_N; i++) {
        hid.ot = i;
        KOP_TRY(kop_ot_send(secrets, &msgs_out[i* KOP_OT_MSG1_BYTES], &msgs_in[i * KOP_OT_MSG0_BYTES], hid));
        // select required secret in constant time
        for (j = 1; j < KOP_OT_M; j++) {
            b = 1 - byte_neq(j, indices[i]);
            cmov(secrets[0].bytes, secrets[j].bytes, KOP_KEM_SS_BYTES, b);
        }
        for (j = 0; j < KOP_PEC_LAMBDA_BYTES; j++) {
            encoding[j] ^= secrets[0].bytes[j];
        }
    }
    return KOP_RESULT_OK;
}

// Get XOR-ed receiver output of oblivious transfers
static void kop_ots_recv_out(
    uint8_t encoding[KOP_PEC_LAMBDA_BYTES],
    const uint8_t msgs_in[KOP_PEC_N * KOP_OT_MSG1_BYTES],
    const kop_ot_recv_s states[KOP_PEC_N])
{
    kop_kem_ss_s secret;
    size_t i, j;

    memset(encoding, 0, KOP_PEC_LAMBDA_BYTES);
    for (i = 0; i < KOP_PEC_N; i++) {
        kop_ot_recv_out(&secret, &msgs_in[i * KOP_OT_MSG1_BYTES], &states[i]);
        for (j = 0; j < KOP_PEC_LAMBDA_BYTES; j++) {
            encoding[j] ^= secret.bytes[j];
        }
    }
}

void kop_pec_init(
    kop_pec_state_s *state,
    const uint8_t input[KOP_INPUT_BYTES],
    const uint8_t sid[KOP_SID_BYTES])
{
    memset(state, 0, sizeof(kop_pec_state_s));
    memcpy(state->input, input, KOP_INPUT_BYTES);
    memcpy(state->hid.sid, sid, KOP_SID_BYTES);
}

void kop_pec_alice_m0(
    kop_pec_state_s *state,
    uint8_t msg_out[KOP_PEC_MSG0_BYTES])
{
    kop_ot_index_t indices[KOP_PEC_N];

    words_from_bytes(indices, state->input);
    state->hid.role = 0;
    kop_ots_recv_init(state->recv, msg_out, indices, state->hid);
}

kop_result_e kop_pec_bob_m1(
    kop_pec_state_s *state,
    uint8_t msg_out[KOP_PEC_MSG1_BYTES],
    const uint8_t msg_in[KOP_PEC_MSG0_BYTES])
{
    uint8_t local_msg_in[KOP_PEC_MSG0_BYTES];
    kop_result_e res;
    kop_ot_index_t indices[KOP_PEC_N];
    
    memcpy(local_msg_in, msg_in, KOP_PEC_MSG0_BYTES);
    words_from_bytes(indices, state->input);
    state->hid.role = 0;
    KOP_TRY(kop_ots_send(state->encoding, msg_out, local_msg_in, indices, state->hid));
    // state->encoding == B(y)
    state->hid.role = 1;
    kop_ots_recv_init(state->recv, &msg_out[KOP_PEC_N * KOP_OT_MSG1_BYTES], indices, state->hid);
    return KOP_RESULT_OK;
}

kop_result_e kop_pec_alice_m2(
    kop_pec_state_s *state,
    uint8_t msg_out[KOP_PEC_MSG2_BYTES],
    const uint8_t msg_in[KOP_PEC_MSG1_BYTES])
{
    uint8_t local_msg_out[KOP_PEC_MSG2_BYTES], tmp[KOP_PEC_LAMBDA_BYTES];
    kop_ot_index_t indices[KOP_PEC_N];
    kop_result_e res;
    size_t i;

    state->hid.role = 0;
    kop_ots_recv_out(local_msg_out, msg_in, state->recv);
    // local_msg_out == B(x)
    for (i = 0; i < KOP_PEC_N; i++) {
        indices[i] = state->recv[i].index;
    }
    state->hid.role = 1;
    KOP_TRY(kop_ots_send(
        state->encoding,
        &local_msg_out[KOP_PEC_LAMBDA_BYTES],
        &msg_in[KOP_PEC_N * KOP_OT_MSG1_BYTES],
        indices,
        state->hid)
    );
    // state->encoding == A(x)
    kop_pec_g(tmp, state->encoding);
    // tmp == G(A(x))
    for (i = 0; i < KOP_PEC_LAMBDA_BYTES; i++) {
        state->encoding[i] ^= local_msg_out[i];
    }
    // state->encoding == A(x) ^ B(x)
    for (i = 0; i < KOP_PEC_LAMBDA_BYTES; i++) {
        local_msg_out[i] ^= tmp[i];
    }
    // local_msg_out == G(A(x)) ^ B(x)
    memcpy(msg_out, local_msg_out, KOP_PEC_MSG2_BYTES);
    return KOP_RESULT_OK;
}

void kop_pec_bob_m3(
    int *accept,
    kop_pec_state_s *state,
    uint8_t msg_out[KOP_PEC_MSG3_BYTES],
    const uint8_t msg_in[KOP_PEC_MSG2_BYTES])
{
    uint8_t local_encoding[KOP_PEC_LAMBDA_BYTES], local_msg_out[KOP_PEC_LAMBDA_BYTES];
    size_t i;

    // msg_in == G(A(x)) ^ B(x)
    // state->encoding == B(y)
    state->hid.role = 1;
    kop_ots_recv_out(local_encoding, &msg_in[KOP_PEC_LAMBDA_BYTES], state->recv);
    // local_encoding == A(y)
    for (i = 0; i < KOP_PEC_LAMBDA_BYTES; i++) {
        local_msg_out[i] = local_encoding[i] ^ state->encoding[i];
    }
    // local_msg_out == A(y) ^ B(y)
    kop_pec_g(local_encoding, local_encoding);
    // local_encoding == G(A(y))
    for (i = 0; i < KOP_PEC_LAMBDA_BYTES; i++) {
        local_encoding[i] ^= state->encoding[i];
    }
    // local_encoding == G(A(y)) ^ B(y)
    *accept = 1 - verify(local_encoding, msg_in, KOP_PEC_LAMBDA_BYTES);
    memset(msg_out, 0, KOP_PEC_MSG3_BYTES);
    msg_out[0] = (uint8_t)(*accept);
    if (*accept == 1) {
        memcpy(&msg_out[1], local_msg_out, KOP_PEC_LAMBDA_BYTES);
    }
}

kop_result_e kop_pec_alice_accept(
    int *accept,
    kop_pec_state_s *state,
    const uint8_t msg_in[KOP_PEC_MSG3_BYTES])
{
    if (msg_in[0] == 0) {
        *accept = 0;
        return KOP_RESULT_OK;
    }

    *accept = 1 - verify(state->encoding, &msg_in[1], KOP_PEC_LAMBDA_BYTES);
    if (*accept == 0) {
        return KOP_RESULT_ERROR;
    }
    return KOP_RESULT_OK;
}

