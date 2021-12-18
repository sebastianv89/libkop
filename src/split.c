#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "split.h"

int kop_split_accepted(const kop_state_s *state)
{
    return (state->state == KOP_STATE_DONE && state->pec.accept);
}

void kop_split_init(
    kop_state_s *state,
    const uint8_t input[KOP_INPUT_BYTES])
{
    memset(state, 0, sizeof(kop_state_s));
    kop_pec_set_input(&state->pec, input);

    state->state = KOP_STATE_INIT;
}

void kop_split_alice0(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG0_BYTES])
{
    assert(state->state == KOP_STATE_INIT);

    OQS_UNWRAP(KOP_SPLIT_KEYGEN(state->pk_alice, state->sk));
    msg_out[0] = (uint8_t)(KOP_SPLIT_TAG_ALICE0);
    memcpy(&msg_out[1], state->pk_alice, KOP_SPLIT_PK_BYTES);

    state->state = KOP_STATE_EXPECT_BOB1;
}

void kop_split_bob1(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG1_BYTES],
    const uint8_t msg_in[KOP_SPLIT_MSG0_BYTES])
{
    size_t sig_len;
    assert(state->state == KOP_STATE_INIT);
    assert(msg_in[0] == KOP_SPLIT_TAG_ALICE0);

    OQS_UNWRAP(KOP_SPLIT_KEYGEN(state->pk_bob, state->sk));
    memcpy(state->pk_alice, &msg_in[1], KOP_SPLIT_PK_BYTES);
    msg_out[0] = (uint8_t)(KOP_SPLIT_TAG_BOB1);
    memcpy(&msg_out[1], state->pk_alice, KOP_SPLIT_PK_BYTES);
    memcpy(&msg_out[1 + KOP_SPLIT_PK_BYTES], state->pk_bob, KOP_SPLIT_PK_BYTES);
    OQS_UNWRAP(KOP_SPLIT_SIGN(&msg_out[1], &sig_len, msg_out, 1 + KOP_SID_BYTES, state->sk));
    memcpy(&msg_out[1 + KOP_SPLIT_SIG_BYTES], state->pk_bob, KOP_SPLIT_PK_BYTES);

    state->state = KOP_STATE_EXPECT_ALICE2;
}

kop_result_e kop_split_alice2(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG2_BYTES],
    uint8_t msg_in[KOP_SPLIT_MSG1_BYTES])
{
    uint8_t sig[KOP_SPLIT_SIG_BYTES];
    size_t sig_len;
    assert(state->state == KOP_STATE_EXPECT_BOB1);
    assert(msg_in[0] == KOP_SPLIT_TAG_BOB1);

    memcpy(sig, &msg_in[1], KOP_SPLIT_SIG_BYTES);
    memmove(&msg_in[1 + KOP_SPLIT_PK_BYTES], &msg_in[1 + KOP_SPLIT_SIG_BYTES], KOP_SPLIT_PK_BYTES);
    memcpy(&msg_in[1], state->pk_alice, KOP_SPLIT_PK_BYTES);
    if (OQS_SUCCESS != KOP_SPLIT_VERIFY(msg_in, 1 + KOP_SID_BYTES, sig, KOP_SPLIT_SIG_BYTES, &msg_in[1 + KOP_SPLIT_PK_BYTES])) {
        return KOP_RESULT_ERROR;
    }
    memcpy(state->pk_bob, &msg_in[1 + KOP_SPLIT_PK_BYTES], KOP_SPLIT_PK_BYTES);
    
    msg_out[0] = (uint8_t)(KOP_SPLIT_TAG_ALICE2);
    kop_pec_alice_m0(&state->pec, &msg_out[1]);
    memcpy(&msg_out[1 + KOP_PEC_MSG0_BYTES], state->pk_alice, KOP_SPLIT_PK_BYTES);
    memcpy(&msg_out[1 + KOP_PEC_MSG0_BYTES + KOP_SPLIT_PK_BYTES], state->pk_bob, KOP_SPLIT_PK_BYTES);
    OQS_UNWRAP(KOP_SPLIT_SIGN(&msg_out[1 + KOP_PEC_MSG0_BYTES], &sig_len, msg_out, 1 + KOP_PEC_MSG0_BYTES + KOP_SID_BYTES, state->sk));

    state->state = KOP_STATE_EXPECT_BOB3;
    return KOP_RESULT_OK;
}

kop_result_e kop_split_bob3(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG3_BYTES],
    uint8_t msg_in[KOP_SPLIT_MSG2_BYTES])
{
    uint8_t sig[KOP_SPLIT_SIG_BYTES];
    size_t sig_len;
    assert(state->state == KOP_STATE_EXPECT_ALICE2);
    assert(msg_in[0] == KOP_SPLIT_TAG_ALICE2);

    memcpy(sig, &msg_in[1 + KOP_PEC_MSG0_BYTES], KOP_SPLIT_SIG_BYTES);
    memcpy(&msg_in[1 + KOP_PEC_MSG0_BYTES], state->pk_alice, KOP_SPLIT_PK_BYTES);
    memmove(&msg_in[1 + KOP_PEC_MSG0_BYTES + KOP_SPLIT_PK_BYTES], state->pk_bob, KOP_SPLIT_PK_BYTES);
    if (OQS_SUCCESS != KOP_SPLIT_VERIFY(msg_in, 1 + KOP_PEC_MSG0_BYTES + KOP_SID_BYTES, sig, KOP_SPLIT_SIG_BYTES, state->pk_alice)) {
        return KOP_RESULT_ERROR;
    }
    
    if (KOP_RESULT_OK != kop_pec_bob_m1(&state->pec, &msg_out[1], &msg_in[1])) {
        state->state = KOP_STATE_ABORTED;
        return KOP_RESULT_ERROR;
    }
    msg_out[0] = (uint8_t)(KOP_SPLIT_TAG_BOB3);
    memcpy(&msg_out[1 + KOP_PEC_MSG1_BYTES], state->pk_alice, KOP_SPLIT_PK_BYTES);
    memcpy(&msg_out[1 + KOP_PEC_MSG1_BYTES + KOP_SPLIT_PK_BYTES], state->pk_bob, KOP_SPLIT_PK_BYTES);
    OQS_UNWRAP(KOP_SPLIT_SIGN(&msg_out[1 + KOP_PEC_MSG1_BYTES], &sig_len, msg_out, 1 + KOP_PEC_MSG1_BYTES + KOP_SID_BYTES, state->sk));

    state->state = KOP_STATE_EXPECT_ALICE4;
    return KOP_RESULT_OK;
}

kop_result_e kop_split_alice4(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG4_BYTES],
    uint8_t msg_in[KOP_SPLIT_MSG3_BYTES])
{
    uint8_t sig[KOP_SPLIT_SIG_BYTES];
    size_t sig_len;
    assert(state->state == KOP_STATE_EXPECT_BOB3);
    assert(msg_in[0] == KOP_SPLIT_TAG_BOB3);

    memcpy(sig, &msg_in[1 + KOP_PEC_MSG1_BYTES], KOP_SPLIT_SIG_BYTES);
    memcpy(&msg_in[1 + KOP_PEC_MSG1_BYTES], state->pk_alice, KOP_SPLIT_PK_BYTES);
    memmove(&msg_in[1 + KOP_PEC_MSG1_BYTES + KOP_SPLIT_PK_BYTES], state->pk_bob, KOP_SPLIT_PK_BYTES);
    if (OQS_SUCCESS != KOP_SPLIT_VERIFY(msg_in, 1 + KOP_PEC_MSG1_BYTES + KOP_SID_BYTES, sig, KOP_SPLIT_SIG_BYTES, state->pk_bob)) {
        return KOP_RESULT_ERROR;
    }
    
    if (KOP_RESULT_OK != kop_pec_alice_m2(&state->pec, &msg_out[1], &msg_in[1])) {
        state->state = KOP_STATE_ABORTED;
        return KOP_RESULT_ERROR;
    }
    msg_out[0] = (uint8_t)(KOP_SPLIT_TAG_ALICE4);
    memcpy(&msg_out[1 + KOP_PEC_MSG2_BYTES], state->pk_alice, KOP_SPLIT_PK_BYTES);
    memcpy(&msg_out[1 + KOP_PEC_MSG2_BYTES + KOP_SPLIT_PK_BYTES], state->pk_bob, KOP_SPLIT_PK_BYTES);
    OQS_UNWRAP(KOP_SPLIT_SIGN(&msg_out[1 + KOP_PEC_MSG2_BYTES], &sig_len, msg_out, 1 + KOP_PEC_MSG2_BYTES + KOP_SID_BYTES, state->sk));

    state->state = KOP_STATE_EXPECT_BOB5;
    return KOP_RESULT_OK;
}

kop_result_e kop_split_bob5(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG5_BYTES],
    uint8_t msg_in[KOP_SPLIT_MSG4_BYTES])
{
    uint8_t sig[KOP_SPLIT_SIG_BYTES];
    size_t sig_len;
    assert(state->state == KOP_STATE_EXPECT_ALICE4);
    assert(msg_in[0] == KOP_SPLIT_TAG_ALICE4);

    memcpy(sig, &msg_in[1 + KOP_PEC_MSG2_BYTES], KOP_SPLIT_SIG_BYTES);
    memcpy(&msg_in[1 + KOP_PEC_MSG2_BYTES], state->pk_alice, KOP_SPLIT_PK_BYTES);
    memmove(&msg_in[1 + KOP_PEC_MSG2_BYTES + KOP_SPLIT_PK_BYTES], state->pk_bob, KOP_SPLIT_PK_BYTES);
    if (OQS_SUCCESS != KOP_SPLIT_VERIFY(msg_in, 1 + KOP_PEC_MSG2_BYTES + KOP_SID_BYTES, sig, KOP_SPLIT_SIG_BYTES, state->pk_alice)) {
        return KOP_RESULT_ERROR;
    }
    
    msg_out[0] = (uint8_t)(KOP_SPLIT_TAG_BOB5);
    kop_pec_bob_m3(&state->pec, &msg_out[1], &msg_in[1]);
    memcpy(&msg_out[1 + KOP_PEC_MSG3_BYTES], state->pk_alice, KOP_SPLIT_PK_BYTES);
    memcpy(&msg_out[1 + KOP_PEC_MSG3_BYTES + KOP_SPLIT_PK_BYTES], state->pk_bob, KOP_SPLIT_PK_BYTES);
    OQS_UNWRAP(KOP_SPLIT_SIGN(&msg_out[1 + KOP_PEC_MSG3_BYTES], &sig_len, msg_out, 1 + KOP_PEC_MSG3_BYTES + KOP_SID_BYTES, state->sk));

    state->state = KOP_STATE_DONE;
    return KOP_RESULT_OK;
}

kop_result_e kop_split_alice6(
    kop_state_s *state,
    uint8_t msg_in[KOP_SPLIT_MSG5_BYTES])
{
    uint8_t sig[KOP_SPLIT_SIG_BYTES];
    assert(state->state == KOP_STATE_EXPECT_BOB5);
    assert(msg_in[0] == KOP_SPLIT_TAG_BOB5);

    memcpy(sig, &msg_in[1 + KOP_PEC_MSG3_BYTES], KOP_SPLIT_SIG_BYTES);
    memcpy(&msg_in[1 + KOP_PEC_MSG3_BYTES], state->pk_alice, KOP_SPLIT_PK_BYTES);
    memmove(&msg_in[1 + KOP_PEC_MSG3_BYTES + KOP_SPLIT_PK_BYTES], state->pk_bob, KOP_SPLIT_PK_BYTES);
    if (OQS_SUCCESS != KOP_SPLIT_VERIFY(msg_in, 1 + KOP_PEC_MSG3_BYTES + KOP_SID_BYTES, sig, KOP_SPLIT_SIG_BYTES, state->pk_bob)) {
        return KOP_RESULT_ERROR;
    }
    
    if (KOP_RESULT_OK != kop_pec_alice_accept(&state->pec, &msg_in[1])) {
        state->state = KOP_STATE_ABORTED;
        return KOP_RESULT_ERROR;
    }

    state->state = KOP_STATE_DONE;
    return KOP_RESULT_OK;
}
