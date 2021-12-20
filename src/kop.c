#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "kop.h"
#include "params.h"

int kop_has_aborted(kop_state_s *state)
{
    return kop_split_aborted(&state->split);
}

void kop_init(
    kop_state_s *state,
    const uint8_t input[KOP_INPUT_BYTES])
{
    kop_split_init(&state->split, input);
}

kop_result_e kop_msg0(
    kop_state_s *state,
    uint8_t msg_out[KOP_MSG0_BYTES])
{
    uint8_t local_msg_out[KOP_SPLIT_MSG0_BYTES] = {0};

    if (state->split.state != KOP_STATE_INIT) {
        return KOP_RESULT_ERROR;
    }

    kop_split_alice0(&state->split, local_msg_out);
    memcpy(msg_out, local_msg_out, KOP_MSG0_BYTES);
    return KOP_RESULT_OK;
}

kop_result_e kop_process_msg(
    kop_state_s *state,
    uint8_t *msg_out,
    size_t *msg_out_len,
    const uint8_t *msg_in,
    size_t msg_in_len)
{
    *msg_out_len = 0;
    if (msg_in_len == 0) {
        return KOP_RESULT_ERROR;
    }
    switch (msg_in[0]) {
        case KOP_SPLIT_TAG_ALICE0: 
            if (state->split.state == KOP_STATE_INIT) {
                uint8_t local_msg_in[KOP_SPLIT_MSG0_BYTES];
                uint8_t local_msg_out[KOP_SPLIT_MSG1_BYTES];
                memcpy(local_msg_in, msg_in, KOP_MSG0_BYTES);
                kop_split_bob1(&state->split, local_msg_out, local_msg_in);
                memcpy(msg_out, local_msg_out, KOP_MSG1_BYTES);
                *msg_out_len = KOP_MSG1_BYTES;
                return KOP_RESULT_OK;
            }
            break;
        case KOP_SPLIT_TAG_BOB1:
            if (state->split.state == KOP_STATE_EXPECT_BOB1) {
                uint8_t local_msg_in[KOP_SPLIT_MSG1_BYTES];
                uint8_t local_msg_out[KOP_SPLIT_MSG2_BYTES];
                memcpy(local_msg_in, msg_in, KOP_MSG1_BYTES);
                if (KOP_RESULT_OK == kop_split_alice2(&state->split, local_msg_out, local_msg_in)) {
                    memcpy(msg_out, local_msg_out, KOP_MSG2_BYTES);
                    *msg_out_len = KOP_MSG2_BYTES;
                    return KOP_RESULT_OK;
                }
            }
            break;
        case KOP_SPLIT_TAG_ALICE2:
            if (state->split.state == KOP_STATE_EXPECT_ALICE2) {
                uint8_t local_msg_in[KOP_SPLIT_MSG2_BYTES];
                uint8_t local_msg_out[KOP_SPLIT_MSG3_BYTES];
                memcpy(local_msg_in, msg_in, KOP_MSG2_BYTES);
                if (KOP_RESULT_OK == kop_split_bob3(&state->split, local_msg_out, local_msg_in)) {
                    memcpy(msg_out, local_msg_out, KOP_MSG3_BYTES);
                    *msg_out_len = KOP_MSG3_BYTES;
                    return KOP_RESULT_OK;
                }
            }
            break;
        case KOP_SPLIT_TAG_BOB3:
            if (state->split.state == KOP_STATE_EXPECT_BOB3) {
                uint8_t local_msg_in[KOP_SPLIT_MSG3_BYTES];
                uint8_t local_msg_out[KOP_SPLIT_MSG4_BYTES];
                memcpy(local_msg_in, msg_in, KOP_MSG3_BYTES);
                if (KOP_RESULT_OK == kop_split_alice4(&state->split, local_msg_out, local_msg_in)) {
                    memcpy(msg_out, local_msg_out, KOP_MSG4_BYTES);
                    *msg_out_len = KOP_MSG4_BYTES;
                    return KOP_RESULT_OK;
                }
            }
            break;
        case KOP_SPLIT_TAG_ALICE4:
            if (state->split.state == KOP_STATE_EXPECT_ALICE4) {
                uint8_t local_msg_in[KOP_SPLIT_MSG4_BYTES];
                uint8_t local_msg_out[KOP_SPLIT_MSG5_BYTES];
                memcpy(local_msg_in, msg_in, KOP_MSG4_BYTES);
                if (KOP_RESULT_OK == kop_split_bob5(&state->split, local_msg_out, local_msg_in)) {
                    memcpy(msg_out, local_msg_out, KOP_MSG5_BYTES);
                    *msg_out_len = KOP_MSG5_BYTES;
                    // ensure rejection is (also) indicated by the return code
                    if (kop_split_accepted(&state->split)) {
                        return KOP_RESULT_OK;
                    }
                }
            }
            break;
        case KOP_SPLIT_TAG_BOB5:
            if (state->split.state == KOP_STATE_EXPECT_BOB5) {
                uint8_t local_msg_in[KOP_SPLIT_MSG5_BYTES];
                memcpy(local_msg_in, msg_in, KOP_MSG5_BYTES);
                if (KOP_RESULT_OK == kop_split_alice6(&state->split, local_msg_in)) {
                    *msg_out_len = 0;
                    // ensure rejection is (also) indicated by the return code
                    if (kop_split_accepted(&state->split)) {
                        return KOP_RESULT_OK;
                    }
                }
            }
    }
    return KOP_RESULT_ERROR;
}
