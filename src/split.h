#ifndef KOP_SPLIT_H
#define KOP_SPLIT_H

#include <stdint.h>
#include <stddef.h>

#include "params.h"
#include "pec.h"

#define KOP_SPLIT_TAG_ALICE0 0
#define KOP_SPLIT_TAG_BOB1 1
#define KOP_SPLIT_TAG_ALICE2 2
#define KOP_SPLIT_TAG_BOB3 3
#define KOP_SPLIT_TAG_ALICE4 4
#define KOP_SPLIT_TAG_BOB5 5

typedef enum {
    KOP_STATE_INIT = 1,
    KOP_STATE_EXPECT_BOB1,
    KOP_STATE_EXPECT_ALICE2,
    KOP_STATE_EXPECT_BOB3,
    KOP_STATE_EXPECT_ALICE4,
    KOP_STATE_EXPECT_BOB5,
    KOP_STATE_DONE,
    KOP_STATE_ABORTED,
} kop_split_state_e;

typedef struct {
    kop_split_state_e state;
    uint8_t sk[KOP_SPLIT_SK_BYTES];
    uint8_t pk_alice[KOP_SPLIT_PK_BYTES];
    uint8_t pk_bob[KOP_SPLIT_PK_BYTES];
    kop_pec_state_s pec;
} kop_state_s;

int kop_split_accepted(const kop_state_s *state);

void kop_split_init(
    kop_state_s *state,
    const uint8_t input[KOP_INPUT_BYTES]);

void kop_split_alice0(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG0_BYTES]);

void kop_split_bob1(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG1_BYTES],
    const uint8_t msg_in[KOP_SPLIT_MSG0_BYTES]);

kop_result_e kop_split_alice2(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG2_BYTES],
    uint8_t msg_in[KOP_SPLIT_MSG1_BYTES]);

kop_result_e kop_split_bob3(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG3_BYTES],
    uint8_t msg_in[KOP_SPLIT_MSG2_BYTES]);

kop_result_e kop_split_alice4(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG4_BYTES],
    uint8_t msg_in[KOP_SPLIT_MSG3_BYTES]);

kop_result_e kop_split_bob5(
    kop_state_s *state,
    uint8_t msg_out[KOP_SPLIT_MSG5_BYTES],
    uint8_t msg_in[KOP_SPLIT_MSG4_BYTES]);

kop_result_e kop_split_alice6(
    kop_state_s *state,
    uint8_t msg_in[KOP_SPLIT_MSG5_BYTES]);

#endif
