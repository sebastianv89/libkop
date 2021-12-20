#ifndef KOP_PEC_H
#define KOP_PEC_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "common.h"
#include "group.h"
#include "ot.h"

#define KOP_PEC_MSG0_BYTES (KOP_PEC_N * KOP_OT_MSG0_BYTES)
#define KOP_PEC_MSG1_BYTES (KOP_PEC_N * (KOP_OT_MSG0_BYTES + KOP_OT_MSG1_BYTES))
#define KOP_PEC_MSG2_BYTES (KOP_PEC_LAMBDA_BYTES + KOP_PEC_N * KOP_OT_MSG1_BYTES)
#define KOP_PEC_MSG3_BYTES (1 + KOP_PEC_LAMBDA_BYTES)

typedef struct {
    hid_t hid;
    kop_ot_recv_s recv[KOP_PEC_N];
    uint8_t input[KOP_INPUT_BYTES];
    uint8_t encoding[KOP_PEC_LAMBDA_BYTES];
    int accept;
} kop_pec_state_s;

// Set the user input (x for Alice, y for Bob).
// Both Alice and Bob use this subroutine.
void kop_pec_set_input(
    kop_pec_state_s *state,
    const uint8_t input[KOP_INPUT_BYTES]);

// Set the sid. Both Alice and Bob use this subroutine.
void kop_pec_set_sid(
    kop_pec_state_s *state,
    const uint8_t sid[KOP_SID_BYTES]);

// Alice generates the initiating message msg_out (m0).
void kop_pec_alice_m0(
    kop_pec_state_s *state,
    uint8_t msg_out[KOP_PEC_MSG0_BYTES]);

// Bob processes msg_in (m0) and replies with msg_in (m1).
// 
// This may fail if msg_in contains invalid input: then it returns KOP_ABORT
kop_result_e kop_pec_bob_m1(
    kop_pec_state_s *state,
    uint8_t msg_out[KOP_PEC_MSG1_BYTES],
    const uint8_t msg_in[KOP_PEC_MSG0_BYTES]);

// Alice processes msg_in (m1) and replies with msg_out (m2)
//
// This may fail if msg_in contains invalid input: then it returns KOP_ABORT
kop_result_e kop_pec_alice_m2(
    kop_pec_state_s *state,
    uint8_t msg_out[KOP_PEC_MSG2_BYTES],
    const uint8_t msg_in[KOP_PEC_MSG1_BYTES]);

// Bob processes msg_in (m2), accepts/rejects and replies with msg_out (m3).
// 
// Set state->accept to 1 if accepted (x==y), or to 0 if rejected (x != y)
void kop_pec_bob_m3(
    kop_pec_state_s *state,
    uint8_t msg_out[KOP_PEC_MSG3_BYTES],
    const uint8_t msg_in[KOP_PEC_MSG2_BYTES]);

// Alice processes msg_in (m3) and accepts/rejects.
//
// Set state->accept to 1 if accepted (x==y), or to 0 if rejected (x != y)
//
// This may return KOP_RESULT_ERROR, if Bob says he accepted but does not provide the correct message,
// which indicates malicious behaviour.
kop_result_e kop_pec_alice_accept(
    kop_pec_state_s *state,
    const uint8_t msg_in[KOP_PEC_MSG3_BYTES]);

#endif
