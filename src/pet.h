#ifndef KOP_PET_H
#define KOP_PET_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "group.h"
#include "ot.h"

typedef struct {
    hid_t hid;
    uint8_t input[KOP_INPUT_BYTES];
    kop_ot_recv_s recv[KOP_SIGMA];
    uint8_t encoding[KOP_PET_PRF_BYTES];
} kop_pet_state_s;

void kop_pet_init(
    kop_pet_state_s *state,
    const uint8_t input[KOP_INPUT_BYTES],
    const uint8_t sid[KOP_SID_BYTES]);

void kop_pet_alice_m0(
    kop_pet_state_s *state,
    uint8_t msg_out[KOP_PET_MSG0_BYTES]);

kop_result_e kop_pet_bob_m1(
    kop_pet_state_s *state,
    uint8_t msg_out[KOP_PET_MSG1_BYTES],
    const uint8_t msg_in[KOP_PET_MSG0_BYTES]);

kop_result_e kop_pet_alice_m2(
    kop_pet_state_s *state,
    uint8_t msg_out[KOP_PET_MSG2_BYTES],
    const uint8_t msg_in[KOP_PET_MSG1_BYTES]);

kop_result_e kop_pet_bob_m3(
    kop_pet_state_s *state,
    uint8_t msg_out[KOP_PET_MSG3_BYTES],
    const uint8_t msg_in[KOP_PET_MSG2_BYTES]);

kop_result_e kop_pet_alice_accept(
    kop_pet_state_s *state,
    const uint8_t msg_in[KOP_PET_MSG3_BYTES]);

#endif
