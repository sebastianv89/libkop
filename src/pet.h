#ifndef PET_H
#define PET_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "group.h"
#include "ot.h"

typedef struct {
    hid_t hid;
    uint8_t input[KOP_INPUT_BYTES];
    kop_ot_recv_s recv[KOP_SIGMA]; // might save some space by dynamically allocating this
    uint8_t encoding[KOP_PRF_BYTES];
} kop_pet_state_s;

typedef struct {
    kop_ot_recv_msg_s recv[KOP_SIGMA];
} kop_pet_msg0_s;

typedef struct {
    kop_ot_send_msg_s send[KOP_SIGMA];
    kop_ot_recv_msg_s recv[KOP_SIGMA];
} kop_pet_msg1_s;

typedef struct {
    kop_ot_send_msg_s send[KOP_SIGMA];
    uint8_t encoding[KOP_PRF_BYTES];
} kop_pet_msg2_s;

typedef struct {
    uint8_t encoding[KOP_PRF_BYTES];
} kop_pet_msg3_s;


void kop_pet_init(
    kop_pet_state_s *state,
    const uint8_t input[KOP_INPUT_BYTES],
    const uint8_t sid[KOP_SID_BYTES]);

kop_result_e kop_pet_alice_m0(
    kop_pet_state_s *state,
    kop_pet_msg0_s *msg_out);

kop_result_e kop_pet_bob_m1(
    kop_pet_state_s *state,
    kop_pet_msg1_s *msg_out,
    const kop_pet_msg0_s *msg_in);

kop_result_e kop_pet_alice_m2(
    kop_pet_state_s *state,
    kop_pet_msg2_s *msg_out,
    const kop_pet_msg1_s *msg_in);

kop_result_e kop_pet_bob_m3(
    kop_pet_state_s *state,
    kop_pet_msg3_s *msg_out,
    const kop_pet_msg2_s *msg_in);

kop_result_e kop_pet_alice_accept(
    kop_pet_state_s *state,
    const kop_pet_msg3_s *msg_in);

#endif
