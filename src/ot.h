#ifndef KOP_OT_H
#define KOP_OT_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "kem.h"
#include "group.h"
#include "common.h"

typedef uint8_t kop_ot_index_t;

typedef struct {
    kop_kem_sk_s sk;
    kop_ot_index_t index;
} kop_ot_recv_s;

void kop_ot_recv_init(
    kop_ot_recv_s *state,
    uint8_t msg_out[KOP_OT_MSG0_BYTES],
    kop_ot_index_t index,
    hid_t hid);

kop_result_e kop_ot_send(
    kop_kem_ss_s secrets[KOP_OT_M],
    uint8_t msg_out[KOP_OT_MSG1_BYTES],
    const uint8_t msg_in[KOP_OT_MSG0_BYTES],
    hid_t hid);

void kop_ot_recv_out(
    kop_kem_ss_s *secret,
    const uint8_t msg_in[KOP_OT_MSG1_BYTES],
    const kop_ot_recv_s *state);

#endif
