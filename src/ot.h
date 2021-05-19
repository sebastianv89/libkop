#ifndef OT_H
#define OT_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "kem.h"
#include "group.h"

typedef uint8_t kop_ot_index_t;

typedef struct {
    kop_kem_sk_s sk;
    kop_ot_index_t index;
} kop_ot_recv_s;

typedef struct {
    kop_kem_ss_s secrets[KOP_OT_N];
} kop_ot_send_s;

typedef struct {
    kop_kem_pk_s pks[KOP_OT_N];
} kop_ot_recv_msg_s;

typedef struct {
    kop_kem_ct_s cts[KOP_OT_N];
} kop_ot_send_msg_s;


void kop_ot_recv_init(
    kop_ot_recv_s *state,
    kop_ot_recv_msg_s *msg_out,
    kop_ot_index_t index,
    hid_t hid);

void kop_ot_send(
    kop_ot_send_s *state,
    kop_ot_send_msg_s *msg_out,
    const kop_ot_recv_msg_s *msg_in,
    hid_t hid);

void kop_ot_recv_out(
    kop_kem_ss_s *secret,
    const kop_ot_send_msg_s *msg_in,
    const kop_ot_recv_s *state_in);

#endif
