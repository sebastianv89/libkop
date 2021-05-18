#ifndef OT_H
#define OT_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "group.h"

void kop_ot_recv_init(
    uint8_t sk[KOP_SK_BYTES],
    uint8_t pks[KOP_OT_MSG0_BYTES],
    uint8_t index,
    hid_t *hid);

void kop_ot_send(
    uint8_t sss[KOP_OT_N * KOP_SS_BYTES],
    uint8_t cts[KOP_OT_MSG1_BYTES],
    const uint8_t pks[KOP_OT_MSG0_BYTES],
    hid_t *hid);

void kop_ot_recv_out(
    uint8_t ss[KOP_SS_BYTES],
    const uint8_t cts[KOP_OT_MSG1_BYTES],
    const uint8_t sk[KOP_SK_BYTES],
    uint8_t index);

#endif
