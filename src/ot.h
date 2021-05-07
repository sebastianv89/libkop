#ifndef OT_H
#define OT_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

void kemot_receiver_init(uint8_t sk[SK_BYTES],
                         uint8_t pks[OTKEM_N * PK_BYTES],
                         uint8_t index,
                         const uint8_t sid[SID_BYTES]);

void kemot_sender(uint8_t sss[OTKEM_N * SS_BYTES],
                  uint8_t cts[OTKEM_N * CT_BYTES],
                  const uint8_t pks[OTKEM_N * PK_BYTES],
                  const uint8_t sid[SID_BYTES]);

void kemot_receiver_output(uint8_t ss[SS_BYTES],
                           const uint8_t cts[OTKEM_N * CT_BYTES],
                           const uint8_t sk[SK_BYTES],
                           uint8_t index);

#endif
