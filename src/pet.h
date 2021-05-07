#ifndef PET_H
#define PET_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

void pet_alice_m0(uint8_t sks[PET_SIGMA * SK_BYTES],
                  uint8_t pks[PET_SIGMA * OTKEM_N * PK_BYTES],
                  const uint8_t x[PET_INPUT_BYTES]);

void pet_bob_m1(uint8_t y_b[PET_LAMBDA],
                uint8_t sks[PET_SIGMA * SK_BYTES],
                uint8_t msg_out[PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES)],
                const uint8_t pks_in[PET_SIGMA * OTKEM_N * PK_BYTES],
                const uint8_t y[PET_INPUT_BYTES]);

void pet_alice_m2(uint8_t x_a[PET_LAMBDA],
                 uint8_t msg_out[PET_LAMBDA + PET_SIGMA * OTKEM_N * CT_BYTES],
                 const uint8_t msg_in[PET_SIGMA * OTKEM_N * (CT_BYTES + PK_BYTES)],
                 const uint8_t sks[PET_SIGMA * SK_BYTES],
                 const uint8_t x[PET_INPUT_BYTES]);

int pet_bob_m3(uint8_t y_a[PET_LAMBDA],
               const uint8_t msg_in[PET_LAMBDA + PET_SIGMA * CT_BYTES],
               const uint8_t sks[PET_SIGMA * SK_BYTES],
               const uint8_t y[PET_INPUT_BYTES],
               const uint8_t y_b[PET_LAMBDA]);

int pet_alice_accept(const uint8_t y_a[PET_LAMBDA],
                     const uint8_t x_a[PET_LAMBDA]);

#endif
