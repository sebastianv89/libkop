#ifndef PET_H
#define PET_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

// TODO work with structs instead of concatenated byte-arrays

// not static: want to benchmark this, but this is not part of the API
void kop_pet_prf(uint8_t out[KOP_PRF_BYTES], const uint8_t in[KOP_SS_BYTES + KOP_INPUT_BYTES]);

void kop_pet_alice_m0(
    uint8_t sks[KOP_SIGMA * KOP_SK_BYTES],
    uint8_t pks[KOP_PET_MSG0_BYTES],
    const uint8_t x[KOP_INPUT_BYTES],
    const uint8_t sid[KOP_SID_BYTES]);

void kop_pet_bob_m1(
    uint8_t y_b[KOP_PRF_BYTES],
    uint8_t sks[KOP_SIGMA * KOP_SK_BYTES],
    uint8_t msg_out[KOP_PET_MSG1_BYTES],
    const uint8_t pks_in[KOP_PET_MSG0_BYTES],
    const uint8_t y[KOP_INPUT_BYTES],
    const uint8_t sid[KOP_SID_BYTES]);

void kop_pet_alice_m2(
    uint8_t x_a[KOP_PRF_BYTES],
    uint8_t msg_out[KOP_PET_MSG2_BYTES],
    const uint8_t msg_in[KOP_PET_MSG1_BYTES],
    const uint8_t sks[KOP_SIGMA * KOP_SK_BYTES],
    const uint8_t x[KOP_INPUT_BYTES],
    const uint8_t sid[KOP_SID_BYTES]);

int kop_pet_bob_m3(
    uint8_t y_a[KOP_PET_MSG3_BYTES],
    const uint8_t msg_in[KOP_PET_MSG2_BYTES],
    const uint8_t sks[KOP_SIGMA * KOP_SK_BYTES],
    const uint8_t y[KOP_INPUT_BYTES],
    const uint8_t y_b[KOP_PRF_BYTES]);

int kop_pet_alice_accept(
    const uint8_t y_a[KOP_PET_MSG3_BYTES],
    const uint8_t x_a[KOP_PRF_BYTES]);

#endif
