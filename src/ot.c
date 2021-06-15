#include <stddef.h>
#include <stdint.h>

#include "ot.h"
#include "kem.h"
#include "group.h"
#include "params.h"
#include "common.h"

void kop_ot_recv_init(
    kop_ot_recv_s *state,
    uint8_t msg_out[KOP_OT_MSG0_BYTES],
    kop_ot_index_t index,
    hid_t hid)
{
    kop_kem_pk_s pk, r;
    const uint8_t * pk_pointers[KOP_OT_N - 1];
    const uint8_t * rho;
    size_t i;
    uint8_t swapbit = 1;

    kop_kem_keygen(&pk, &state->sk);
    rho = kop_pq_pk_rho(pk.pq);
    for (i = 1; i < KOP_OT_N; i++) {
        kop_random_pk(&r, rho);
        kop_kem_pk_serialize(&msg_out[i * KOP_KEM_PK_BYTES], &r);
        pk_pointers[i - 1] = &msg_out[i * KOP_KEM_PK_BYTES];
    }
    hid.kem = index;
    kop_hash_pks(&r, pk_pointers, rho, hid);
    kop_sub_pk(&pk, &pk, &r);
    kop_kem_pk_serialize(msg_out, &pk);
    // put the public key in `index`-th place
    for (i = 0; i < KOP_OT_N-1; i++) {
        swapbit &= byte_neq(i, index);
        cswap(&msg_out[i * KOP_KEM_PK_BYTES], &msg_out[(i + 1) * KOP_KEM_PK_BYTES], KOP_KEM_PK_BYTES, swapbit);
    }
    state->index = index;
}

kop_result_e kop_ot_send(
    kop_kem_ss_s secrets[KOP_OT_N],
    uint8_t msg_out[KOP_OT_MSG1_BYTES],
    const uint8_t msg_in[KOP_OT_MSG0_BYTES],
    hid_t hid)
{
    kop_result_e res;
    kop_kem_pk_s pk, digest;
    const uint8_t * pk_pointers[KOP_OT_N];
    const uint8_t * rho;
    size_t i;

    for (i = 0; i < KOP_OT_N - 1; i++) {
        pk_pointers[i] = &msg_in[(i + 1) * KOP_KEM_PK_BYTES];
    }
    for (i = 0; i < KOP_OT_N; i++) {
        KOP_TRY(kop_kem_pk_deserialize(&pk, &msg_in[i * KOP_KEM_PK_BYTES]));
        rho = kop_pq_pk_rho(pk.pq);
        hid.kem = i;
        kop_hash_pks(&digest, pk_pointers, rho, hid);
        kop_add_pk(&pk, &pk, &digest);
        kop_kem_encaps(&msg_out[i * KOP_KEM_CT_BYTES], &secrets[i], &pk);
        pk_pointers[i] = &msg_in[i * KOP_KEM_PK_BYTES];
    }
    return KOP_RESULT_OK;
}

void kop_ot_recv_out(
    kop_kem_ss_s *secret,
    const uint8_t msg_in[KOP_OT_MSG1_BYTES],
    const kop_ot_recv_s *state)
{
    uint8_t ct[KOP_KEM_CT_BYTES];
    uint8_t b;
    size_t i;

    // select ciphertext in constant time
    for (i = 0; i < KOP_OT_N; i++) {
        b = 1 - byte_neq(i, state->index);
        cmov(ct, &msg_in[i * KOP_KEM_CT_BYTES], KOP_KEM_CT_BYTES, b);
    }
    kop_kem_decaps(secret, ct, &state->sk);
}
