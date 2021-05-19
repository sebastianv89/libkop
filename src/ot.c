#include <stddef.h>
#include <stdint.h>

#include "ot.h"
#include "params.h"
#include "common.h"
#include "group.h"
#include "kem.h"

void kop_ot_recv_init(
    kop_ot_recv_s *state,
    kop_ot_recv_msg_s *msg_out,
    kop_ot_index_t index,
    hid_t hid)
{
    size_t i;
    uint8_t swapbit = 1;
    kop_kem_pk_s digest;
    const kop_kem_pk_s * pk_pointers[KOP_OT_N - 1];

    for (i = 1; i < KOP_OT_N; i++) {
        random_pk(&msg_out->pks[i]);
        pk_pointers[i-1] = &msg_out->pks[i];
    }
    hid.kem = index;
    hash_pks(&digest, pk_pointers, hid);
    kop_kem_keygen(&msg_out->pks[0], &state->sk);
    sub_pk(&msg_out->pks[0], &msg_out->pks[0], &digest);

    // put the last group element in `index`-th place
    for (i = 0; i < KOP_OT_N-1; i++) {
        swapbit &= byte_neq(i, index);
        cswap(msg_out->pks[i].bytes, msg_out->pks[i + 1].bytes, KOP_PK_BYTES, swapbit);
    }
    state->index = index;
}

void kop_ot_send(
    kop_ot_send_s *state,
    kop_ot_send_msg_s *msg_out,
    const kop_ot_recv_msg_s *msg_in,
    hid_t hid)
{
    kop_kem_pk_s pk, digest;
    const kop_kem_pk_s * pk_pointers[KOP_OT_N];
    size_t i;

    // TODO write DRY code
    for (i = 0; i < KOP_OT_N - 1; i++) {
        pk_pointers[i] = &msg_in->pks[i + 1];
    }
    hid.kem = 0;
    hash_pks(&digest, pk_pointers, hid);
    add_pk(&pk, &msg_in->pks[0], &digest);
    kop_kem_encaps(&msg_out->cts[0], &state->secrets[0], &pk);
    for (i = 1; i < KOP_OT_N; i++) {
        pk_pointers[i - 1] = &msg_in->pks[i - 1];
        hid.kem = i;
        hash_pks(&digest, pk_pointers, hid);
        add_pk(&pk, &msg_in->pks[i], &digest);
        kop_kem_encaps(&msg_out->cts[i], &state->secrets[i], &pk);
    }
}

void kop_ot_recv_out(
    kop_kem_ss_s *secret,
    const kop_ot_send_msg_s *msg_in,
    const kop_ot_recv_s *state_in)
{
    kop_kem_ct_s ct = {0}; // FIXME should not need initialization, but get warning otherwise
    uint8_t b;
    size_t i;

    for (i = 0; i < KOP_OT_N; i++) {
        b = 1 - byte_neq(i, state_in->index);
        cmov(ct.bytes, msg_in->cts[i].bytes, KOP_CT_BYTES, b);
    }
    kop_kem_decaps(secret, &ct, &state_in->sk);
}
