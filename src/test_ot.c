#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "ot.h"
#include "kem.h"
#include "group.h"
#include "common.h"
#include "params.h"
#include "types.h"
#include "randombytes.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static void test_ot()
{
    kop_result_e res;
    kop_kem_ss_s secret, secrets[KOP_OT_N];
    kop_ot_recv_s recv;
    uint8_t msg0[KOP_OT_MSG0_BYTES];
    uint8_t msg1[KOP_OT_MSG1_BYTES];
    hid_t hid;
    unsigned int ui, uj;
    kop_ot_index_t i, j;

    randombytes(hid.sid, KOP_SID_BYTES);
    hid.oenc = 0;
    hid.ot = 0;

    for (ui = 0; ui < KOP_OT_N; ui++) {
        i = (kop_ot_index_t)(ui);
        kop_ot_recv_init(&recv, msg0, i, hid);
        res = kop_ot_send(secrets, msg1, msg0, hid);
        assert(res == KOP_RESULT_OK);
        kop_ot_recv_out(&secret, msg1, &recv);
        for (uj = 0; uj < KOP_OT_N; uj++) {
            j = (kop_ot_index_t)(uj);
            assert(verify(secret.bytes, secrets[j].bytes, KOP_KEM_SS_BYTES) == (i != j));
        }
    }
}

static void print_sizes()
{
    printf("%s, N=%u\n", XSTR(KOP_KEM_ALG), KOP_OT_N);
    printf("M0, R -> S: %8u bytes (N public keys)\n", KOP_OT_MSG0_BYTES);
    printf("M1, S -> R: %8u bytes (N ciphertexts)\n", KOP_OT_MSG1_BYTES);
}

int main(int argc, char *argv[])
{
    size_t i, nr_of_tests = 16;

    if (argc >= 2) {
        nr_of_tests = atoi(argv[1]);
        if (nr_of_tests == 0) {
            fprintf(stderr, "Usage: %s [nr_of_tests]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    printf("OQS %s\n", OQS_VERSION_TEXT);
    print_sizes();
    for (i = 0; i < nr_of_tests; i++) {
        test_ot();
    }

    return EXIT_SUCCESS;
}

