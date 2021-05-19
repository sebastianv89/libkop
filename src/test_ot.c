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
    kop_kem_ss_s secret;
    kop_ot_recv_s recv;
    kop_ot_send_s send;
    kop_ot_recv_msg_s msg0;
    kop_ot_send_msg_s msg1;
    hid_t hid;
    kop_ot_index_t i, j;

    randombytes(hid.sid, KOP_SID_BYTES);
    hid.oenc = 0;
    hid.ot = 0;

    for (i = 0; i < KOP_OT_N; i++) {
        kop_ot_recv_init(&recv, &msg0, i, hid);
        kop_ot_send(&send, &msg1, &msg0, hid);
        kop_ot_recv_out(&secret, &msg1, &recv);
        for (j = 0; j < KOP_OT_N; j++) {
            assert(verify(secret.bytes, send.secrets[j].bytes, KOP_SS_BYTES) == (i != j));
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

