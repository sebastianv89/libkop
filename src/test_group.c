#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "group.h"

#define XSTR(s) STR(s)
#define STR(s) #s

static void test_group()
{
    // TODO write test
    assert(1);
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

    for (i = 0; i < nr_of_tests; i++) {
        test_group();
    }

    return EXIT_SUCCESS;
}

