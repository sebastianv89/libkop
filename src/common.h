#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <decaf/common.h>

typedef enum {
    KOP_RESULT_OK = 0,
    KOP_RESULT_ERROR = -1,
} kop_result_e;

#ifdef KOP_DEBUG
#include <stdlib.h>
#else
#define NDEBUG
#endif

/// Macro for simplifying error handling
#define KOP_TRY(call) ({\
    res = call;\
    if (res != KOP_RESULT_OK) {\
        return res;\
    }\
    })

// Keccak calls can only fail if provided with invalid input format/length, but
// since that is static across all calls Keccak should never fail.  Confirm
// this in debug mode and assume it in release mode.
#ifdef KOP_DEBUG
#define KECCAK_UNWRAP(call) ({\
    if (call != KECCAK_SUCCESS) {\
        exit(EXIT_FAILURE);\
    }\
    })
#else
#define KECCAK_UNWRAP(call) ({ call; })
#endif

// OQS calls can only fail if provided with invalid input, or if misconfigured
// during compilation/installation.  Although decapsulation could fail for some
// cryptosystems, to OT requires implicit failure (the OQS call always returns
// OQS_SUCCESS).  Confirm this in debug mode and assume it in release mode.
#ifdef KOP_DEBUG
#define OQS_UNWRAP(call) ({\
    if (call != OQS_SUCCESS) {\
        exit(EXIT_FAILURE);\
    }\
    })
#else
#define OQS_UNWRAP(call) ({ call; })
#endif

static inline uint8_t byte_neq(uint8_t a, uint8_t b)
{
    return (-(uint64_t)(a ^ b)) >> 63;
}

// Verify that the bytearrays are equal. Returns 0 if they are equal, 1
// otherwise.
//
// Runs in constant time.
int verify(const uint8_t *a, const uint8_t *b, size_t len);


// Move bytearray from x to r if b=1. Otherwise b=0: leave r unmodified.
//
// Runs in constant time.
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

// Swap bytearrays x and y if b=1. Otherwise b=0: leave x and y unmodified.
//
// Runs in constant time.
void cswap(uint8_t *x, uint8_t *y, size_t len, uint8_t b);

#endif
