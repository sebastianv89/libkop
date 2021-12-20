#ifndef KOP_KOP_H
#define KOP_KOP_H

#include "split.h"
#include "params.h"

typedef struct {
    kop_split_state_s split;
} kop_state_s;

/// Return boolean: has the protocol aborted?
int kop_has_aborted(kop_state_s *state);

/// Initialize the state with the given input (hash of shared secret, public keys and session id)
void kop_init(
    kop_state_s *state,
    const uint8_t input[KOP_INPUT_BYTES]);

// Generate the first message.
// The state should be initialized for this to work.
kop_result_e kop_msg0(
    kop_state_s *state,
    uint8_t msg_out[KOP_MSG0_BYTES]);

// Process a message and (optionally) generate the next protocol message (in
// which case msg_out_len > 0).  The protocol accepts/rejects on messages four
// and five, which is also indicated by the return code: KOP_RESULT_OK on
// accept, KOP_RESULT_ERROR on reject.
//
// The msg_out buffer MUST hold enough bytes for the outgoing message (constant
// sizes: KOP_MSG1_BYTES, ..., KOP_MSG5_BYTES).  The msg_in buffer MUST hold
// enough bytes for the incoming message (constant sizes: KOP_MSG0_BYTES, ...,
// KOP_MSG5_BYTES).  These buffers may overlap.
//
// Note: the protocol rejects when the inputs were unequal, but it aborts when
// it detects any dishonest messages.  The distinction is usually not
// important, but while rejection could simply mean that the honest user made a
// typo in their password, while abortion always indicates malicious behaviour.
// The outcome of `kop_has_aborted` can distinguish rejectionn from abortion.
kop_result_e kop_process_msg(
    kop_state_s *state,
    uint8_t *msg_out,
    size_t *msg_out_len,
    const uint8_t *msg_in,
    size_t msg_in_len);

#endif
